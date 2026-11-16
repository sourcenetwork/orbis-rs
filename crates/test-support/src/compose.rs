//! Docker Compose subprocess helpers shared by [`super::VeraTestContainer`],
//! [`super::CosmosNetwork`], and [`super::NativeNetworkAdapter`].

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PROJECT_ID: AtomicU64 = AtomicU64::new(0);

pub(super) fn unique_project_name(prefix: &str) -> String {
    let sequence = NEXT_PROJECT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{sequence}", std::process::id())
}

pub(super) fn compose_command(compose_file: &str, project_name: &str) -> Command {
    let mut command = Command::new("docker");
    command
        .args([
            "compose",
            "--project-name",
            project_name,
            "-f",
            compose_file,
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..");
    #[cfg(all(unix, feature = "native"))]
    if compose_file == crate::native_network::NATIVE_COMPOSE_FILE {
        let revision = std::env::var("VERA_REF")
            .ok()
            .filter(|revision| !revision.is_empty())
            .unwrap_or_else(crate::native_network::native_vera_ref);
        command.env("VERA_REF", revision);
    }
    command
}

// `published_port`/`localhost_url`/`report_compose_failure`/`stop_compose`
// are shared by `CosmosNetwork`/`VeraTestContainer` (Cosmos) and
// `NativeTestNetwork`/`NativeNetworkAdapter` (native, Phase B of the
// harness-unification plan) — both drive a real multi-service Compose file.
#[cfg(any(feature = "cosmos", feature = "native"))]
fn parse_published_port(output: &str) -> Option<u16> {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.trim().rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

#[cfg(any(feature = "cosmos", feature = "native"))]
pub(super) fn published_port(
    compose_file: &str,
    project_name: &str,
    service: &str,
    container_port: u16,
) -> Result<u16, String> {
    published_port_with_env(compose_file, project_name, service, container_port, &[])
}

/// Query a published port while replaying the environment that defines the
/// Compose project. Native fixtures use interpolated network, address, image,
/// and bind-mount values, so even a read-only `compose port` command must see
/// the same values as the original `compose up`.
#[cfg(any(feature = "cosmos", feature = "native"))]
pub(super) fn published_port_with_env(
    compose_file: &str,
    project_name: &str,
    service: &str,
    container_port: u16,
    env: &[(String, String)],
) -> Result<u16, String> {
    let mut command = compose_command(compose_file, project_name);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .args(["port", service, &container_port.to_string()])
        .output()
        .map_err(|error| {
            format!("Failed to query published port for {service}:{container_port}: {error}")
        })?;

    if !output.status.success() {
        return Err(format!(
            "Failed to query published port for {service}:{container_port}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_published_port(&stdout).ok_or_else(|| {
        format!("Unexpected docker compose port output for {service}:{container_port}: {stdout:?}")
    })
}

#[cfg(any(feature = "cosmos", feature = "native"))]
pub(super) fn localhost_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

#[cfg(any(feature = "cosmos", feature = "native"))]
pub(super) fn report_compose_failure(compose_file: &str, project_name: &str) {
    eprintln!("Docker Compose diagnostics for project {project_name}:");
    let _ = diagnostic_output(
        "docker compose ps",
        compose_command(compose_file, project_name).args(["ps", "--all"]),
    );

    if let Some(output) = diagnostic_output(
        "docker compose ps --quiet",
        compose_command(compose_file, project_name).args(["ps", "--all", "--quiet"]),
    ) {
        let container_ids: Vec<&str> = std::str::from_utf8(&output.stdout)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .collect();
        if container_ids.is_empty() {
            eprintln!("No containers found for project {project_name}");
        } else {
            let _ = diagnostic_output(
                "docker inspect",
                Command::new("docker")
                    .args([
                        "inspect",
                        "--format",
                        "{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} restart={{.RestartCount}} oom={{.State.OOMKilled}}",
                    ])
                    .args(container_ids),
            );
        }
    }

    eprintln!("Recent container logs:");
    let _ = diagnostic_output(
        "docker compose logs",
        compose_command(compose_file, project_name).args(["logs", "--no-color", "--tail", "200"]),
    );
}

/// Re-emit child output on the test thread so libtest captures it alongside
/// the failure. A failed diagnostic must remain visible without hiding the
/// original panic or preventing the remaining diagnostics and cleanup.
#[cfg(any(feature = "cosmos", feature = "native"))]
fn diagnostic_output(label: &str, command: &mut Command) -> Option<std::process::Output> {
    match command.output() {
        Ok(output) => {
            if !output.stdout.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            }
            if output.status.success() {
                Some(output)
            } else {
                eprintln!("{label} exited with {}", output.status);
                None
            }
        }
        Err(error) => {
            eprintln!("Failed to run {label}: {error}");
            None
        }
    }
}

#[cfg(any(feature = "cosmos", feature = "native"))]
pub(super) fn stop_compose(compose_file: &str, project_name: &str) {
    // `--profile node4`/`--profile defra` are harmless no-ops when that
    // profile was never used in `up` — passed unconditionally so `down`
    // always tears down whichever opt-in services this project actually
    // started, without the caller having to remember which profiles it used.
    match compose_command(compose_file, project_name)
        .args([
            "--profile",
            "node4",
            "--profile",
            "defra",
            "down",
            "-v",
            "--remove-orphans",
        ])
        .status()
    {
        Ok(status) if !status.success() => {
            eprintln!("docker compose down exited with non-zero status: {status}");
        }
        Ok(_) => {}
        Err(error) => eprintln!("Failed to stop docker compose: {error}"),
    }
}

/// Build the `cli-tool` sidecar image used by `defra_pre_scenario.rs`'s
/// reader step — a one-off container run on the test network's own bridge
/// for the one piece of that flow (Defra-stored PRE retrieval) a host
/// process can't reach on Docker Desktop (macOS/Windows); see that test's
/// own module doc comment. Idempotent: Docker's own build cache makes a
/// repeat call with the same `crypto_feature` a fast no-op after the first.
#[cfg(any(feature = "cosmos", feature = "native"))]
pub fn build_cli_tool_sidecar_image(crypto_feature: &str) -> Result<String, String> {
    let tag = format!("orbis-cli-tool-sidecar:{crypto_feature}");
    let status = Command::new("docker")
        .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
        .args([
            "build",
            "-f",
            "docker/Dockerfile.cli-tool-sidecar",
            "--build-arg",
            &format!("CRYPTO_FEATURE={crypto_feature}"),
            "-t",
            &tag,
            ".",
        ])
        .status()
        .map_err(|error| format!("Failed to run docker build for cli-tool sidecar: {error}"))?;
    if !status.success() {
        return Err(format!(
            "docker build failed for cli-tool sidecar image {tag}"
        ));
    }
    Ok(tag)
}

/// Run a one-off `image` container joined to `network`, passing `args` to
/// its entrypoint, and return its captured stdout. `--rm`: never left
/// behind, regardless of exit status.
#[cfg(any(feature = "cosmos", feature = "native"))]
pub fn run_sidecar_container(image: &str, network: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(["run", "--rm", "--network", network, image])
        .args(args)
        .output()
        .map_err(|error| format!("Failed to run sidecar container {image}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "sidecar container {image} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::unique_project_name;

    #[cfg(any(feature = "cosmos", feature = "native"))]
    #[test]
    fn parses_compose_port_output() {
        assert_eq!(
            super::parse_published_port("127.0.0.1:49152\n"),
            Some(49152)
        );
    }

    #[cfg(all(unix, feature = "native"))]
    #[test]
    fn native_compose_commands_supply_the_vera_revision() {
        let command = super::compose_command(crate::native_network::NATIVE_COMPOSE_FILE, "test");
        let value = command
            .get_envs()
            .find_map(|(key, value)| (key == "VERA_REF").then_some(value).flatten());
        let expected = std::env::var("VERA_REF")
            .ok()
            .filter(|revision| !revision.is_empty())
            .unwrap_or_else(crate::native_network::native_vera_ref);
        assert_eq!(
            value.and_then(|value| value.to_str()),
            Some(expected.as_str())
        );
    }

    #[test]
    fn project_names_are_unique() {
        assert_ne!(
            unique_project_name("orbis-test"),
            unique_project_name("orbis-test")
        );
    }
}
