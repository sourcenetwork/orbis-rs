//! Docker Compose subprocess helpers shared by [`super::VeraTestContainer`] and
//! [`super::IntegrationTestNetwork`].

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
    command
}

fn parse_published_port(output: &str) -> Option<u16> {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.trim().rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

pub(super) fn published_port(
    compose_file: &str,
    project_name: &str,
    service: &str,
    container_port: u16,
) -> Result<u16, String> {
    let output = compose_command(compose_file, project_name)
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

pub(super) fn localhost_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

pub(super) fn report_compose_failure(compose_file: &str, project_name: &str) {
    eprintln!("Docker Compose diagnostics for project {project_name}:");
    let _ = compose_command(compose_file, project_name)
        .args(["ps", "--all"])
        .status();

    if let Ok(output) = compose_command(compose_file, project_name)
        .args(["ps", "--all", "--quiet"])
        .output()
    {
        let container_ids: Vec<&str> = std::str::from_utf8(&output.stdout)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .collect();
        if !container_ids.is_empty() {
            let _ = Command::new("docker")
                .args([
                    "inspect",
                    "--format",
                    "{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} restart={{.RestartCount}} oom={{.State.OOMKilled}}",
                ])
                .args(container_ids)
                .status();
        }
    }

    eprintln!("Recent container logs:");
    let _ = compose_command(compose_file, project_name)
        .args(["logs", "--no-color", "--tail", "200"])
        .status();
}

pub(super) fn stop_compose(compose_file: &str, project_name: &str) {
    match compose_command(compose_file, project_name)
        .args(["--profile", "node4", "down", "-v", "--remove-orphans"])
        .status()
    {
        Ok(status) if !status.success() => {
            eprintln!("docker compose down exited with non-zero status: {status}");
        }
        Ok(_) => {}
        Err(error) => eprintln!("Failed to stop docker compose: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_published_port, unique_project_name};

    #[test]
    fn parses_compose_port_output() {
        assert_eq!(parse_published_port("127.0.0.1:49152\n"), Some(49152));
    }

    #[test]
    fn project_names_are_unique() {
        assert_ne!(
            unique_project_name("orbis-test"),
            unique_project_name("orbis-test")
        );
    }
}
