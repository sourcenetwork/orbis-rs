use crate::compose::{node_service, sourcehub_service_name, SOURCEHUB_SERVICE};
use crate::config::{NetworkProfile, NetworkProfileKind};
use crate::results::ResourceSample;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct DockerCompose {
    project: String,
    compose_file: PathBuf,
    working_dir: PathBuf,
}

impl DockerCompose {
    pub fn new(project: String, compose_file: PathBuf) -> Result<Self> {
        validate_project_name(&project)?;
        if !compose_file.is_file() {
            bail!("compose file does not exist: {}", compose_file.display());
        }
        // Docker Compose resolves --file relative to its process working
        // directory. The generated artifact path is commonly relative to the
        // repository root, while we deliberately run Compose from the stack
        // directory. Canonicalizing here prevents the stack path from being
        // applied twice (stack-dir/stack-dir/compose.yaml).
        let compose_file = compose_file
            .canonicalize()
            .with_context(|| format!("resolve compose file {}", compose_file.display()))?;
        let working_dir = compose_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok(Self {
            project,
            compose_file,
            working_dir,
        })
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    fn command(&self) -> Command {
        let mut command = Command::new("docker");
        command.kill_on_drop(true);
        command
            .arg("compose")
            .arg("--project-name")
            .arg(&self.project)
            .arg("--file")
            .arg(&self.compose_file)
            .current_dir(&self.working_dir);
        command
    }

    async fn status(&self, args: &[&str]) -> Result<()> {
        let output = self.command().args(args).output().await?;
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "docker compose {} failed for project {}: {}",
                args.join(" "),
                self.project,
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    async fn streamed_status(&self, args: &[&str]) -> Result<()> {
        let status = self.command().args(args).status().await?;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "docker compose {} failed for project {} with {status}",
                args.join(" "),
                self.project,
            ))
        }
    }

    async fn output(&self, args: &[&str]) -> Result<String> {
        let output = self.command().args(args).output().await?;
        if !output.status.success() {
            bail!(
                "docker compose {} failed for project {}: {}",
                args.join(" "),
                self.project,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    pub async fn build(&self) -> Result<()> {
        self.streamed_status(&["build", SOURCEHUB_SERVICE, "node-001"])
            .await
    }

    pub async fn up_sourcehub(&self, replicas: usize) -> Result<()> {
        let services: Vec<String> = (0..replicas).map(sourcehub_service_name).collect();
        let mut args = vec![
            "up".to_string(),
            "--detach".to_string(),
            "--wait".to_string(),
        ];
        args.extend(services);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.status(&refs).await
    }

    pub async fn up_nodes(&self) -> Result<()> {
        self.status(&["up", "--detach", "--no-build"]).await
    }

    pub async fn down(&self) -> Result<()> {
        self.status(&["down", "--volumes", "--remove-orphans"])
            .await
    }

    pub async fn published_port(&self, service: &str, container_port: u16) -> Result<u16> {
        let output = self
            .output(&["port", service, &container_port.to_string()])
            .await?;
        parse_published_port(&output).ok_or_else(|| {
            anyhow!("unexpected compose port output for {service}:{container_port}: {output:?}")
        })
    }

    pub async fn service_container_id(&self, service: &str) -> Result<String> {
        let output = self.output(&["ps", "--quiet", service]).await?;
        output
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("no container found for service {service}"))
    }

    pub async fn logs(&self, service: &str, tail: usize) -> Result<String> {
        self.output(&["logs", "--no-color", "--tail", &tail.to_string(), service])
            .await
    }

    pub async fn write_failure_logs(&self, output_dir: &Path, label: &str) -> Result<()> {
        tokio::fs::create_dir_all(output_dir).await?;
        let services = self.output(&["config", "--services"]).await?;
        for service in services.lines().filter(|line| !line.trim().is_empty()) {
            let logs = self
                .logs(service, 500)
                .await
                .unwrap_or_else(|error| format!("failed to collect logs: {error:#}"));
            tokio::fs::write(output_dir.join(format!("{label}-{service}.log")), logs).await?;
        }
        Ok(())
    }

    pub async fn apply_network_profile(
        &self,
        profile: &NetworkProfile,
        node_count: usize,
    ) -> Result<NetworkCalibration> {
        if profile.kind == NetworkProfileKind::Lan {
            return Ok(NetworkCalibration {
                profile: profile.clone(),
                applied_rules: Vec::new(),
                udp_probe: None,
            });
        }

        let rule = netem_rule(profile)?;
        let mut applied_rules = Vec::with_capacity(node_count);
        for index in 1..=node_count {
            let service = node_service(index);
            let script = format!(
                "tc qdisc replace dev eth0 root handle 1: prio; \
                 tc qdisc replace dev eth0 parent 1:3 handle 30: netem {rule}; \
                 tc filter replace dev eth0 protocol ip parent 1:0 prio 3 u32 match ip protocol 17 0xff flowid 1:3; \
                 tc -s qdisc show dev eth0"
            );
            let output = self
                .output(&["exec", "--no-TTY", &service, "sh", "-ec", &script])
                .await
                .with_context(|| format!("apply UDP-only netem to {service}"))?;
            applied_rules.push(AppliedNetworkRule { service, output });
        }

        // A real Iroh ceremony remains the primary calibration. This lightweight
        // UDP probe verifies that datagrams traverse the same shaped egress path.
        let udp_probe = if node_count >= 2 {
            Some(
                self.udp_calibration_probe(&node_service(1), &node_service(2), profile)
                    .await?,
            )
        } else {
            None
        };
        Ok(NetworkCalibration {
            profile: profile.clone(),
            applied_rules,
            udp_probe,
        })
    }

    async fn udp_calibration_probe(
        &self,
        source: &str,
        target: &str,
        profile: &NetworkProfile,
    ) -> Result<UdpProbe> {
        let target_script = format!(
            "payload=\"$(nc -u -l -w 5 45678)\"; test \"$payload\" = probe; printf pong | nc -u -w 2 {source} 45679"
        );
        let mut target_command = self.command();
        let mut target_listener = target_command
            .args(["exec", "--no-TTY", target, "sh", "-ec", &target_script])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let source_script = format!(
            "start=$(date +%s%N); (sleep 0.01; printf probe | nc -u -w 2 {target} 45678) & reply=\"$(nc -u -l -w 5 45679)\"; end=$(date +%s%N); test \"$reply\" = pong; echo $(((end-start)/1000000))"
        );
        let round_trip = self
            .output(&["exec", "--no-TTY", source, "sh", "-ec", &source_script])
            .await;
        let target_status = tokio::time::timeout(Duration::from_secs(7), target_listener.wait())
            .await
            .context("UDP calibration target did not exit")??;
        if !target_status.success() {
            bail!("UDP calibration echo process failed on {target}");
        }
        let elapsed_ms = round_trip?
            .lines()
            .last()
            .context("UDP calibration emitted no timing")?
            .trim()
            .parse()
            .context("parse UDP calibration milliseconds")?;
        if elapsed_ms + 5.0 < profile.delay_ms {
            bail!(
                "UDP calibration observed {elapsed_ms:.1} ms, below the configured {:.1} ms egress delay",
                profile.delay_ms
            );
        }
        Ok(UdpProbe {
            source: source.to_string(),
            target: target.to_string(),
            elapsed_ms,
            expected_egress_delay_ms: profile.delay_ms,
        })
    }

    pub async fn resource_samples(
        &self,
        run_id: &str,
        stack_id: &str,
    ) -> Result<Vec<ResourceSample>> {
        let ids = self.output(&["ps", "--quiet"]).await?;
        let ids: Vec<&str> = ids.lines().filter(|line| !line.is_empty()).collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = Command::new("docker");
        command.kill_on_drop(true);
        let output = command
            .arg("stats")
            .arg("--no-stream")
            .arg("--format")
            .arg("{{json .}}")
            .args(&ids)
            .output()
            .await?;
        if !output.status.success() {
            bail!(
                "docker stats failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let sampled_at_unix_ms = unix_ms();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| parse_stats_line(line, run_id, stack_id, sampled_at_unix_ms))
            .collect()
    }

    pub async fn container_failures(&self) -> Result<Vec<ContainerFailure>> {
        let ids = self.output(&["ps", "--all", "--quiet"]).await?;
        let mut failures = Vec::new();
        for id in ids.lines().filter(|line| !line.is_empty()) {
            let mut command = Command::new("docker");
            command.kill_on_drop(true);
            let output = command.args(["inspect", id]).output().await?;
            if !output.status.success() {
                continue;
            }
            let inspected: Vec<ContainerInspect> = serde_json::from_slice(&output.stdout)?;
            let Some(inspected) = inspected.into_iter().next() else {
                continue;
            };
            if inspected.state.oom_killed
                || inspected.restart_count > 0
                || inspected.state.status == "exited"
            {
                failures.push(ContainerFailure {
                    container_id: id.to_string(),
                    status: inspected.state.status,
                    exit_code: inspected.state.exit_code,
                    oom_killed: inspected.state.oom_killed,
                    restart_count: inspected.restart_count,
                });
            }
        }
        Ok(failures)
    }
}

fn validate_project_name(project: &str) -> Result<()> {
    if !project.starts_with("orbis-bench-")
        || project.len() > 63
        || !project
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("refusing non-benchmark Compose project name: {project:?}");
    }
    Ok(())
}

pub fn parse_published_port(output: &str) -> Option<u16> {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(|line| line.trim().rsplit_once(':'))
        .and_then(|(_, port)| port.parse().ok())
}

fn netem_rule(profile: &NetworkProfile) -> Result<String> {
    if !profile.delay_ms.is_finite()
        || !profile.jitter_ms.is_finite()
        || !profile.loss_percent.is_finite()
    {
        bail!("network shaping values must be finite");
    }
    let mut pieces = vec![format!("delay {:.3}ms", profile.delay_ms)];
    if profile.jitter_ms > 0.0 {
        pieces.push(format!("{:.3}ms", profile.jitter_ms));
    }
    if profile.loss_percent > 0.0 {
        pieces.push(format!("loss {:.4}%", profile.loss_percent));
    }
    Ok(pieces.join(" "))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkCalibration {
    pub profile: NetworkProfile,
    pub applied_rules: Vec<AppliedNetworkRule>,
    pub udp_probe: Option<UdpProbe>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppliedNetworkRule {
    pub service: String,
    pub output: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UdpProbe {
    pub source: String,
    pub target: String,
    pub elapsed_ms: f64,
    pub expected_egress_delay_ms: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContainerFailure {
    pub container_id: String,
    pub status: String,
    pub exit_code: i64,
    pub oom_killed: bool,
    pub restart_count: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerStats {
    #[serde(rename = "ID")]
    id: String,
    name: String,
    #[serde(rename = "CPUPerc")]
    cpu_percent: String,
    #[serde(rename = "MemUsage")]
    memory_usage: String,
    #[serde(rename = "NetIO")]
    network_io: String,
    #[serde(rename = "BlockIO")]
    block_io: String,
    #[serde(rename = "PIDs")]
    pids: String,
}

fn parse_stats_line(
    line: &str,
    run_id: &str,
    stack_id: &str,
    sampled_at_unix_ms: u128,
) -> Result<ResourceSample> {
    let value: DockerStats = serde_json::from_str(line).context("parse docker stats JSON")?;
    let (memory_bytes, memory_limit_bytes) = parse_pair(&value.memory_usage);
    let (network_rx_bytes, network_tx_bytes) = parse_pair(&value.network_io);
    let (block_read_bytes, block_write_bytes) = parse_pair(&value.block_io);
    Ok(ResourceSample {
        run_id: run_id.to_string(),
        stack_id: stack_id.to_string(),
        sampled_at_unix_ms,
        service: value.name,
        container_id: value.id,
        cpu_percent: value.cpu_percent.trim_end_matches('%').trim().parse().ok(),
        memory_bytes,
        memory_limit_bytes,
        network_rx_bytes,
        network_tx_bytes,
        block_read_bytes,
        block_write_bytes,
        pids: value.pids.trim().parse().ok(),
    })
}

fn parse_pair(value: &str) -> (Option<u64>, Option<u64>) {
    let mut parts = value.split('/').map(str::trim);
    (
        parts.next().and_then(parse_bytes),
        parts.next().and_then(parse_bytes),
    )
}

pub fn parse_bytes(value: &str) -> Option<u64> {
    let split = value.find(|character: char| !character.is_ascii_digit() && character != '.')?;
    let number: f64 = value[..split].trim().parse().ok()?;
    let unit = value[split..].trim().to_ascii_lowercase();
    let multiplier = match unit.as_str() {
        "b" => 1.0,
        "kb" => 1_000.0,
        "kib" => 1_024.0,
        "mb" => 1_000_000.0,
        "mib" => 1_048_576.0,
        "gb" => 1_000_000_000.0,
        "gib" => 1_073_741_824.0,
        _ => return None,
    };
    Some((number * multiplier).round() as u64)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    status: String,
    exit_code: i64,
    #[serde(rename = "OOMKilled")]
    oom_killed: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerInspect {
    state: ContainerState,
    #[serde(default)]
    restart_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorReport {
    pub docker_version: String,
    pub compose_version: String,
    pub cpu_count: usize,
    pub available_memory_bytes: Option<u64>,
    pub available_disk_bytes: Option<u64>,
    pub net_admin_probe: String,
    pub warnings: Vec<String>,
}

pub async fn doctor(runtime_image: Option<&str>) -> Result<DoctorReport> {
    let docker_version = command_text("docker", &["version", "--format", "{{json .}}"])
        .await
        .context("Docker daemon is unavailable")?;
    let compose_version = command_text("docker", &["compose", "version", "--short"])
        .await
        .context("Docker Compose v2 is unavailable")?;
    let info = command_text("docker", &["info", "--format", "{{json .}}"]).await?;
    let info_json: serde_json::Value = serde_json::from_str(&info).unwrap_or_default();
    let available_memory_bytes = info_json
        .get("MemTotal")
        .and_then(ValueExt::as_u64_flexible);
    let cpu_count = info_json
        .get("NCPU")
        .and_then(ValueExt::as_u64_flexible)
        .map(|value| value as usize)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
        });
    let available_disk_bytes = host_disk_available().await.ok();
    let mut warnings = Vec::new();
    if cpu_count < 4 {
        warnings.push("Docker exposes fewer than 4 CPUs; large rings will be host-limited".into());
    }
    if available_memory_bytes.is_some_and(|bytes| bytes < 8 * 1024 * 1024 * 1024) {
        warnings
            .push("Docker exposes less than 8 GiB RAM; a 50-node stack is unlikely to fit".into());
    }

    let net_admin_probe = if let Some(image) = runtime_image {
        let mut command = Command::new("docker");
        command.kill_on_drop(true);
        let output = command
            .args([
                "run",
                "--rm",
                "--cap-add",
                "NET_ADMIN",
                "--entrypoint",
                "sh",
                image,
                "-ec",
                "test -x /usr/local/bin/orbis-node; command -v tc >/dev/null; ! command -v orbis-bench >/dev/null; tc qdisc add dev lo root netem delay 1ms; tc qdisc del dev lo root",
            ])
            .output()
            .await?;
        if !output.status.success() {
            bail!(
                "runtime image prerequisite/NET_ADMIN probe failed for {image}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        "passed (tc present; orbis-bench absent)".to_string()
    } else {
        warnings.push(
            "runtime image was not supplied; NET_ADMIN and image-content probes were skipped"
                .into(),
        );
        "skipped".to_string()
    };

    Ok(DoctorReport {
        docker_version,
        compose_version,
        cpu_count,
        available_memory_bytes,
        available_disk_bytes,
        net_admin_probe,
        warnings,
    })
}

pub async fn image_digest(image: &str) -> Result<String> {
    command_text(
        "docker",
        &["image", "inspect", "--format", "{{.Id}}", image],
    )
    .await
}

async fn command_text(program: &str, args: &[&str]) -> Result<String> {
    let mut command = Command::new(program);
    command.kill_on_drop(true);
    let output = command.args(args).stdin(Stdio::null()).output().await?;
    if !output.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn host_disk_available() -> Result<u64> {
    let output = command_text("df", &["-Pk", "."]).await?;
    let row = output
        .lines()
        .last()
        .context("df returned no filesystem row")?;
    let available_kib: u64 = row
        .split_ascii_whitespace()
        .nth(3)
        .context("df row omitted available blocks")?
        .parse()?;
    Ok(available_kib.saturating_mul(1_024))
}

trait ValueExt {
    fn as_u64_flexible(&self) -> Option<u64>;
}

impl ValueExt for serde_json::Value {
    fn as_u64_flexible(&self) -> Option<u64> {
        self.as_u64()
            .or_else(|| self.as_str().and_then(|value| value.parse().ok()))
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_project_scope_is_enforced() {
        assert!(validate_project_name("orbis-bench-run1-s001").is_ok());
        assert!(validate_project_name("production").is_err());
        assert!(validate_project_name("orbis-bench-BAD").is_err());
    }

    #[test]
    fn parses_ports_and_docker_units() {
        assert_eq!(parse_published_port("0.0.0.0:49153\n"), Some(49153));
        assert_eq!(parse_published_port("[::]:49154\n"), Some(49154));
        assert_eq!(parse_bytes("1.5GiB"), Some(1_610_612_736));
        assert_eq!(parse_bytes("12.3MB"), Some(12_300_000));
    }

    #[test]
    fn netem_is_udp_delay_jitter_and_loss() {
        let rule = netem_rule(&NetworkProfile {
            name: "wan".into(),
            kind: NetworkProfileKind::Wan,
            delay_ms: 25.0,
            jitter_ms: 5.0,
            loss_percent: 0.1,
        })
        .unwrap();
        assert_eq!(rule, "delay 25.000ms 5.000ms loss 0.1000%");
    }

    #[test]
    fn compose_file_is_absolute_when_working_directory_changes() {
        let original_dir = std::env::current_dir().unwrap();
        let temp = tempfile::tempdir_in(&original_dir).unwrap();
        let relative_dir = temp.path().strip_prefix(&original_dir).unwrap();
        let relative_file = relative_dir.join("compose.yaml");
        std::fs::write(original_dir.join(&relative_file), "services: {}\n").unwrap();

        let compose = DockerCompose::new("orbis-bench-path-test".into(), relative_file).unwrap();

        assert!(compose.compose_file.is_absolute());
        assert_eq!(
            compose.compose_file.parent(),
            Some(compose.working_dir.as_path())
        );
        assert_eq!(
            compose.compose_file,
            compose.working_dir.join("compose.yaml")
        );
    }
}
