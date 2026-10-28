//! Container lifecycle shared by native integration fixtures.
//! Commands and container output stay in the fixture's private directory.

use crate::compose::{compose_command, unique_project_name};
use serde::Deserialize;
use std::{
    fs::{self, File},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("container fixture I/O: {0}")]
    Io(#[from] io::Error),
    #[error("container metadata: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Docker {operation} failed (exit {code:?}); details retained privately")]
    Command {
        operation: &'static str,
        code: Option<i32>,
    },
    #[error("Docker {0} exceeded its command deadline")]
    Timeout(&'static str),
    #[error("Docker returned invalid container identity")]
    Identity,
    #[error("native container fixture requires Linux host networking")]
    Platform,
    #[error("container paths must remain inside the private fixture root")]
    Path,
}

#[derive(Clone, Copy, Debug)]
pub enum NativeImage {
    Vera,
    Orbis,
    OrbisDiagnostic,
}
impl NativeImage {
    fn image(self) -> String {
        let (variable, fallback) = match self {
            Self::Vera => ("ORBIS_NATIVE_VERA_IMAGE", "orbis-vera-native:local"),
            Self::Orbis => ("ORBIS_NATIVE_IMAGE", "orbis-node-native:local"),
            Self::OrbisDiagnostic => (
                "ORBIS_NATIVE_DIAGNOSTIC_IMAGE",
                "orbis-node-native-diagnostic:local",
            ),
        };
        std::env::var(variable).unwrap_or_else(|_| fallback.into())
    }
    fn entrypoint(self) -> &'static str {
        match self {
            Self::Vera => "verad",
            Self::Orbis | Self::OrbisDiagnostic => "orbis-node",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ContainerExit {
    code: i32,
}
impl ContainerExit {
    pub fn success(self) -> bool {
        self.code == 0
    }
}
impl std::fmt::Display for ContainerExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "container exit {}", self.code)
    }
}

#[derive(Deserialize)]
struct State {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "ExitCode")]
    exit_code: i32,
}

/// Container UID/GID for a directory owned by the fixture.
pub fn bind_mount_user(directory: &Path) -> io::Result<String> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixture must be a directory",
        ));
    }
    Ok(format!("{}:{}", metadata.uid(), metadata.gid()))
}

/// One Compose service with a private bind-mounted store and explicit lifecycle.
/// Linux host networking preserves the fixture's loopback-only peer endpoints.
pub struct ContainerNode {
    project: String,
    compose: PathBuf,
    private: PathBuf,
    log: PathBuf,
    container: String,
    sequence: AtomicU64,
    _control: tempfile::TempDir,
}
impl ContainerNode {
    pub fn start(
        image: NativeImage,
        root: &Path,
        directory: &Path,
        args: &[String],
        environment: &[(&str, &str)],
        log: &Path,
    ) -> Result<Self, ContainerError> {
        if !cfg!(target_os = "linux") {
            return Err(ContainerError::Platform);
        }
        let (root, directory, log) = private_paths(root, directory, log)?;
        let project = unique_project_name("orbis-native");
        let mut control = tempfile::Builder::new()
            .prefix("orbis-compose-")
            .tempdir()?;
        if std::env::var("VERA_E2E_KEEP").is_ok_and(|value| value == "1") {
            control.disable_cleanup(true);
        }
        let private = control.path().to_owned();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
        let compose = private.join("compose.json");
        let user = bind_mount_user(&directory)?;
        let environment: std::collections::BTreeMap<_, _> = environment.iter().copied().collect();
        let spec = serde_json::json!({"services": {"node": {
            "image": image.image(), "entrypoint": [image.entrypoint()], "command": args,
            "network_mode": "host", "working_dir": directory,
            "user": user,
            "volumes": [{"type": "bind", "source": root, "target": root}],
            "environment": environment, "stop_signal": "SIGINT", "stop_grace_period": "10s"
        }}});
        fs::write(&compose, serde_json::to_vec(&spec)?)?;
        File::create(&log)?;
        let mut node = Self {
            project,
            compose,
            private,
            log,
            container: String::new(),
            sequence: AtomicU64::new(0),
            _control: control,
        };
        let mut start = node.compose_command();
        start.args(["up", "-d", "--no-build", "--pull", "never"]);
        node.run("start", start)?;
        let mut identity = node.compose_command();
        identity.args(["ps", "--all", "--quiet", "node"]);
        let output = node.run("identity", identity)?;
        let id = fs::read_to_string(output)?.trim().to_owned();
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ContainerError::Identity);
        }
        node.container = id;
        Ok(node)
    }

    fn compose_command(&self) -> Command {
        compose_command(
            self.compose
                .to_str()
                .expect("private Compose path is UTF-8"),
            &self.project,
        )
    }

    fn run(
        &self,
        operation: &'static str,
        mut command: Command,
    ) -> Result<PathBuf, ContainerError> {
        let number = self.sequence.fetch_add(1, Ordering::Relaxed);
        let output = self.private.join(format!("{number}-{operation}.out"));
        let stderr = self.private.join(format!("{number}-{operation}.err"));
        let mut child = command
            .stdout(Stdio::from(File::create(&output)?))
            .stderr(Stdio::from(File::create(stderr)?))
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error.into());
                }
            };
            if let Some(status) = status {
                if status.success() {
                    return Ok(output);
                }
                return Err(ContainerError::Command {
                    operation,
                    code: status.code(),
                });
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ContainerError::Timeout(operation));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn try_wait(&self) -> Result<Option<ContainerExit>, ContainerError> {
        let mut command = Command::new("docker");
        command.args(["inspect", "--format", "{{json .State}}", &self.container]);
        let output = self.run("inspect", command)?;
        let state: State = serde_json::from_slice(&fs::read(output)?)?;
        Ok((!state.running).then_some(ContainerExit {
            code: state.exit_code,
        }))
    }

    // Direct Docker commands avoid a Compose plugin subprocess surviving
    // cancellation. Dropping the future kills the Docker client, not the node.
    #[cfg(feature = "native")]
    async fn run_async(
        &self,
        operation: &'static str,
        mut command: Command,
        merge_output: bool,
    ) -> Result<PathBuf, ContainerError> {
        let number = self.sequence.fetch_add(1, Ordering::Relaxed);
        let output = self.private.join(format!("{number}-{operation}.out"));
        let stdout = File::create(&output)?;
        let stderr = if merge_output {
            stdout.try_clone()?
        } else {
            File::create(self.private.join(format!("{number}-{operation}.err")))?
        };
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut command = tokio::process::Command::from(command);
        let status =
            tokio::time::timeout(Duration::from_secs(30), command.kill_on_drop(true).status())
                .await
                .map_err(|_| ContainerError::Timeout(operation))??;
        if !status.success() {
            return Err(ContainerError::Command {
                operation,
                code: status.code(),
            });
        }
        Ok(output)
    }

    /// Observe the node without blocking a caller's asynchronous readiness gate.
    #[cfg(feature = "native")]
    pub async fn try_wait_async(&self) -> Result<Option<ContainerExit>, ContainerError> {
        let mut command = Command::new("docker");
        command.args(["inspect", "--format", "{{json .State}}", &self.container]);
        let output = self.run_async("inspect", command, false).await?;
        let state: State = serde_json::from_slice(&tokio::fs::read(output).await?)?;
        Ok((!state.running).then_some(ContainerExit {
            code: state.exit_code,
        }))
    }

    /// Refresh private live logs; cancellation respects the caller's deadline.
    #[cfg(feature = "native")]
    pub async fn refresh_logs(&self) -> Result<(), ContainerError> {
        let mut command = Command::new("docker");
        command.args(["logs", &self.container]);
        let output = self.run_async("live-logs", command, true).await?;
        tokio::fs::copy(output, &self.log).await?;
        Ok(())
    }

    #[cfg(feature = "native")]
    pub async fn interrupt_async(&self) -> Result<(), ContainerError> {
        let mut command = Command::new("docker");
        command.args(["kill", "--signal", "SIGINT", &self.container]);
        self.run_async("interrupt", command, false).await?;
        Ok(())
    }

    fn signal(&self, signal: &'static str) -> Result<(), ContainerError> {
        let mut command = self.compose_command();
        command.args(["kill", "--signal", signal, "node"]);
        self.run("signal", command)?;
        Ok(())
    }
    pub fn kill(&self) -> Result<(), ContainerError> {
        self.signal("SIGKILL")
    }
    pub fn pause(&self) -> Result<(), ContainerError> {
        self.signal("SIGSTOP")
    }

    pub fn wait(&self) -> Result<ContainerExit, ContainerError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.try_wait()? {
                self.retain_logs()?;
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(ContainerError::Timeout("exit"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn retain_logs(&self) -> Result<(), ContainerError> {
        let mut command = self.compose_command();
        command.args(["logs", "--no-color", "--no-log-prefix", "node"]);
        let output = self.run("logs", command)?;
        fs::copy(output, &self.log)?;
        Ok(())
    }
}
impl Drop for ContainerNode {
    fn drop(&mut self) {
        let _ = self.retain_logs();
        let mut command = self.compose_command();
        command.args(["down", "--timeout", "1", "--remove-orphans"]);
        let _ = self.run("cleanup", command);
    }
}

fn private_paths(
    root: &Path,
    directory: &Path,
    log: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), ContainerError> {
    let root = root.canonicalize()?;
    let directory = directory.canonicalize()?;
    let log_parent = log.parent().ok_or(ContainerError::Path)?.canonicalize()?;
    let log = log_parent.join(log.file_name().ok_or(ContainerError::Path)?);
    if !directory.starts_with(&root)
        || !log_parent.starts_with(&root)
        || log
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(ContainerError::Path);
    }
    Ok((root, directory, log))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bind_mount_user_rejects_files_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, "fixture").unwrap();
        assert_eq!(
            bind_mount_user(&file).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let link = root.path().join("link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        assert_eq!(
            bind_mount_user(&link).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(bind_mount_user(root.path()).is_ok());
    }

    #[test]
    fn private_paths_reject_external_stores_and_symlinked_logs() {
        let fixture = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        let root = fixture.path();
        let log = root.join("node.log");
        assert!(private_paths(root, root, &log).is_ok());
        assert!(matches!(
            private_paths(root, foreign.path(), &log),
            Err(ContainerError::Path)
        ));
        assert!(matches!(
            private_paths(root, root, &foreign.path().join("node.log")),
            Err(ContainerError::Path)
        ));
        let external = foreign.path().join("existing.log");
        fs::write(&external, "preserve").unwrap();
        std::os::unix::fs::symlink(&external, &log).unwrap();
        assert!(matches!(
            private_paths(root, root, &log),
            Err(ContainerError::Path)
        ));
        assert_eq!(fs::read_to_string(external).unwrap(), "preserve");
    }
}
