//! End-to-end test harness for orbis-rs.
//!
//! Provides ring configuration builders, process management, and health checks
//! for driving multi-node Orbis test rings.
//!
//! Each test run gets a unique `run_id` for isolation:
//! - State dirs under `target/e2e/{run_id}/`
//! - Auto-assigned ports (no conflicts between parallel runs)
//! - `Drop` cleans up unless `ORBIS_E2E_KEEP=1`

pub mod fixture;
pub mod orbis;
pub mod sourcehub;

use std::{
    fmt,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::Rng;

/// Generate a unique run ID based on timestamp + random suffix.
pub fn generate_run_id() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let suffix: u32 = rand::thread_rng().gen_range(1000..9999);
    format!("{ts}-{suffix}")
}

/// Whether to keep test artifacts after completion.
pub fn keep_artifacts() -> bool {
    std::env::var("ORBIS_E2E_KEEP").map_or(false, |v| v == "1" || v == "true")
}

/// Allocate N unique ports using OS auto-assignment.
///
/// Binds to port 0, holds listeners briefly to reserve ports,
/// then releases them for process startup.
pub fn allocate_ports(n: usize) -> eyre::Result<Vec<u16>> {
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| eyre::eyre!("failed to allocate port: {}", e))?;
        let port = listener.local_addr()?.port();
        ports.push(port);
        listeners.push(listener);
    }
    drop(listeners);
    Ok(ports)
}

/// Base directory for e2e test artifacts.
pub fn e2e_base_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."))
        .join("target")
        .join("e2e")
}

/// A managed child process that sends SIGTERM on drop.
///
/// Redirects stdout/stderr to log files in the given log directory.
/// On drop: SIGTERM → wait 500ms → SIGKILL if still alive.
pub struct ManagedProcess {
    name: String,
    child: Option<Child>,
    log_dir: PathBuf,
}

impl fmt::Debug for ManagedProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedProcess")
            .field("name", &self.name)
            .field("running", &self.child.is_some())
            .field("log_dir", &self.log_dir)
            .finish()
    }
}

impl ManagedProcess {
    /// Spawn a new managed process.
    ///
    /// Creates log files at `{log_dir}/stdout.log` and `{log_dir}/stderr.log`.
    pub fn spawn(name: &str, cmd: &mut Command, log_dir: &Path) -> eyre::Result<Self> {
        std::fs::create_dir_all(log_dir)?;

        let stdout_file = std::fs::File::create(log_dir.join("stdout.log"))?;
        let stderr_file = std::fs::File::create(log_dir.join("stderr.log"))?;

        let child = cmd
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| eyre::eyre!("failed to spawn '{}': {}", name, e))?;

        tracing::info!(name, pid = child.id(), "spawned process");

        Ok(Self {
            name: name.to_string(),
            child: Some(child),
            log_dir: log_dir.to_path_buf(),
        })
    }

    /// Check if the process is still running.
    pub fn is_running(&mut self) -> bool {
        self.child
            .as_mut()
            .map_or(false, |c| c.try_wait().ok().flatten().is_none())
    }

    /// Kill the process immediately.
    pub fn kill(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!(name = self.name, "killed process");
        }
        self.child = None;
    }

    /// Get the log directory path.
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Get the process name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            // Send SIGTERM on Unix
            #[cfg(unix)]
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }

            // Wait up to 500ms for graceful shutdown
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            loop {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }

            tracing::debug!(name = self.name, "cleaned up process");
        }
    }
}

/// A test run directory that cleans up on drop (unless `ORBIS_E2E_KEEP=1`).
///
/// Field drop order matters: in structs that hold both processes and a TestRunDir,
/// the processes must be listed first so they're killed before the directory is removed.
#[derive(Debug)]
pub struct TestRunDir {
    path: PathBuf,
    keep: bool,
}

impl TestRunDir {
    /// Create a new test run directory under `target/e2e/{run_id}/`.
    pub fn new(run_id: &str) -> eyre::Result<Self> {
        let path = e2e_base_dir().join(run_id);
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            keep: keep_artifacts(),
        })
    }

    /// Get the run directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create a subdirectory for a named component (e.g. "node0", "node1").
    pub fn component_dir(&self, name: &str) -> eyre::Result<PathBuf> {
        let dir = self.path.join(name);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

impl Drop for TestRunDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        } else {
            eprintln!("Preserving test artifacts at: {}", self.path.display());
        }
    }
}

/// Find the orbis-node binary in the target directory.
///
/// Looks for `target/debug/orbis-node` relative to the workspace root.
/// Returns an error with a helpful message if not found.
pub fn find_orbis_node_binary() -> eyre::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."));

    // Check debug first, then release
    let debug_binary = workspace_root.join("target").join("debug").join("orbis-node");
    if debug_binary.exists() {
        return Ok(debug_binary);
    }

    let release_binary = workspace_root
        .join("target")
        .join("release")
        .join("orbis-node");
    if release_binary.exists() {
        return Ok(release_binary);
    }

    Err(eyre::eyre!(
        "orbis-node binary not found. Run `cargo build -p orbis-node` first.\n\
         Looked at:\n  {}\n  {}",
        debug_binary.display(),
        release_binary.display()
    ))
}
