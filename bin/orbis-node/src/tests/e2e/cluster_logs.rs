//! Keep a failed test's `verad` logs, which otherwise go with the cluster's
//! temporary directory.

use std::path::{Path, PathBuf};
use vera_harness::cluster::TestCluster;

/// Where failed tests leave their validator logs: `ORBIS_TEST_LOG_DIR`, or
/// `orbis-test-logs` under the system temporary directory.
fn root() -> PathBuf {
    std::env::var_os("ORBIS_TEST_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("orbis-test-logs"))
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Copy every node's log directory when the current thread is panicking.
/// Call it from a `Drop` that runs before the cluster is dropped.
pub(super) fn retain_on_panic(cluster: &TestCluster) {
    if !std::thread::panicking() {
        return;
    }
    let test = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .replace("::", "-");
    let destination = root().join(format!("{test}-{}", std::process::id()));
    for index in 0..cluster.node_count() {
        let target = destination.join(format!("node{index}"));
        if let Err(error) = copy_dir(&cluster.node(index).log_dir, &target) {
            eprintln!(
                "could not keep node {index} logs in {}: {error}",
                target.display()
            );
        }
    }
    eprintln!("verad logs kept in {}", destination.display());
}
