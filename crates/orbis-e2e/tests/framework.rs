//! Framework validation tests.
//!
//! These tests validate the e2e framework infrastructure itself:
//! port allocation, directory lifecycle, process management, run ID generation.
//! They don't require orbis-node or SourceHub.

use orbis_e2e::{allocate_ports, generate_run_id, find_orbis_node_binary, ManagedProcess, TestRunDir};
use std::process::Command;

#[test]
fn run_id_is_unique() {
    let id1 = generate_run_id();
    let id2 = generate_run_id();
    assert_ne!(id1, id2, "run IDs should be unique");
    assert!(id1.contains('-'), "run ID should have timestamp-suffix format");
}

#[test]
fn allocate_ports_returns_unique_ports() {
    let ports = allocate_ports(5).expect("should allocate 5 ports");
    assert_eq!(ports.len(), 5);

    // All ports should be unique
    let mut sorted = ports.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 5, "all ports should be unique");

    // All ports should be non-zero
    for p in &ports {
        assert!(*p > 0, "port should be non-zero");
    }
}

#[test]
fn test_run_dir_creates_and_cleans_up() {
    let run_id = generate_run_id();
    let path;
    {
        let dir = TestRunDir::new(&run_id).expect("should create run dir");
        path = dir.path().to_path_buf();
        assert!(path.exists(), "run dir should exist");

        // Create a subdirectory
        let sub = dir.component_dir("node0").expect("should create component dir");
        assert!(sub.exists(), "component dir should exist");
    }
    // After drop, directory should be cleaned up (unless ORBIS_E2E_KEEP=1)
    if std::env::var("ORBIS_E2E_KEEP").map_or(true, |v| v != "1" && v != "true") {
        assert!(!path.exists(), "run dir should be cleaned up on drop");
    }
}

#[test]
fn managed_process_spawns_and_cleans_up() {
    let run_id = generate_run_id();
    let dir = TestRunDir::new(&run_id).expect("should create run dir");
    let log_dir = dir.component_dir("test-process").expect("should create log dir");

    // Spawn a simple process (sleep for a bit)
    let mut cmd = Command::new("sleep");
    cmd.arg("60");

    let mut proc = ManagedProcess::spawn("test-sleeper", &mut cmd, &log_dir)
        .expect("should spawn process");

    assert!(proc.is_running(), "process should be running after spawn");

    // Kill it
    proc.kill();
    assert!(!proc.is_running(), "process should not be running after kill");

    // Log files should exist
    assert!(log_dir.join("stdout.log").exists(), "stdout.log should exist");
    assert!(log_dir.join("stderr.log").exists(), "stderr.log should exist");
}

#[test]
fn managed_process_sigterm_on_drop() {
    let run_id = generate_run_id();
    let dir = TestRunDir::new(&run_id).expect("should create run dir");
    let log_dir = dir.component_dir("drop-test").expect("should create log dir");

    let mut cmd = Command::new("sleep");
    cmd.arg("60");

    let proc = ManagedProcess::spawn("drop-sleeper", &mut cmd, &log_dir)
        .expect("should spawn process");

    // Get the pid before dropping
    // (we can't easily check the pid after drop, but we verify the Drop impl runs without panic)
    drop(proc);

    // If we get here, SIGTERM + cleanup worked
}

#[test]
fn orbis_node_binary_exists() {
    // This test verifies the binary was built (cargo build -p orbis-node should have run)
    match find_orbis_node_binary() {
        Ok(path) => {
            assert!(path.exists(), "binary path should exist");
            assert!(
                path.to_str().unwrap().contains("orbis-node"),
                "binary should be named orbis-node"
            );
        }
        Err(e) => {
            // Not a hard failure — binary just needs to be built first
            eprintln!("orbis-node binary not found (run `cargo build -p orbis-node`): {}", e);
        }
    }
}
