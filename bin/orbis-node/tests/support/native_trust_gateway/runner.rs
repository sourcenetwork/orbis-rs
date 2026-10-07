use super::private_file;
use std::{
    io::Read as _,
    os::unix::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

pub(super) fn artifacts() -> PathBuf {
    for name in ["TRUST_NATIVE_GATEWAY_TEST_BINARY", "DEFRADB_RUST_BINARY"] {
        let path = std::env::var_os(name).expect("compiled Trust/Defra fixture artifact required");
        assert!(
            Path::new(&path).is_absolute() && Path::new(&path).is_file(),
            "fixture binary path"
        );
    }
    assert!(
        std::env::var_os("TRUST_NATIVE_GATEWAY_BINARY").is_some()
            || std::env::var_os("TRUST_NATIVE_GATEWAY_IMAGE").is_some(),
        "a production native gateway artifact is required"
    );
    PathBuf::from(std::env::var_os("TRUST_NATIVE_GATEWAY_TEST_BINARY").unwrap())
}

// Own the Go subprocess group, including any host gateway/Defra children.
// The Go fixture owns graceful process/container cleanup on normal completion.
struct Group(u32);
impl Drop for Group {
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", self.0)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub(super) async fn run(binary: &Path, descriptor: &Path, root: &Path) {
    let log = root.join("trust-ring-go.log");
    let output = private_file(&log);
    let mut command = tokio::process::Command::new(binary);
    command.as_std_mut().process_group(0);
    command
        .args([
            "-test.run=^TestNativeGatewayRingDKGContract$",
            "-test.v",
            "-test.timeout=120s",
        ])
        .env("TRUST_NATIVE_RING_FIXTURE", descriptor)
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .kill_on_drop(true);
    let mut child = command.spawn().expect("start compiled Trust ring contract");
    let _group = Group(child.id().expect("Go fixture process ID"));
    let status = tokio::time::timeout(Duration::from_secs(125), child.wait())
        .await
        .expect("Go ring contract exceeded the existing gateway test deadline")
        .expect("wait for Go ring contract");
    assert!(
        status.success(),
        "Go ring contract failed; details retained privately"
    );
    let mut output = String::new();
    std::fs::File::open(log)
        .unwrap()
        .take(4 * 1024 * 1024)
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("--- PASS: TestNativeGatewayRingDKGContract ("))
            .count(),
        1,
        "the exact Go contract must execute once and pass"
    );
}
