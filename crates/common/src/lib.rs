pub mod blockchain;

use std::process::Command;
use std::time::Duration;

const DOCKER_COMPOSE_FILE: &str = "docker/docker-compose-sourcehub-test.yml";
const SOURCEHUB_RPC_URL: &str = "http://localhost:26657";
const SOURCEHUB_API_URL: &str = "http://localhost:1317";

pub struct SourceHubTestContainer {
    compose_file: String,
}

impl SourceHubTestContainer {
    pub fn new() -> Self {
        let compose_file = DOCKER_COMPOSE_FILE.to_string();

        // Start the container
        let status = Command::new("docker")
            .args(["compose", "-f", &compose_file, "up", "-d"])
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status()
            .expect("Failed to start docker compose");

        assert!(status.success(), "Failed to start sourcehub container");

        let container = Self { compose_file };

        // Wait for the container to be healthy
        container.wait_for_healthy();

        container
    }

    pub fn wait_for_healthy(&self) {
        let max_attempts = 60;
        let delay = Duration::from_secs(2);

        for attempt in 1..=max_attempts {
            if self.is_healthy() {
                println!("SourceHub is healthy after {} attempts", attempt);
                return;
            }
            println!(
                "Waiting for SourceHub to be healthy (attempt {}/{})",
                attempt, max_attempts
            );
            std::thread::sleep(delay);
        }

        panic!(
            "SourceHub failed to become healthy after {} attempts",
            max_attempts
        );
    }

    pub fn is_healthy(&self) -> bool {
        // Check if the RPC endpoint is responding
        let rpc_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", SOURCEHUB_RPC_URL)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !rpc_healthy {
            return false;
        }

        // Also check if the REST API is responding
        let rest_healthy = Command::new("curl")
            .args([
                "-sf",
                &format!(
                    "{}/cosmos/base/tendermint/v1beta1/node_info",
                    SOURCEHUB_API_URL
                ),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        rest_healthy
    }

    pub fn rpc_url(&self) -> &'static str {
        SOURCEHUB_RPC_URL
    }

    pub fn api_url(&self) -> &'static str {
        SOURCEHUB_API_URL
    }
}

impl Drop for SourceHubTestContainer {
    fn drop(&mut self) {
        println!("Stopping SourceHub test container...");

        let status = Command::new("docker")
            .args(["compose", "-f", &self.compose_file, "down", "-v"])
            .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
            .status();

        if let Err(e) = status {
            eprintln!("Failed to stop docker compose: {}", e);
        }
    }
}
