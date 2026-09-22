//! A standalone Vera chain container, with no orbis-node instances.

use super::compose::{
    compose_command, localhost_url, published_port, report_compose_failure, stop_compose,
    unique_project_name,
};
use common::blockchain::{ChainConfig, ChainConfigBuilder};
use std::process::Command;
use std::time::Duration;

const DOCKER_COMPOSE_FILE: &str = "docker/docker-compose-vera-test.yml";

pub struct VeraTestContainer {
    compose_file: String,
    project_name: String,
    chain_config: ChainConfig,
}

impl VeraTestContainer {
    pub fn new() -> Self {
        let compose_file = DOCKER_COMPOSE_FILE.to_string();
        let project_name = unique_project_name("orbis-vera");

        let status = compose_command(&compose_file, &project_name)
            .args(["up", "-d", "--build"])
            .status()
            .expect("Failed to start docker compose");

        if !status.success() {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to start vera container");
        }

        let chain_config = (|| -> Result<ChainConfig, String> {
            Ok(ChainConfig::builder()
                .rpc_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "vera",
                    26657,
                )?)))
                .rest_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "vera",
                    1317,
                )?)))
                .grpc_url(Some(localhost_url(published_port(
                    &compose_file,
                    &project_name,
                    "vera",
                    9090,
                )?)))
                .build())
        })()
        .unwrap_or_else(|error| {
            report_compose_failure(&compose_file, &project_name);
            stop_compose(&compose_file, &project_name);
            panic!("Failed to discover Vera endpoints: {error}");
        });

        let container = Self {
            compose_file,
            project_name,
            chain_config,
        };

        container.wait_for_healthy();

        container
    }

    pub fn wait_for_healthy(&self) {
        let max_attempts = 60;
        let delay = Duration::from_secs(2);

        for attempt in 1..=max_attempts {
            if self.is_healthy() {
                println!("Vera is healthy after {} attempts", attempt);
                return;
            }
            println!(
                "Waiting for Vera to be healthy (attempt {}/{})",
                attempt, max_attempts
            );
            std::thread::sleep(delay);
        }

        panic!(
            "Vera failed to become healthy after {} attempts",
            max_attempts
        );
    }

    pub fn is_healthy(&self) -> bool {
        let rpc_healthy = Command::new("curl")
            .args(["-sf", &format!("{}/health", self.rpc_url())])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !rpc_healthy {
            return false;
        }

        let rest_healthy = Command::new("curl")
            .args([
                "-sf",
                &format!(
                    "{}/cosmos/base/tendermint/v1beta1/node_info",
                    self.api_url()
                ),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        rest_healthy
    }

    pub fn rpc_url(&self) -> &str {
        &self.chain_config.rpc_url
    }

    pub fn api_url(&self) -> &str {
        &self.chain_config.rest_url
    }

    pub fn grpc_url(&self) -> &str {
        &self.chain_config.grpc_url
    }

    pub fn chain_config(&self) -> ChainConfig {
        self.chain_config.clone()
    }

    pub fn chain_config_builder(&self) -> ChainConfigBuilder {
        ChainConfigBuilder::default()
            .rpc_url(Some(self.rpc_url().to_string()))
            .rest_url(Some(self.api_url().to_string()))
            .grpc_url(Some(self.grpc_url().to_string()))
    }
}

impl Default for VeraTestContainer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VeraTestContainer {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report_compose_failure(&self.compose_file, &self.project_name);
        }
        println!("Stopping Vera test container...");
        stop_compose(&self.compose_file, &self.project_name);
    }
}
