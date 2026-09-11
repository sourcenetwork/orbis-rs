use anyhow::{ensure, Context, Result};
use crypto::lakey::WorkerRequest;
use serde::Deserialize;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

static CONCURRENCY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Deserialize)]
struct Namespace {
    chain: String,
    ring: String,
    epoch: u64,
    node: u32,
}

/// Configuration paths are operator-controlled; requests never choose executables or paths.
pub async fn invoke(request: &WorkerRequest, expected_index: u32) -> Result<Vec<u8>> {
    request.identity.encode()?;
    ensure!(request.session != [0; 32], "missing LaKey session");
    let _permit = CONCURRENCY.try_acquire().context("LaKey worker busy")?;
    let configured =
        std::env::var("LAKEY_NODE_CONFIGS").context("LaKey node configurations unavailable")?;
    ensure!(
        configured.len() <= 65536,
        "LaKey configuration list too large"
    );
    let paths: Vec<PathBuf> = serde_json::from_str(&configured)?;
    ensure!(
        !paths.is_empty() && paths.len() <= 32,
        "invalid LaKey configuration count"
    );
    let mut selected = None;
    for path in paths {
        let bytes = tokio::fs::read(&path).await?;
        ensure!(bytes.len() <= 65536, "LaKey configuration too large");
        let config: Namespace = serde_json::from_slice(&bytes)?;
        if config.chain == request.identity.chain
            && config.ring == request.identity.ring
            && config.epoch == request.identity.epoch
        {
            ensure!(
                selected.is_none(),
                "duplicate LaKey namespace configuration"
            );
            ensure!(
                config.node.checked_add(1) == Some(expected_index),
                "LaKey node index does not match ring membership"
            );
            selected = Some(path);
        }
    }
    let config = selected.context("LaKey epoch unavailable on this node")?;
    let binary = std::env::var("LAKEY_WORKER").context("LaKey executable unavailable")?;
    let mut child = tokio::process::Command::new(binary)
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().context("LaKey input unavailable")?;
    let output = child.stdout.take().context("LaKey output unavailable")?;
    let work = async {
        input.write_all(&serde_json::to_vec(request)?).await?;
        input.write_all(b"\n").await?;
        drop(input);
        let mut bytes = Vec::new();
        BufReader::new(output.take(4097))
            .read_until(b'\n', &mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 4096 && bytes.last() == Some(&b'\n'),
            "LaKey output too large"
        );
        ensure!(child.wait().await?.success(), "LaKey MPC did not complete");
        Ok(bytes)
    };
    tokio::time::timeout(Duration::from_secs(120), work)
        .await
        .context("LaKey MPC timed out")?
}
