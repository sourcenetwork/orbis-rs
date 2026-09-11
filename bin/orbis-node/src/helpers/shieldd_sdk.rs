use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::Status;
const MAX_RESPONSE: u64 = 1024 * 1024;
static CONCURRENCY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

pub(crate) async fn invoke(
    executable: &str,
    args: &[&str],
    input: &[u8],
) -> Result<Vec<u8>, Status> {
    let _permit = CONCURRENCY
        .try_acquire()
        .map_err(|_| Status::resource_exhausted("Shieldd verifier busy"))?;
    if input.len() > 65536 {
        return Err(Status::resource_exhausted(
            "Shieldd verifier input too large",
        ));
    }
    let mut child = tokio::process::Command::new(executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Status::unavailable("Shieldd verifier unavailable"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Status::internal("verifier stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Status::internal("verifier stdout unavailable"))?;
    let work = async {
        stdin
            .write_all(input)
            .await
            .map_err(|_| Status::unavailable("verifier input failed"))?;
        drop(stdin);
        let mut bytes = Vec::new();
        stdout
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Status::unavailable("verifier output failed"))?;
        if bytes.len() as u64 > MAX_RESPONSE {
            return Err(Status::resource_exhausted("verifier output too large"));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| Status::unavailable("verifier wait failed"))?;
        if !status.success() {
            return Err(Status::failed_precondition(
                "transaction verification or acceptance unavailable",
            ));
        }
        Ok(bytes)
    };
    tokio::time::timeout(Duration::from_secs(90), work)
        .await
        .map_err(|_| Status::deadline_exceeded("Shieldd verification timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_invocations_are_rejected_before_spawning() {
        let permit = CONCURRENCY.acquire().await.unwrap();
        let error = invoke("/nonexistent-verifier", &[], &[]).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        drop(permit);
        let error = invoke("/nonexistent-verifier", &[], &[]).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
    }
}
