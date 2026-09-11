//! Private local MPC/PRE worker; authorization belongs to the invoking Orbis node.
#[cfg(feature = "decaf377")]
mod worker {
    use anyhow::{ensure, Context, Result};
    use crypto::r#trait::{PriShare, ThresholdDealer};
    use crypto::{
        lakey::{reencrypt, Operation, PublicShare, WorkerRequest},
        CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, ScalarField,
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::{
        io::{BufRead, BufReader, Read, Write},
        path::PathBuf,
        process::{Command, Stdio},
    };
    use zeroize::Zeroizing;

    pub static PHASE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    fn phase(value: u8) {
        PHASE.store(value, std::sync::atomic::Ordering::Relaxed);
    }

    const DRIVER: &str = include_str!("../../../../scripts/lakey/node.py");

    #[derive(Deserialize)]
    struct Config {
        chain: String,
        ring: String,
        epoch: u64,
        node: u32,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Output {
        montgomery_share: String,
    }
    pub fn run() -> Result<()> {
        phase(1);
        let config_path = PathBuf::from(
            std::env::args()
                .nth(1)
                .context("node configuration required")?,
        );
        let config: Config = serde_json::from_slice(&std::fs::read(&config_path)?)?;
        let mut input = Vec::new();
        BufReader::new(std::io::stdin().take(65537)).read_until(b'\n', &mut input)?;
        ensure!(
            input.len() <= 65536 && input.last() == Some(&b'\n'),
            "invalid request frame"
        );
        phase(2);
        let request: WorkerRequest = serde_json::from_slice(&input)?;
        ensure!(
            request.identity.chain == config.chain
                && request.identity.ring == config.ring
                && request.identity.epoch == config.epoch,
            "LaKey master namespace mismatch"
        );
        ensure!(
            config.node < 5 && request.session != [0; 32],
            "invalid LaKey node/session"
        );
        if let Operation::Pre {
            epk,
            reader,
            reader_proof,
        } = &request.operation
        {
            GroupAffine::from_bytes(epk)?;
            PreImpl::verify_reader_key(&GroupAffine::from_bytes(reader)?, reader_proof)?;
        }
        let mut binding = Sha256::new();
        binding.update(b"orbis.lakey.session.v1\0");
        binding.update(request.identity.encode()?);
        binding.update(request.session);
        // All parties must run the same operation, ciphertext, and recipient.
        match &request.operation {
            Operation::PublicKey => binding.update([0]),
            Operation::Pre { epk, reader, .. } => {
                binding.update([1]);
                binding.update(epk);
                binding.update(reader);
            }
        }
        let matrix = request.identity.matrix()?;
        let payload = serde_json::to_vec(
            &serde_json::json!({"matrix":matrix,"binding":hex::encode(binding.finalize())}),
        )?;
        phase(3);
        let mut child = Command::new("python3")
            .args(["-c", DRIVER])
            .arg(config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut input = child.stdin.take().context("MPC input unavailable")?;
        input.write_all(&payload)?;
        input.write_all(b"\n")?;
        drop(input);
        phase(4);
        let mut bytes = Zeroizing::new(Vec::new());
        BufReader::new(
            child
                .stdout
                .take()
                .context("MPC output unavailable")?
                .take(4097),
        )
        .read_until(b'\n', &mut bytes)?;
        if bytes.len() > 4096 || bytes.last() != Some(&b'\n') {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("MPC output too large");
        }
        ensure!(child.wait()?.success(), "local LaKey MPC failed");
        phase(5);
        let output: Output = serde_json::from_slice(&bytes)?;
        let text = Zeroizing::new(output.montgomery_share);
        let encoded = Zeroizing::new(hex::decode(text.as_str())?);
        let mut scalar = Zeroizing::new(<ScalarField as CryptoDeserialize>::from_bytes(&encoded)?);
        let mut two256 = [0; 33];
        two256[32] = 1;
        *scalar *= ScalarField::from_le_bytes_mod_order(&two256)
            .inverse()
            .context("invalid Montgomery factor")?;
        let share = PriShare {
            i: config.node + 1,
            v: *scalar,
        };
        phase(6);
        match request.operation {
            Operation::PublicKey => serde_json::to_writer(
                std::io::stdout(),
                &PublicShare {
                    index: share.i,
                    public_share: (GroupAffine::GENERATOR * share.v).to_bytes()?,
                },
            )?,
            Operation::Pre {
                epk,
                reader,
                reader_proof,
            } => serde_json::to_writer(
                std::io::stdout(),
                &reencrypt(
                    share,
                    &epk,
                    &GroupAffine::from_bytes(&reader)?,
                    &reader_proof,
                )?,
            )?,
        }
        writeln!(std::io::stdout())?;
        Ok(())
    }
}

fn main() {
    #[cfg(feature = "decaf377")]
    if worker::run().is_ok() {
        return;
    }
    #[cfg(feature = "decaf377")]
    eprintln!(
        "LaKey worker failed at phase {}; no result released",
        worker::PHASE.load(std::sync::atomic::Ordering::Relaxed)
    );
    #[cfg(not(feature = "decaf377"))]
    eprintln!("LaKey requires Decaf377");
    std::process::exit(1);
}
