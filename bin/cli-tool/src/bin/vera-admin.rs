use anyhow::{bail, ensure, Context, Result};
use bulletin::native::{decode_node_signing_key, NativeConfig};
use clap::{Parser, Subcommand};
use hub_client::{
    nodes::{encode_node_request, sign_node_request, NodeCommand, NodeRequest, SignedNodeRequest},
    rings::encode_ring_command,
    rings::RingCommand,
    HubClient, NativeWorker, HUB_ADDRESS,
};
use hub_domain::NativeTx;
use local_storage::{
    r#trait::{LocalStorage, LocalStorageKeys},
    redb::RedbStorage,
};
use serde_json::json;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Native Vera node and ring administration with certified results")]
struct Args {
    /// Deployment trust file, also accepted by orbis-node --vera-config.
    #[arg(long)]
    vera_config: PathBuf,
    /// Private operator directory, separate from running node storage.
    #[arg(long)]
    directory: Option<PathBuf>,
    /// Password file for the encrypted worker store.
    #[arg(long, env = "ORBIS_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open or create a worker and print its delegation identity and pending request.
    Worker,
    /// Derive a new ring's identity from its create request and actor DID.
    RingId {
        request: PathBuf,
        #[arg(long)]
        actor: String,
    },
    /// Read a ring from certified current state.
    Ring {
        ring_id: String,
        #[arg(long, default_value_t = 1)]
        minimum_revision: u64,
    },
    /// Read a participant's route, controller and admission settings from certified state.
    Node {
        node_key: String,
        #[arg(long, default_value_t = 1)]
        minimum_revision: u64,
    },
    /// Sign an exact node command locally; write the returned authorization to a file.
    SignNode {
        command: PathBuf,
        #[arg(long)]
        node_key: String,
        #[arg(long)]
        sequence: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Journal a signed node/controller command without submitting it.
    PrepareNode { request: PathBuf },
    /// Journal an exact Create, Update or Cancel request without submitting it.
    PrepareRing {
        request: PathBuf,
        #[arg(long)]
        token_file: PathBuf,
    },
    /// Recover the pending result or submit its exact bytes; retain it until acknowledged.
    Submit,
    /// Release a completed request after recording its result.
    Acknowledge { submission_id: String },
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "{} exceeds {maximum} bytes",
        path.display()
    );
    Ok(bytes)
}

fn ring_command(path: &Path) -> Result<RingCommand> {
    Ok(serde_json::from_slice(&read_bounded(path, 64 * 1024)?)?)
}

fn open_worker(args: &Args, config: &NativeConfig) -> Result<NativeWorker> {
    let base = args
        .directory
        .as_ref()
        .context("--directory is required for worker operations")?
        .join(hex::encode(config.root));
    fs::create_dir_all(&base)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
    }
    let password = read_bounded(
        args.password_file
            .as_ref()
            .context("--password-file is required for worker operations")?,
        4096,
    )?;
    let password = std::str::from_utf8(&password)?.trim_end_matches(['\r', '\n']);
    ensure!(!password.is_empty(), "store password is empty");
    let storage = RedbStorage::new(
        password.to_owned(),
        base.join("keys.redb")
            .to_str()
            .context("store path is not UTF-8")?
            .to_owned(),
    )?;
    Ok(NativeWorker::open(
        &base.join("worker"),
        config.deployment_id,
        |name| {
            storage
                .get_encrypted(LocalStorageKeys::NativeWorkerKey(name.into()))
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "worker key is missing".to_owned())
        },
        |name, bytes| {
            storage.set_encrypted(
                LocalStorageKeys::NativeWorkerKey(name.into()),
                Zeroizing::new(bytes.to_vec()),
            )
        },
    )?)
}

fn print(value: serde_json::Value) -> Result<()> {
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn observe(timestamp: u64, config: &NativeConfig) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        timestamp <= now.saturating_add(15) && now.saturating_sub(timestamp) <= config.maximum_age,
        "evidence is stale or from the future"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config =
        NativeConfig::load(&args.vera_config).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if let Command::RingId { request, actor } = &args.command {
        let RingCommand::Create(ring) = ring_command(request)? else {
            bail!("ring-id requires a Create request")
        };
        return print(json!({"ring_id": ring.id(config.root, actor)?}));
    }
    if let Command::SignNode {
        command,
        node_key,
        sequence,
        expires_at,
        key_file,
    } = &args.command
    {
        let command: NodeCommand = serde_json::from_slice(&read_bounded(command, 48 * 1024)?)?;
        let bytes = read_bounded(key_file, 128)?;
        let encoded = if bytes.len() == 32 {
            bytes.as_slice()
        } else {
            bytes.trim_ascii()
        };
        let key = decode_node_signing_key(encoded)?;
        let signed = sign_node_request(
            NodeRequest {
                deployment_root: config.root,
                deployment_id: config.deployment_id,
                node_key: node_key.clone(),
                sequence: *sequence,
                expires_at: *expires_at,
                command,
            },
            &key,
        )?;
        return print(serde_json::to_value(signed)?);
    }
    tokio::time::timeout(config.timeout, run(&args, &config))
        .await
        .context("request deadline exceeded; any pending submission remains journaled")?
}

async fn run(args: &Args, config: &NativeConfig) -> Result<()> {
    let client = HubClient::new(&config.endpoint);
    let first = client.read_finalized_revision(1, &config.trusted).await?;
    ensure!(
        first.parent_hash.trim_start_matches("0x") == hex::encode(config.root),
        "consensus proof does not bind the configured deployment"
    );
    if let Command::Ring {
        ring_id,
        minimum_revision,
    } = &args.command
    {
        let read = client
            .read_threshold_ring(ring_id, *minimum_revision, &config.trusted)
            .await?;
        observe(read.timestamp, config)?;
        return print(
            json!({"revision": read.revision, "timestamp": read.timestamp, "ring": read.record}),
        );
    }
    if let Command::Node {
        node_key,
        minimum_revision,
    } = &args.command
    {
        let read = client
            .read_threshold_node(node_key, *minimum_revision, &config.trusted)
            .await?;
        observe(read.timestamp, config)?;
        return print(
            json!({"revision": read.revision, "timestamp": read.timestamp, "node": read.record}),
        );
    }
    let mut worker = open_worker(args, config)?;
    match &args.command {
        Command::Worker => print(
            json!({"worker_did": worker.did(), "next_sequence": worker.next_sequence(),
            "pending_id": worker.pending().map(NativeTx::decode_wire).transpose()?.map(|tx| tx.tx_id().0)}),
        ),
        Command::PrepareRing {
            request,
            token_file,
        } => {
            let command = ring_command(request)?;
            let token = read_bounded(token_file, 64 * 1024)?;
            let wire = worker.prepare(
                HUB_ADDRESS,
                encode_ring_command(&command, std::str::from_utf8(&token)?.trim())?,
            )?;
            print(json!({"submission_id": NativeTx::decode_wire(wire)?.tx_id().0}))
        }
        Command::PrepareNode { request } => {
            let signed: SignedNodeRequest =
                serde_json::from_slice(&read_bounded(request, 48 * 1024)?)?;
            ensure!(
                signed.request.deployment_root == config.root
                    && signed.request.deployment_id == config.deployment_id,
                "node request targets a different deployment"
            );
            let wire = worker.prepare(HUB_ADDRESS, encode_node_request(&signed)?)?;
            print(json!({"submission_id": NativeTx::decode_wire(wire)?.tx_id().0}))
        }
        Command::Submit | Command::Acknowledge { .. } => {
            let wire = worker.pending().context("no pending request")?;
            let id = NativeTx::decode_wire(wire)?.tx_id().0;
            if let Command::Acknowledge { submission_id } = &args.command {
                ensure!(
                    submission_id.parse::<alloy_primitives::B256>()? == id,
                    "submission ID does not match the pending request"
                );
                let proof = client
                    .read_receipt(id, &config.trusted)
                    .await?
                    .context("pending request has no certified receipt")?;
                let result = worker.acknowledge(&proof, &config.trusted)?;
                return print(json!({"acknowledged": id, "success": result.success()}));
            }
            let mut submitted = false;
            loop {
                if let Some(proof) = client.read_receipt(id, &config.trusted).await? {
                    let result = proof.verify(id, &config.trusted)?;
                    print(
                        json!({"submission_id": id, "revision": proof.revision.height, "success": result.success()}),
                    )?;
                    ensure!(result.success(), "command was rejected; acknowledge its receipt before preparing another request");
                    return Ok(());
                }
                if !submitted {
                    ensure!(
                        client.send_native_tx(wire).await? == id,
                        "submission identifier mismatch"
                    );
                    submitted = true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        Command::Ring { .. }
        | Command::RingId { .. }
        | Command::Node { .. }
        | Command::SignNode { .. } => unreachable!(),
    }
}
