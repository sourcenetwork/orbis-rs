//! Spins up a real, local, Docker-backed native Vera cluster and seeds a
//! single ring+policy covering both resources every example-integrations
//! app needs: `key`/`signer` (Sign) and `document`/`reader` (PRE/
//! StoreSecret) — one cluster serves passkey-sign, yubikey-sign, and
//! email-decrypt identically, not a passkey-sign-specific setup.
//!
//! Deliberately Docker-backed, not the in-process `harness` feature:
//! `harness`'s own doc comment says its authorization is always a
//! permissive `DummyAuthZ` ("not ACP policy enforcement"), which can't
//! demonstrate the grant/revoke/recovery story these example apps exist to
//! show.
//!
//! `cli-tool`'s `set-relationship-on-chain` can't be used for the grant step
//! after a passkey registers: its admin commands only talk to the Cosmos
//! backend (`common::blockchain::cosmos::*`), not native/Vera. So `grant`/
//! `revoke` are subcommands of this same binary instead — the ACP relation
//! shape is otherwise identical.

mod native_admin;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use native_admin::DEPLOYMENT;
use proto::v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest};
use std::time::Duration;
use test_support::node_readiness::wait_for_nodes_ready;
use test_support::{NodeInfo, VeraNetworkAdapter};
use vera_client::VeraClient;

/// The one ready-to-use Sign key derivation `up` creates on the seeded
/// ring, so there's something to grant/sign against immediately.
const DEFAULT_DERIVATION: &str = "example-integrations-dev-key";

/// The one ready-to-use PRE document `up` stores on the seeded ring, so
/// there's something to grant/decrypt against immediately.
const DEFAULT_PLAINTEXT: &str = "hello from orbis-dev-cluster";

const COMBINED_POLICY_YAML: &str = r#"
name: example-integrations-dev-policy
resources:
  - name: ring_policy
    relations:
      - name: creator
        types:
          - actor
    permissions:
      - name: create_ring
        expr: creator
  - name: ring
    relations:
      - name: operator
        types:
          - actor
    permissions:
      - name: update_ring
        expr: operator
  - name: key
    relations:
      - name: signer
        types:
          - actor
    permissions:
      - name: sign
        expr: signer
  - name: document
    relations:
      - name: reader
        types:
          - actor
    permissions:
      - name: read
        expr: reader
"#;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts a fresh local cluster, seeds the shared ring+policy, and
    /// blocks until Ctrl-C (tearing the cluster down on exit).
    Up {
        /// Number of orbis-node containers to start (1-4).
        #[arg(long, default_value_t = 3)]
        nodes: usize,
        /// DKG threshold for the seeded ring.
        #[arg(long, default_value_t = 2)]
        threshold: u32,
        /// WebAuthn relying-party id the nodes are configured with — must
        /// match whatever a passkey-based example app is passed as its own
        /// `--rp-id` (passkey-sign's own default, reused here, is
        /// `localhost`).
        #[arg(long, default_value = "localhost")]
        webauthn_rp_id: String,
        /// WebAuthn origin the nodes are configured with — must match a
        /// passkey-based example app's own `--origin` (passkey-sign's own
        /// default, reused here, is `http://localhost:8787`).
        #[arg(long, default_value = "http://localhost:8787")]
        webauthn_origin: String,
    },
    /// Registers `object_id` under `resource` in `policy_id` — required
    /// before `grant` can set a relation on it. `up` already does this for
    /// the Sign key derivation it creates; a PRE/StoreSecret `document`
    /// object needs it run once, after the document is stored (its object
    /// id comes back from that call, not from this tool).
    RegisterObject(ObjectArgs),
    /// Grants `relation` on `resource`/`object_id` to `subject_did`, against
    /// an already-running cluster started with `up`.
    Grant(RelationshipArgs),
    /// Revokes `relation` on `resource`/`object_id` from `subject_did`,
    /// against an already-running cluster started with `up`.
    Revoke(RelationshipArgs),
    /// Encrypts `plaintext` for the ring, stores it via StoreSecret, and
    /// registers the resulting object under the `document` resource —
    /// everything needed for a PRE decrypt example except the actual
    /// `grant` of `reader` to a specific DID (run that separately once you
    /// know which DID). `up` already does this once automatically; use
    /// this to store additional documents against an already-running
    /// cluster.
    StoreSecret(StoreSecretArgs),
}

#[derive(Parser)]
struct StoreSecretArgs {
    /// orbis-node gRPC endpoint (node0, printed by `up`).
    #[arg(long)]
    orbis_endpoint: String,
    /// Chain RPC URL printed by `up` — needed to register the resulting
    /// object, a separate step from StoreSecret's own gRPC call.
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    policy_id: String,
    #[arg(long)]
    ring_id: String,
    /// Finalized ring public key printed by `up`.
    #[arg(long)]
    ring_pk: String,
    /// Plaintext to encrypt and store.
    #[arg(long, default_value = "hello from orbis-dev-cluster")]
    plaintext: String,
}

#[derive(Parser)]
struct ObjectArgs {
    /// Chain RPC URL printed by `up` (e.g. http://127.0.0.1:PORT).
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    policy_id: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    object_id: String,
}

#[derive(Parser)]
struct RelationshipArgs {
    /// Chain RPC URL printed by `up` (e.g. http://127.0.0.1:PORT).
    #[arg(long)]
    rpc_url: String,
    #[arg(long)]
    policy_id: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    object_id: String,
    #[arg(long)]
    relation: String,
    #[arg(long)]
    subject_did: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Up {
            nodes,
            threshold,
            webauthn_rp_id,
            webauthn_origin,
        } => up(nodes, threshold, webauthn_rp_id, webauthn_origin).await,
        Command::RegisterObject(args) => {
            let client = VeraClient::new(args.rpc_url.clone());
            let keys = native_admin::derive_admin_keys(&client).await?;
            native_admin::register_object(
                &client,
                &keys,
                &args.policy_id,
                &args.resource,
                &args.object_id,
            )
            .await?;
            println!("Registered: {}/{}", args.resource, args.object_id);
            Ok(())
        }
        Command::Grant(args) => {
            let client = VeraClient::new(args.rpc_url.clone());
            let keys = native_admin::derive_admin_keys(&client).await?;
            native_admin::grant_relationship(
                &client,
                &keys,
                &args.policy_id,
                &args.resource,
                &args.object_id,
                &args.relation,
                &args.subject_did,
            )
            .await?;
            report_relationship_done("Granted", &args);
            Ok(())
        }
        Command::Revoke(args) => {
            let client = VeraClient::new(args.rpc_url.clone());
            let keys = native_admin::derive_admin_keys(&client).await?;
            native_admin::revoke_relationship(
                &client,
                &keys,
                &args.policy_id,
                &args.resource,
                &args.object_id,
                &args.relation,
                &args.subject_did,
            )
            .await?;
            report_relationship_done("Revoked", &args);
            Ok(())
        }
        Command::StoreSecret(args) => {
            let client = VeraClient::new(args.rpc_url.clone());
            let keys = native_admin::derive_admin_keys(&client).await?;
            let document_id = store_sample_document(
                &args.orbis_endpoint,
                &args.ring_id,
                &args.ring_pk,
                &args.policy_id,
                args.plaintext.as_bytes(),
            )
            .await?;
            native_admin::register_object(
                &client,
                &keys,
                &args.policy_id,
                "document",
                &document_id,
            )
            .await?;
            println!("Stored and registered document: {document_id}");
            println!(
                "Grant a reader:\n  cargo run -p orbis-dev-cluster -- grant --rpc-url {} \\
      --policy-id {} --resource document --object-id {document_id} \\
      --relation reader --subject-did <DID>",
                args.rpc_url, args.policy_id
            );
            Ok(())
        }
    }
}

/// Encrypts `plaintext` locally for the ring (`ring_pk`) and stores it via
/// StoreSecret, returning the resulting object id. StoreSecret's own
/// authentication is JWT-only — no passkey/WebAuthn CLI path exists for it
/// (by design; see `crates/authn/README.md`'s `endpoints` section) — but
/// that's irrelevant here: storing a document's *authentication method*
/// doesn't matter to what a PRE decrypt example demonstrates, only that
/// the resulting object is readable by whichever DID gets granted `reader`
/// on it afterward. Mirrors `bin/orbis-node/src/tests/e2e/pre_scenario.rs`'s
/// own `prepare`/`store_with_retry` helpers, built on the same
/// `cli_tool::{prepare_secret, store_prepared_secret}` functions.
async fn store_sample_document(
    orbis_endpoint: &str,
    ring_id: &str,
    ring_pk: &str,
    policy_id: &str,
    plaintext: &[u8],
) -> Result<String> {
    let prepared = cli_tool::prepare_secret(
        plaintext,
        ring_pk,
        None,
        policy_id.to_string(),
        "document".to_string(),
        "read".to_string(),
        None,
        None,
        None,
        None,
    )
    .map_err(|e| anyhow!("prepare document: {e}"))?;
    let stored = cli_tool::store_prepared_secret(
        orbis_endpoint.to_string(),
        &prepared,
        ring_id.to_string(),
        None,
        false,
        None,
    )
    .await
    .map_err(|e| anyhow!("store document: {e}"))?;
    Ok(stored.object_id)
}

fn report_relationship_done(verb: &str, args: &RelationshipArgs) {
    println!(
        "{verb}: {} on {}/{} for {}",
        args.relation, args.resource, args.object_id, args.subject_did
    );
}

async fn up(
    node_count: usize,
    threshold: u32,
    webauthn_rp_id: String,
    webauthn_origin: String,
) -> Result<()> {
    println!("Starting a local native Vera cluster ({node_count} nodes)...");
    // Opt-in pass-through `test_support::network::vera` forwards into every
    // node container — see `passkey_sign_scenario.rs`'s `WebAuthnNodeEnv` for
    // the same pattern. Must be set before `start_configured` reads it.
    std::env::set_var("ORBIS_WEBAUTHN_RP_ID", &webauthn_rp_id);
    std::env::set_var("ORBIS_WEBAUTHN_ORIGIN", &webauthn_origin);
    let network = VeraNetworkAdapter::start_configured(
        DEPLOYMENT,
        node_count,
        false,
        false,
        false,
        vera_harness::cluster::GenesisBuilder::devnet(),
    )
    .await;

    let endpoints = network.node_endpoints();
    let nodes: Vec<NodeInfo> = wait_for_nodes_ready(&endpoints).await;
    println!("All {} nodes are ready.", nodes.len());

    let rpc_url = network.cluster().node(0).rpc_url();
    let client = VeraClient::new(rpc_url.clone());
    let keys = native_admin::derive_admin_keys(&client).await?;

    println!("Creating the shared dev policy...");
    let policy_id =
        native_admin::create_policy(&client, &keys.worker, &keys.trusted, COMBINED_POLICY_YAML)
            .await?;

    println!("Authorizing nodes and creating the ring (threshold {threshold})...");
    let ring_id =
        native_admin::register_and_create_ring(&client, &keys, &policy_id, &nodes, threshold)
            .await?;

    println!("Triggering DKG...");
    let mut dkg_client = DkgServiceClient::connect(nodes[0].grpc_endpoint.clone())
        .await
        .map_err(|e| anyhow!("connect to node for DKG trigger: {e}"))?;
    dkg_client
        .start_dkg(StartDkgRequest {
            ring_id: ring_id.clone(),
        })
        .await
        .map_err(|e| anyhow!("start DKG: {e}"))?;

    println!("Waiting for DKG to finalize (this can take a little while)...");
    let ring_pk =
        native_admin::wait_for_ring_pk(&client, &ring_id, &keys.trusted, Duration::from_secs(240))
            .await?;

    // Sign's permission checks key on a named key-derivation object, not
    // the ring id itself — see `native_admin::register_key_derivation`'s
    // own doc comment. Create one ready to grant/sign against.
    println!("Registering a Sign key derivation...");
    let derivation_id = native_admin::register_key_derivation(
        &client,
        &keys,
        &ring_id,
        DEFAULT_DERIVATION,
        &policy_id,
        "key",
        "sign",
    )
    .await?;
    native_admin::register_object(&client, &keys, &policy_id, "key", &derivation_id).await?;

    // A ready-made object for the PRE decrypt example — same reasoning as
    // the key derivation above: something to grant/decrypt against
    // immediately, without a separate store-secret round trip first.
    println!("Storing a sample encrypted document for the PRE example...");
    let document_id = store_sample_document(
        &nodes[0].grpc_endpoint,
        &ring_id,
        &ring_pk,
        &policy_id,
        DEFAULT_PLAINTEXT.as_bytes(),
    )
    .await?;
    native_admin::register_object(&client, &keys, &policy_id, "document", &document_id).await?;

    print_summary(
        &nodes,
        &rpc_url,
        &policy_id,
        &ring_id,
        &ring_pk,
        &derivation_id,
        &document_id,
        &native_admin::chain_id(&keys),
    );

    println!("\nPress Ctrl-C to tear down the cluster.");
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow!("wait for Ctrl-C: {e}"))?;
    println!("Shutting down...");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_summary(
    nodes: &[NodeInfo],
    rpc_url: &str,
    policy_id: &str,
    ring_id: &str,
    ring_pk: &str,
    derivation_id: &str,
    document_id: &str,
    chain_id: &str,
) {
    println!("\n==================== Cluster ready ====================");
    println!("Node endpoints:");
    for (i, node) in nodes.iter().enumerate() {
        println!("  node{i}: {}", node.grpc_endpoint);
    }
    println!("Chain RPC:     {rpc_url}");
    println!("Policy id:     {policy_id}");
    println!("Ring id:       {ring_id}");
    println!("Ring pk:       {ring_pk}");
    println!("Derivation id: {derivation_id}  (Sign's own object id — grant against this, not the ring id)");
    println!(
        "Document id:   {document_id}  (a sample PRE document already stored and registered — \
         plaintext {DEFAULT_PLAINTEXT:?})"
    );
    println!(
        "Chain id:      {chain_id}  (PRE's reader-key proof-of-possession transcript binds this \
         exactly — it is *not* the bare deployment number {DEPLOYMENT}; Sign doesn't care, PRE does)"
    );
    println!();
    println!("Point an example app at this cluster, e.g.:");
    println!(
        "  cargo run -p passkey-sign -- --orbis-endpoint {} --chain-id {chain_id}",
        nodes[0].grpc_endpoint
    );
    println!();
    println!("After registering a passkey in the browser, grant its DID access:");
    println!(
        "  Sign:\n    cargo run -p orbis-dev-cluster -- grant --rpc-url {rpc_url} \\
      --policy-id {policy_id} --resource key --object-id {derivation_id} \\
      --relation signer --subject-did <PASSKEY_DID>"
    );
    println!(
        "  PRE decrypt (the sample document above):\n    cargo run -p orbis-dev-cluster -- grant --rpc-url {rpc_url} \\
      --policy-id {policy_id} --resource document --object-id {document_id} \\
      --relation reader --subject-did <PASSKEY_DID>"
    );
    println!();
    println!(
        "Store more documents with `orbis-dev-cluster store-secret` (see --help) — each \
         one needs its own `grant` afterward, same shape as above."
    );
    println!("=========================================================");
}
