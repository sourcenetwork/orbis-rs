//! Integration Test: x-archive — Full Service Key Architecture
//!
//! Four service keys on disk. Three real identities in Orbis. Zero private keys on hardware.
//!
//! ```text
//! Key               On Disk?   Real Identity     What It Does
//! ────────────────────────────────────────────────────────────────────
//! JACK_DID          NO         Jack (human)      Signs SourceHub policy txs
//! COMPARTMENT_DID   NO         x-archive         Owns documents, threshold-signs them
//! JACK_SVC          YES        (disposable)      Authenticates to Orbis for JACK_DID
//! DEFRA_SVC         YES        (disposable)      Authenticates to Orbis for COMPARTMENT_DID
//! APP_SVC           YES        (disposable)      Authenticates to DefraDB
//! ```
//!
//! Every file keyring key is a fuse. Blow it, replace it, move on.
//! The real identities survive in the ring.
//!
//! ## Data flow: writing a document
//!
//! ```text
//! x-archive app         DefraDB              SourceHub          Orbis Ring
//!      │                   │                     │                  │
//!      │ auth as APP_SVC   │                     │                  │
//!      ├──────────────────→│                     │                  │
//!      │                   │ "can APP_SVC write  │                  │
//!      │                   │  tweet?"            │                  │
//!      │                   ├────────────────────→│                  │
//!      │                   │        allowed      │                  │
//!      │                   │←────────────────────┤                  │
//!      │                   │                                        │
//!      │                   │ auth as DEFRA_SVC                      │
//!      │                   │ "sign doc as COMPARTMENT_DID"          │
//!      │                   ├───────────────────────────────────────→│
//!      │                   │                    threshold sign      │
//!      │                   │                    (2 of 3 nodes)      │
//!      │                   │←───────────────────────────────────────┤
//!      │                   │                                        │
//!      │  doc stored       │                                        │
//!      │  owner = COMPARTMENT_DID                                   │
//!      │  sig   = ring threshold sig                                │
//!      │←──────────────────┤                                        │
//! ```

use std::path::PathBuf;
use std::time::Duration;

use common::blockchain::events::BulletinEventSubscription;
use orbis_e2e::defradb::{self, DefraDbNode};
use orbis_e2e::orbis::{OrbisRing, SourceHubUrls};
use orbis_e2e::sourcehub::{self, SourceHubNode};
use orbis_e2e::{
    find_defra_binary, generate_identity_keys, generate_run_id, TestRunDir,
};

// ============================================================================
// Service identity — a disposable file-keyring key
// ============================================================================

/// A service account identity backed by a file keyring.
///
/// These are disposable. If compromised, revoke and regenerate.
/// The real identity (JACK_DID, COMPARTMENT_DID) lives in the Orbis ring.
struct ServiceIdentity {
    /// Human-readable label.
    label: String,
    /// Hex-encoded secp256k1 private key.
    private_key_hex: String,
    /// DID derived from the public key (did:key:...).
    did: String,
    /// Directory where the file keyring stores encrypted keys.
    _keyring_dir: PathBuf,
}

impl ServiceIdentity {
    /// Generate a new service identity with a file keyring.
    ///
    /// Creates a secp256k1 keypair, derives the DID, and stores the key
    /// in an encrypted file keyring under `base_dir/{label}/keys/`.
    fn new_file_keyring(label: &str, base_dir: &std::path::Path) -> Self {
        let keyring_dir = base_dir.join(label).join("keys");
        std::fs::create_dir_all(&keyring_dir)
            .unwrap_or_else(|e| panic!("create keyring dir for {}: {}", label, e));

        // Generate a deterministic key from the label (for test reproducibility)
        let private_key_hex = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            label.hash(&mut h);
            "service".hash(&mut h);
            let h1 = h.finish();
            let mut h2 = DefaultHasher::new();
            h1.hash(&mut h2);
            let h2 = h2.finish();
            format!("{:0>64x}", ((h1 as u128) << 64) | (h2 as u128))
        };

        // Derive DID from the key
        let did = orbis_e2e::sourcehub::source_hub_address(&private_key_hex)
            .unwrap_or_else(|e| panic!("derive address for {}: {}", label, e));

        // TODO: actually write the key into a file keyring here.
        // For now the private_key_hex is held in memory.

        Self {
            label: label.to_string(),
            private_key_hex,
            did,
            _keyring_dir: keyring_dir,
        }
    }
}

// ============================================================================
// Bulletin namespace for ring payloads (must match orbis-node constant)
// ============================================================================
const BULLETIN_RING_NAMESPACE: &str = "orbis";

// ============================================================================
// The test
// ============================================================================

/// Full service key architecture for the x-archive compartment.
///
/// This test is a living specification. It describes the target architecture
/// where Orbis is the root of trust for all identities and no private key
/// for a real identity ever touches disk.
///
/// **Status**: Infrastructure (SourceHub + Orbis DKG + DefraDB) works.
/// Orbis key generation, service key authorization, and signing proxy APIs
/// do not exist yet. See `todo!()` markers for each missing piece.
#[tokio::test]
#[ignore = "spec test: Orbis key gen + signing proxy APIs not yet implemented"]
async fn xarchive_full_service_key_architecture() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    // ================================================================
    // 1. Infrastructure: SourceHub
    // ================================================================
    // SourceHub is the shared trust layer. ACP policies and bulletin
    // posts live here. All identity assertions are verifiable on-chain.

    let run_id = generate_run_id();
    let run_dir = TestRunDir::new(&run_id).expect("create run dir");

    // Identity keys for the 3 Orbis operator nodes (funded in genesis)
    let orbis_operator_keys = generate_identity_keys(&run_id, 3);

    eprintln!("[xarchive] Starting SourceHub...");
    let sh_ports = sourcehub::allocate_source_hub_ports().expect("allocate sh ports");
    let sh_home = run_dir.component_dir("sourcehub").expect("sh dir");
    let sh_log_dir = sh_home.join("logs");
    std::fs::create_dir_all(&sh_log_dir).expect("sh log dir");

    let sourcehub = SourceHubNode::start(
        sh_home,
        sh_log_dir,
        &sh_ports,
        &orbis_operator_keys,
        Duration::from_secs(60),
    )
    .await
    .expect("sourcehub should start");

    // SourceHub is ready (waited for first block in start())
    eprintln!("[xarchive] SourceHub ready: {}", sourcehub.lcd_url);

    // ================================================================
    // 2. Orbis ring: root of trust
    // ================================================================
    // The ring collectively holds threshold keys. No single node has
    // any complete private key. T=2 of N=3 must cooperate to sign.

    eprintln!("[xarchive] Starting Orbis ring (3 nodes, threshold 2)...");
    let ring = OrbisRing::builder()
        .nodes(3)
        .threshold(2)
        .log_level("info")
        .base_dir(run_dir.path())
        .identity_keys(orbis_operator_keys.clone())
        .sourcehub_urls(SourceHubUrls::from(&sourcehub))
        .build()
        .await
        .expect("ring should start");

    ring.wait_ready(Duration::from_secs(60))
        .await
        .expect("all nodes should be healthy");

    let chain_config = sourcehub.chain_config();

    // Query node info for DKG setup
    let mut node_infos = Vec::with_capacity(ring.node_count());
    for i in 0..ring.node_count() {
        let info = cli_tool::query_node_info(ring.node(i).grpc_addr())
            .await
            .unwrap_or_else(|e| panic!("query node{} info: {}", i, e));
        node_infos.push(info);
    }

    // Register ring bulletin namespace + collaborators
    cli_tool::register_bulletin_namespace(
        BULLETIN_RING_NAMESPACE.to_string(),
        chain_config.clone(),
    )
    .await
    .expect("register ring namespace");

    for info in &node_infos {
        cli_tool::add_bulletin_collaborator(
            BULLETIN_RING_NAMESPACE.to_string(),
            info.public_address.clone(),
            chain_config.clone(),
        )
        .await
        .expect("add collaborator");
    }

    // Run DKG
    let event_subscription = BulletinEventSubscription::connect(&sourcehub.comet_rpc_url)
        .await
        .expect("event subscription");

    let peer_ids: Vec<String> = node_infos.iter().map(|n| n.p2p_address.clone()).collect();

    eprintln!("[xarchive] Running DKG...");
    let dkg_result = cli_tool::do_dkg(ring.node(0).grpc_addr(), ring.threshold(), peer_ids)
        .await
        .expect("DKG should succeed");

    let post_event = event_subscription
        .wait_for_artifact(&dkg_result.session_id, Duration::from_secs(120))
        .await
        .expect("DKG completion event");

    let post_payload = cli_tool::read_bulletin_post(
        BULLETIN_RING_NAMESPACE.to_string(),
        post_event.post_id.clone(),
        chain_config.clone(),
    )
    .await
    .expect("read ring post");

    let ring_payload: bulletin::r#trait::RingPayload =
        serde_json::from_slice(&post_payload).expect("parse RingPayload");
    let ring_pk_hex = ring_payload.ring_pk;
    let ring_id = post_event.post_id;

    eprintln!(
        "[xarchive] Ring ready. PK: {}..., ID: {}...",
        &ring_pk_hex[..32.min(ring_pk_hex.len())],
        &ring_id[..16.min(ring_id.len())],
    );

    // ================================================================
    // 3. Generate JACK_DID via Orbis (system identity)
    // ================================================================
    // Jack's real identity. The private key is threshold-held by the ring.
    // No single machine ever has it. Orbis derives it from the ring master
    // key using key derivation: derived_pk = H("jack") * ring_pk
    //
    // NEEDS: Orbis gRPC API — GenerateKey(ring_id, label) -> DID
    //   - Derives public key: crypto::derive_public_key(ring_pk, "jack")
    //   - Returns DID(derived_pk)
    //   - Ring can sign for this DID using the derivation path

    let _jack_did: String = todo!(
        "NEEDS: orbis GenerateKey gRPC API\n\
         Call: orbis.generate_key(ring_id, \"jack\")\n\
         Impl: crypto::derive_public_key(ring_pk, b\"jack\") -> derived_pk\n\
         Return: DID derived from derived_pk\n\
         The ring can threshold-sign for this DID using derivation=\"jack\""
    );

    // ================================================================
    // 4. Create JACK_SVC (service account, file keyring)
    // ================================================================
    // Disposable key stored on Jack's laptop. If the laptop is stolen,
    // revoke this key and issue a new one. JACK_DID is unaffected.

    let jack_svc = ServiceIdentity::new_file_keyring("jack-svc", run_dir.path());
    eprintln!(
        "[xarchive] jack_svc created: {} ({})",
        jack_svc.did, jack_svc.label
    );

    // Register jack_svc as authorized to act for jack_did in Orbis.
    // In production this would be a bootstrap ceremony (biometric-gated).
    //
    // NEEDS: Orbis gRPC API — AuthorizeServiceKey(ring_id, real_did, service_did)
    //   - Stores mapping: (ring_id, jack_did) -> [jack_svc.did]
    //   - Future calls from jack_svc.did are allowed to request
    //     threshold signatures as jack_did

    // orbis.authorize_service_key(&ring_id, &jack_did, &jack_svc.did).await;
    let _: () = todo!(
        "NEEDS: orbis AuthorizeServiceKey gRPC API\n\
         Call: orbis.authorize_service_key(ring_id, jack_did, jack_svc.did)\n\
         Stores: (ring_id, jack_did) permits [jack_svc.did]\n\
         Storage: SourceHub bulletin post or new on-chain module"
    );

    // ================================================================
    // 5. Fund JACK_DID on SourceHub
    // ================================================================
    // JACK_DID needs uopen to submit policy txs.
    // In test: faucet transfer. In prod: genesis allocation.

    // sourcehub.fund_from_faucet(&jack_did).await;
    let _: () = todo!(
        "NEEDS: Fund jack_did on SourceHub\n\
         This requires the address derived from jack_did's public key.\n\
         The public key comes from Orbis (it's the derived key).\n\
         cli_tool::fund(jack_did_address, chain_config) should work\n\
         once we have the address."
    );

    // ================================================================
    // 6. Generate COMPARTMENT_DID via Orbis (x-archive identity)
    // ================================================================
    // The compartment's identity. Owns all documents in x-archive.
    // Threshold-held by the ring, same as JACK_DID.
    //
    // NEEDS: Same GenerateKey API as step 3

    let _compartment_did: String = todo!(
        "NEEDS: orbis GenerateKey gRPC API (same as step 3)\n\
         Call: orbis.generate_key(ring_id, \"x-archive\")\n\
         Impl: crypto::derive_public_key(ring_pk, b\"x-archive\") -> derived_pk\n\
         Return: DID derived from derived_pk"
    );

    // ================================================================
    // 7. Create DEFRA_SVC + APP_SVC (service accounts, file keyring)
    // ================================================================

    let defra_svc = ServiceIdentity::new_file_keyring("defra-svc", run_dir.path());
    eprintln!(
        "[xarchive] defra_svc created: {} ({})",
        defra_svc.did, defra_svc.label
    );

    // Register defra_svc as authorized to act for compartment_did
    //
    // NEEDS: Same AuthorizeServiceKey API as step 4

    // orbis.authorize_service_key(&ring_id, &compartment_did, &defra_svc.did).await;
    let _: () = todo!(
        "NEEDS: orbis AuthorizeServiceKey gRPC API (same as step 4)\n\
         Call: orbis.authorize_service_key(ring_id, compartment_did, defra_svc.did)"
    );

    let app_svc = ServiceIdentity::new_file_keyring("x-archive-svc", run_dir.path());
    eprintln!(
        "[xarchive] app_svc created: {} ({})",
        app_svc.did, app_svc.label
    );
    // app_svc does NOT need Orbis authorization — it only talks to DefraDB.
    // DefraDB checks ACP on SourceHub to decide if app_svc can read/write.

    // ================================================================
    // 8. ACP policy: jack_svc → Orbis → signs as jack_did → SourceHub
    // ================================================================
    // Jack's laptop sends the policy definition to Orbis.
    // Orbis verifies jack_svc is authorized for jack_did.
    // Orbis threshold-signs the MsgCreatePolicy tx as jack_did.
    // Jack's laptop submits the signed tx to SourceHub.
    //
    // NEEDS: Orbis signing proxy gRPC API — SignTransaction(
    //          service_key_jwt,   // jack_svc authenticates
    //          target_did,        // sign as jack_did
    //          tx_bytes,          // the unsigned MsgCreatePolicy
    //        ) -> signed_tx_bytes
    //
    // Alternatively: higher-level API that builds + signs + submits in one call.

    // let policy_id = sourcehub.create_policy_via_orbis(
    //     &orbis, &ring_id,
    //     &jack_svc, &jack_did,
    //     "x-archive-access",
    //     resources: [tweet { reader, writer, read="owner|reader", write="owner|writer" }],
    // ).await;
    let _policy_id: String = todo!(
        "NEEDS: Orbis SignTransaction gRPC API (or higher-level proxy)\n\
         Flow:\n\
         1. Build unsigned MsgCreatePolicy tx\n\
         2. jack_svc sends to Orbis: sign as jack_did\n\
         3. Orbis verifies jack_svc authorization\n\
         4. Orbis threshold-signs (2-of-3 BLS)\n\
         5. Submit signed tx to SourceHub\n\
         6. Return policy_id\n\
         \n\
         Policy: x-archive-access\n\
           resource: tweet\n\
           relations: reader, writer\n\
           permissions: read = owner|reader, write = owner|writer"
    );

    // ================================================================
    // 9. ACP grants via Orbis
    // ================================================================
    // Grant compartment_did → writer + reader on tweet
    // Grant app_svc.did → writer + reader on tweet
    //
    // Same signing proxy pattern: jack_svc → Orbis → signs as jack_did
    //
    // NEEDS: Same SignTransaction API as step 8

    // sourcehub.grant_via_orbis(&orbis, &ring_id, &jack_svc, &jack_did,
    //     &policy_id, &compartment_did, &["writer", "reader"], "tweet").await;
    // sourcehub.grant_via_orbis(&orbis, &ring_id, &jack_svc, &jack_did,
    //     &policy_id, &app_svc.did, &["writer", "reader"], "tweet").await;
    let _: () = todo!(
        "NEEDS: Orbis SignTransaction gRPC API (same as step 8)\n\
         Two grant txs, both signed by Orbis as jack_did:\n\
         1. Grant compartment_did writer+reader on tweet\n\
         2. Grant app_svc.did writer+reader on tweet"
    );

    // ================================================================
    // 10. Start DefraDB with Orbis signer
    // ================================================================
    // DefraDB starts with:
    //   identity: defra_svc (file keyring, authenticates to Orbis)
    //   ACP: SourceHub (checks permissions on-chain)
    //   signer: Orbis (threshold-signs documents as compartment_did)
    //
    // When DefraDB stores a document:
    //   1. Checks ACP on SourceHub (can this actor write?)
    //   2. Sends doc bytes to Orbis for signing as compartment_did
    //   3. Stores doc with _owner=compartment_did, _signature=ring BLS sig
    //
    // NEEDS: DefraDB Signer::Orbis backend
    //   New signer in defradb.rs that delegates to Orbis gRPC:
    //     - endpoint: orbis grpc url
    //     - ring_id: which ring to use
    //     - compartment_did: sign as this identity
    //     - defra_svc credentials: authenticate to Orbis

    let defra_binary = find_defra_binary().expect("find defra binary");
    let defra_ports = defradb::allocate_defra_ports().expect("defra ports");
    let defra_dir = run_dir.component_dir("defra0").expect("defra dir");
    let defra_log_dir = defra_dir.join("logs");
    let defra_root = defra_dir.join("data");
    std::fs::create_dir_all(&defra_root).expect("defra data dir");

    let sh_config = sourcehub.defra_config();

    // Start DefraDB with defra_svc identity + SourceHub ACP.
    // TODO: Add Orbis signer configuration when DefraDB supports it.
    // For now, DefraDB starts with its own identity (defra_svc) and
    // signs locally. The Orbis signing proxy integration is future work.
    let _defra = DefraDbNode::start(
        defra_root,
        defra_log_dir,
        &defra_ports,
        &defra_binary,
        Some(&sh_config),
        Some(&defra_svc.private_key_hex),
        Duration::from_secs(30),
    )
    .await
    .expect("defra should start");

    eprintln!("[xarchive] DefraDB ready: {}", _defra.http_url);

    // NEEDS: DefraDB Signer::Orbis configuration
    //   defra start \
    //     --signer-type orbis \
    //     --signer-orbis-endpoint <orbis_grpc_url> \
    //     --signer-orbis-ring-id <ring_id> \
    //     --signer-orbis-did <compartment_did>

    // ================================================================
    // 11. Create Tweet schema with ACP policy
    // ================================================================
    // NEEDS: policy_id from step 8

    // let schema = format!(r#"
    //     type Tweet @policy(id: "{policy_id}", resource: "tweet") {{
    //         tweet_id: String @index(unique: true)
    //         text: String
    //     }}
    // "#);
    // http.post(format!("{}/api/v0/schema", defra.http_url))
    //     .header("Content-Type", "text/plain")
    //     .body(schema).send().await;
    let _: () = todo!(
        "NEEDS: policy_id from step 8\n\
         Then: POST /api/v0/schema with SDL referencing the policy"
    );

    // ================================================================
    // 12. Write a tweet as app_svc
    // ================================================================
    // app_svc authenticates to DefraDB.
    // DefraDB checks SourceHub ACP: can app_svc write tweet? → YES
    // DefraDB authenticates to Orbis as defra_svc.
    // DefraDB sends doc bytes to Orbis: sign as compartment_did.
    // Orbis threshold-signs (2-of-3 BLS).
    // Document stored with _owner=compartment_did, _signature=ring sig.
    //
    // NEEDS: All previous steps + DefraDB Orbis signer

    // let doc = http.post(format!("{}/api/v0/graphql", defra.http_url))
    //     .header("Authorization", bearer_token(&app_svc))
    //     .json(&json!({"query": r#"mutation {
    //         create_Tweet(input: {tweet_id: "1729", text: "first orbis-signed tweet"}) {
    //             _docID tweet_id text _owner _signature
    //         }
    //     }"#}))
    //     .send().await;
    let _: () = todo!(
        "NEEDS: All previous steps complete\n\
         Then: POST /api/v0/graphql with app_svc bearer token\n\
         mutation create_Tweet(input: {{tweet_id: \"1729\", text: \"first orbis-signed tweet\"}})\n\
         Verify: _owner = compartment_did, _signature verifies against ring_pk"
    );

    // ================================================================
    // 13. Read it back and verify
    // ================================================================
    // Assert: tweet_id = "1729"
    // Assert: text = "first orbis-signed tweet"
    // Assert: _owner = compartment_did (NOT app_svc.did, NOT defra_svc.did)
    // Assert: _signature verifies against ring collective pubkey
    //
    // This proves: the document was signed by the Orbis ring on behalf
    // of the compartment identity. No single machine held the signing key.

    // let result = http.post(format!("{}/api/v0/graphql", defra.http_url))
    //     .header("Authorization", bearer_token(&app_svc))
    //     .json(&json!({"query": "{ Tweet { tweet_id text _owner _signature } }"}))
    //     .send().await;
    //
    // assert_eq!(result[0]["tweet_id"], "1729");
    // assert_eq!(result[0]["_owner"], compartment_did);
    //
    // let sig_bytes = hex::decode(&result[0]["_signature"]).unwrap();
    // let sig = <SignImpl as ThresholdSigner>::Signature::from_bytes(&sig_bytes).unwrap();
    // let ring_pk = GroupAffine::from_bytes(&hex::decode(&ring_pk_hex).unwrap()).unwrap();
    // SignImpl::new().verify(&ring_pk, &doc_bytes, &sig).expect("ring sig should verify");
    let _: () = todo!(
        "NEEDS: All previous steps complete\n\
         Then: Query Tweet, verify _owner=compartment_did,\n\
         verify _signature against ring_pk_hex using SignImpl::verify"
    );

    // ================================================================
    // Done. Drop order: ring → defra → sourcehub → run_dir
    // ================================================================
    eprintln!("[xarchive] === Full service key architecture test complete ===");
}
