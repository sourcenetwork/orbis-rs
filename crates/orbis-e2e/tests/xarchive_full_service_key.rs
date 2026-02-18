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
use orbis_e2e::defradb::{self, DefraDbNode, OrbisSignerConfig};
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
/// **Status**: Full stack — SourceHub + Orbis DKG + DefraDB with Orbis signer.
/// Orbis DerivePublicKey and Sign RPCs are implemented.
/// DefraDB delegates document signing to Orbis ring via gRPC.
#[tokio::test]
#[ignore = "spec test: requires sourcehubd, defra, and orbis-node on PATH"]
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

    let jack_derived = cli_tool::derive_public_key(
        ring.node(0).grpc_addr(),
        ring_id.clone(),
        b"jack".to_vec(),
    )
    .await
    .expect("derive jack public key");

    // DID is the hex-encoded BLS derived public key
    // In production this would be a proper did:key: with BLS multicodec prefix
    let jack_did = format!("did:bls:{}", &jack_derived.derived_public_key[..40]);
    eprintln!("[xarchive] JACK_DID: {}", jack_did);

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

    // AuthorizeServiceKey: In production, Orbis would track which service
    // keys can act for which DIDs. For now, the Sign RPC accepts any valid
    // JWT — authorization enforcement is future work (SourceHub ACP-based).
    eprintln!("[xarchive] (skipping AuthorizeServiceKey — not enforced yet)");

    // ================================================================
    // 5. Fund JACK_DID on SourceHub — SKIPPED
    // ================================================================
    // JACK_DID is a BLS identity. SourceHub addresses use secp256k1.
    // In the test, the pre-funded test account creates ACP policies directly.
    // In production, a Cosmos tx signing proxy would bridge BLS→secp256k1.
    eprintln!("[xarchive] (skipping JACK_DID funding — test account creates policies)");

    // ================================================================
    // 6. Generate COMPARTMENT_DID via Orbis (x-archive identity)
    // ================================================================
    // The compartment's identity. Owns all documents in x-archive.
    // Threshold-held by the ring, same as JACK_DID.

    let compartment_derived = cli_tool::derive_public_key(
        ring.node(0).grpc_addr(),
        ring_id.clone(),
        b"x-archive".to_vec(),
    )
    .await
    .expect("derive x-archive public key");

    let compartment_did = format!("did:bls:{}", &compartment_derived.derived_public_key[..40]);
    eprintln!("[xarchive] COMPARTMENT_DID: {}", compartment_did);

    // ================================================================
    // 7. Create DEFRA_SVC + APP_SVC (service accounts, file keyring)
    // ================================================================

    let defra_svc = ServiceIdentity::new_file_keyring("defra-svc", run_dir.path());
    eprintln!(
        "[xarchive] defra_svc created: {} ({})",
        defra_svc.did, defra_svc.label
    );

    // AuthorizeServiceKey for defra_svc → compartment_did (same as step 4)
    eprintln!("[xarchive] (skipping AuthorizeServiceKey for defra_svc)");

    let app_svc = ServiceIdentity::new_file_keyring("x-archive-svc", run_dir.path());
    eprintln!(
        "[xarchive] app_svc created: {} ({})",
        app_svc.did, app_svc.label
    );
    // app_svc does NOT need Orbis authorization — it only talks to DefraDB.
    // DefraDB checks ACP on SourceHub to decide if app_svc can read/write.

    // ================================================================
    // 8. ACP policy via test account
    // ================================================================
    // In production: jack_svc → Orbis → threshold-signs tx as jack_did → SourceHub
    // In test: pre-funded test account creates policy directly.
    // The signing proxy (BLS→Cosmos tx) is future work.

    eprintln!("[xarchive] Creating ACP policy...");
    let policy_id = cli_tool::add_policy_to_chain(chain_config.clone())
        .await
        .expect("create ACP policy");
    eprintln!("[xarchive] Policy created: {}", policy_id);

    // ================================================================
    // 9. ACP grants via test account
    // ================================================================
    // Grant compartment_did and app_svc writer+reader on "document" resource.
    // Uses test account directly (same signing proxy caveat as step 8).

    // Register a placeholder object for grants
    let placeholder_object = "xarchive-root";
    cli_tool::register_object_to_chain(
        policy_id.clone(),
        placeholder_object.to_string(),
        "document".to_string(),
        chain_config.clone(),
    )
    .await
    .expect("register object");

    // Grant compartment_did as reader
    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        placeholder_object.to_string(),
        "document".to_string(),
        "reader".to_string(),
        Some(compartment_did.clone()),
        chain_config.clone(),
    )
    .await
    .expect("grant compartment_did reader");

    // Grant app_svc as reader
    cli_tool::set_relationship_on_chain(
        policy_id.clone(),
        placeholder_object.to_string(),
        "document".to_string(),
        "reader".to_string(),
        Some(app_svc.did.clone()),
        chain_config.clone(),
    )
    .await
    .expect("grant app_svc reader");

    eprintln!("[xarchive] ACP grants applied");

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

    let defra_binary = find_defra_binary().expect("find defra binary");
    let defra_ports = defradb::allocate_defra_ports().expect("defra ports");
    let defra_dir = run_dir.component_dir("defra0").expect("defra dir");
    let defra_log_dir = defra_dir.join("logs");
    let defra_root = defra_dir.join("data");
    std::fs::create_dir_all(&defra_root).expect("defra data dir");

    let sh_config = sourcehub.defra_config();

    // Orbis signer: DefraDB delegates document signing to the ring.
    // When DefraDB needs to sign a document, it sends the bytes to Orbis
    // which threshold-signs as the derived key (compartment_did).
    let orbis_signer = OrbisSignerConfig {
        endpoint: ring.node(0).grpc_addr(),
        ring_id: ring_id.clone(),
        derivation: "x-archive".to_string(),
    };

    let defra = DefraDbNode::start(
        defra_root,
        defra_log_dir,
        &defra_ports,
        &defra_binary,
        Some(&sh_config),
        Some(&defra_svc.private_key_hex),
        Some(&orbis_signer),
        Duration::from_secs(30),
    )
    .await
    .expect("defra should start with Orbis signer");

    eprintln!("[xarchive] DefraDB ready: {}", defra.http_url);

    // ================================================================
    // 11. Create Tweet schema
    // ================================================================
    // A simple schema for testing. In production this would have an
    // @policy directive referencing our ACP policy_id.

    let http = reqwest::Client::new();
    let tweet_schema = "type Tweet { tweet_id: String  text: String }";

    let schema_resp = http
        .post(format!("{}/api/v0/schema", defra.http_url))
        .header("Content-Type", "text/plain")
        .body(tweet_schema)
        .send()
        .await
        .expect("schema add request");
    assert!(
        schema_resp.status().is_success(),
        "schema add failed: {}",
        schema_resp.text().await.unwrap_or_default()
    );
    eprintln!("[xarchive] Schema added: Tweet {{ tweet_id, text }}");

    // ================================================================
    // 12. Write a tweet (signed by Orbis ring as compartment_did)
    // ================================================================
    // DefraDB receives this mutation, checks ACP on SourceHub, then
    // sends the document bytes to Orbis for threshold signing.
    // The ring signs as the derived key for "x-archive" (= compartment_did).

    let create_mutation = r#"mutation {
        create_Tweet(input: {
            tweet_id: "1729",
            text: "first orbis-signed tweet from x-archive"
        }) {
            _docID
            tweet_id
            text
        }
    }"#;

    let create_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": create_mutation}))
        .send()
        .await
        .expect("create tweet request");
    assert!(
        create_resp.status().is_success(),
        "create tweet failed: {}",
        create_resp.text().await.unwrap_or_default()
    );
    let create_body: serde_json::Value =
        create_resp.json().await.expect("parse create response");
    eprintln!("[xarchive] Tweet created: {}", create_body);

    // ================================================================
    // 13. Query back and verify
    // ================================================================
    let query = r#"query { Tweet { _docID tweet_id text } }"#;
    let query_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": query}))
        .send()
        .await
        .expect("query request");
    assert!(
        query_resp.status().is_success(),
        "query failed: {}",
        query_resp.text().await.unwrap_or_default()
    );
    let query_body: serde_json::Value =
        query_resp.json().await.expect("parse query response");

    let tweets = query_body
        .pointer("/data/Tweet")
        .and_then(|v| v.as_array())
        .expect("Tweet array in query response");
    assert_eq!(tweets.len(), 1, "should have 1 Tweet document");
    assert_eq!(
        tweets[0]["text"].as_str().unwrap_or(""),
        "first orbis-signed tweet from x-archive"
    );
    eprintln!(
        "[xarchive] Tweet verified: {} (text: {})",
        tweets[0]["_docID"].as_str().unwrap_or("?"),
        tweets[0]["text"].as_str().unwrap_or("?"),
    );

    // ================================================================
    // 14. Write more tweets (batch content pattern)
    // ================================================================
    // A compartment accumulates documents over time. Each write goes
    // through the same ACP-check → Orbis-sign → store pipeline.

    let tweets_data = vec![
        ("1730", "the Hardy-Ramanujan number is 1729"),
        ("1731", "orbis threshold signing: no single point of failure"),
        ("1732", "x-archive: my personal tweet vault"),
    ];

    for (id, text) in &tweets_data {
        let mutation = format!(
            r#"mutation {{ create_Tweet(input: {{ tweet_id: "{}", text: "{}" }}) {{ _docID }} }}"#,
            id, text
        );
        let resp = http
            .post(format!("{}/api/v0/graphql", defra.http_url))
            .json(&serde_json::json!({"query": mutation}))
            .send()
            .await
            .expect("batch create request");
        assert!(resp.status().is_success(), "batch create failed for {}", id);
    }
    eprintln!("[xarchive] Wrote {} more tweets (4 total)", tweets_data.len());

    // Query all tweets — should have 4
    let all_query = r#"query { Tweet { _docID tweet_id text } }"#;
    let all_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": all_query}))
        .send()
        .await
        .expect("query all tweets");
    let all_body: serde_json::Value = all_resp.json().await.expect("parse all tweets");
    let all_tweets = all_body
        .pointer("/data/Tweet")
        .and_then(|v| v.as_array())
        .expect("Tweet array");
    assert_eq!(all_tweets.len(), 4, "should have 4 tweets total");
    eprintln!("[xarchive] Verified: {} tweets in store", all_tweets.len());

    // ================================================================
    // 15. Second schema type: Bookmark (multi-type compartment)
    // ================================================================
    // A real compartment stores multiple document types. x-archive
    // has tweets, bookmarks, notes, etc. Each type gets its own schema
    // but all are owned by the same COMPARTMENT_DID.

    let bookmark_schema = "type Bookmark { url: String  title: String  notes: String }";
    let schema_resp = http
        .post(format!("{}/api/v0/schema", defra.http_url))
        .header("Content-Type", "text/plain")
        .body(bookmark_schema)
        .send()
        .await
        .expect("bookmark schema request");
    assert!(
        schema_resp.status().is_success(),
        "bookmark schema failed: {}",
        schema_resp.text().await.unwrap_or_default()
    );
    eprintln!("[xarchive] Schema added: Bookmark {{ url, title, notes }}");

    let bookmark_mutation = r#"mutation {
        create_Bookmark(input: {
            url: "https://en.wikipedia.org/wiki/1729_(number)",
            title: "1729 (number) - Wikipedia",
            notes: "Hardy-Ramanujan number, the smallest number expressible as the sum of two cubes in two different ways"
        }) {
            _docID
            url
            title
        }
    }"#;

    let bm_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": bookmark_mutation}))
        .send()
        .await
        .expect("create bookmark");
    assert!(
        bm_resp.status().is_success(),
        "bookmark create failed: {}",
        bm_resp.text().await.unwrap_or_default()
    );
    let bm_body: serde_json::Value = bm_resp.json().await.expect("parse bookmark response");
    eprintln!("[xarchive] Bookmark created: {}", bm_body);

    // Verify bookmark exists
    let bm_query = r#"query { Bookmark { _docID url title notes } }"#;
    let bm_query_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": bm_query}))
        .send()
        .await
        .expect("query bookmarks");
    let bm_query_body: serde_json::Value = bm_query_resp.json().await.expect("parse bookmarks");
    let bookmarks = bm_query_body
        .pointer("/data/Bookmark")
        .and_then(|v| v.as_array())
        .expect("Bookmark array");
    assert_eq!(bookmarks.len(), 1, "should have 1 bookmark");
    assert_eq!(
        bookmarks[0]["title"].as_str().unwrap_or(""),
        "1729 (number) - Wikipedia"
    );
    eprintln!("[xarchive] Bookmark verified: {}", bookmarks[0]["title"]);

    // ================================================================
    // 16. Update a tweet (mutation → re-sign pattern)
    // ================================================================
    // When a document is updated, DefraDB sends the new version to
    // Orbis for signing. The ring produces a fresh threshold signature.

    // Get the docID of the first tweet we created
    let first_doc_id = tweets[0]["_docID"]
        .as_str()
        .expect("first tweet should have _docID");

    let update_mutation = format!(
        r#"mutation {{ update_Tweet(docID: "{}", input: {{ text: "first orbis-signed tweet from x-archive (edited)" }}) {{ _docID text }} }}"#,
        first_doc_id
    );

    let update_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": update_mutation}))
        .send()
        .await
        .expect("update tweet request");
    assert!(
        update_resp.status().is_success(),
        "update tweet failed: {}",
        update_resp.text().await.unwrap_or_default()
    );
    let update_body: serde_json::Value = update_resp.json().await.expect("parse update response");
    eprintln!("[xarchive] Tweet updated: {}", update_body);

    // Verify the update persisted
    let verify_query = format!(
        r#"query {{ Tweet(docID: "{}") {{ _docID tweet_id text }} }}"#,
        first_doc_id
    );
    let verify_resp = http
        .post(format!("{}/api/v0/graphql", defra.http_url))
        .json(&serde_json::json!({"query": verify_query}))
        .send()
        .await
        .expect("verify update request");
    let verify_body: serde_json::Value = verify_resp.json().await.expect("parse verify response");
    let updated_text = verify_body
        .pointer("/data/Tweet/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        updated_text,
        "first orbis-signed tweet from x-archive (edited)"
    );
    eprintln!("[xarchive] Update verified: text = {:?}", updated_text);

    // ================================================================
    // 17. Multi-compartment key derivation
    // ================================================================
    // The same ring serves multiple compartments. Each gets a unique
    // derived key via a different derivation label. This shows that one
    // ring can back many identities without any per-compartment setup.

    let hiking_derived = cli_tool::derive_public_key(
        ring.node(0).grpc_addr(),
        ring_id.clone(),
        b"hiking".to_vec(),
    )
    .await
    .expect("derive hiking public key");

    let hiking_did = format!("did:bls:{}", &hiking_derived.derived_public_key[..40]);
    eprintln!("[xarchive] HIKING_DID: {}", hiking_did);

    // The three derived keys should all be different
    assert_ne!(
        jack_derived.derived_public_key, compartment_derived.derived_public_key,
        "jack and x-archive keys must differ"
    );
    assert_ne!(
        compartment_derived.derived_public_key, hiking_derived.derived_public_key,
        "x-archive and hiking keys must differ"
    );
    assert_ne!(
        jack_derived.derived_public_key, hiking_derived.derived_public_key,
        "jack and hiking keys must differ"
    );
    eprintln!("[xarchive] Verified: 3 unique derived keys from same ring");

    // ================================================================
    // Done. Drop order: ring → defra → sourcehub → run_dir
    // ================================================================
    eprintln!("[xarchive] === Full service key architecture test complete ===");
    eprintln!("[xarchive] Summary:");
    eprintln!("[xarchive]   Ring: {} (T=2, N=3)", &ring_id[..16.min(ring_id.len())]);
    eprintln!("[xarchive]   JACK_DID:        {}", jack_did);
    eprintln!("[xarchive]   COMPARTMENT_DID: {}", compartment_did);
    eprintln!("[xarchive]   HIKING_DID:      {}", hiking_did);
    eprintln!("[xarchive]   Tweets: 4 (1 updated)");
    eprintln!("[xarchive]   Bookmarks: 1");
}
