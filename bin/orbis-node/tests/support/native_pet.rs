use super::{add_orbis_node4, confirmed, submit, Node};
use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use proto::info_service::{
    info_service_client::InfoServiceClient, GetPetRingStateRequest, GetRingStateRequest,
};
use std::time::Duration;
use tonic::transport::Endpoint;
use vera_client::{
    create_scoped_bearer_token,
    rings::{encode_ring_command, RingCommand, RingPublicKeys, RingRecord, RingState, RingUpdate},
    threshold_objects::ObjectKind,
    BlsSigner, DelegationScope, VeraClient,
};
use vera_domain::ConsensusPublicKey;

#[path = "native_pet/dkg.rs"]
mod dkg;
#[path = "pet_dkg_contract.rs"]
mod pet_dkg_contract;
#[path = "pre_scenario.rs"]
mod pre_scenario;
#[path = "refresh_scenario.rs"]
mod refresh_scenario;
#[path = "reshare_scenario.rs"]
mod reshare_scenario;
#[path = "sign_scenario.rs"]
mod sign_scenario;

#[path = "native_pet/document.rs"]
mod document;
use document::{Delivery, Document, PreChecks, Reader};

#[cfg(feature = "unsafe-testing")]
#[path = "native_pet/report_fault.rs"]
mod report_fault;

#[path = "native_pet/scheduled_refresh.rs"]
mod scheduled_refresh;

#[path = "native_pet/scheduled_store.rs"]
mod stored_bundle;

#[path = "native_pet/member_replacement.rs"]
mod member_replacement;

#[path = "native_pet/soak.rs"]
pub mod soak;

pub enum Scenario {
    Lifecycle,
    ScheduledRefresh,
    MemberReplacement,
    #[cfg(feature = "unsafe-testing")]
    ReportFault,
}

/// Run the shared paired-DKG scenario through the native adapter. The adapter
/// owns native-specific provisioning and gRPC triggering; the common runner
/// owns their ordering and the finalized/local-state assertions. Shared by
/// every `Scenario` variant below and by the standalone `native_dkg` test.
pub async fn dkg_scenario(
    deployment: u64,
    report_fault: bool,
) -> (
    super::native_workflow::NativeWorkflow,
    RingPublicKeys,
    Vec<Polynomials>,
) {
    let (workflow, keys, baseline) = dkg::run(deployment, report_fault).await;
    eprintln!("native PET phase=paired-dkg members=3 threshold=2");
    (workflow, keys, baseline)
}

/// Run the same standard-DKG lifecycle as the Cosmos integration suite,
/// including PRE, signing, refresh, and committee reshare. Only backend
/// provisioning and bulletin/ACP mechanisms differ.
pub async fn dkg_pre_and_sign_scenario(deployment: u64) -> (String, String) {
    dkg::run_pre(deployment).await
}

pub async fn run(scenario: Scenario) {
    let (deployment, report_fault) = match scenario {
        Scenario::Lifecycle => (9075, false),
        Scenario::ScheduledRefresh => (9077, false),
        Scenario::MemberReplacement => (9078, false),
        #[cfg(feature = "unsafe-testing")]
        Scenario::ReportFault => (9076, true),
    };
    let (workflow, keys, baseline) = dkg_scenario(deployment, report_fault).await;
    let super::native_workflow::NativeWorkflow {
        cluster,
        client,
        trusted,
        root,
        controller,
        actor,
        base,
        mut nodes,
        mut addresses,
        infos,
        worker,
        policy,
        policy_bytes,
        ring_id,
        headers: _headers,
        ..
    } = workflow;

    let reader = Reader::new(vera_client::rings::ring_deployment_label(
        root.0, deployment,
    ));
    let audit = cli_tool::reader_did_from_seed("native-pet-owner");
    let wrong_audit = cli_tool::reader_did_from_seed("native-pet-other-owner");
    let stored = Document::new(
        &ring_id,
        &keys,
        &policy,
        &audit,
        b"native stored PET document",
    );
    let inline = Document::new(
        &ring_id,
        &keys,
        &policy,
        &audit,
        b"native inline PET document",
    );
    stored.store(endpoint(&addresses[0]), &reader).await;
    // The stored path is certified, while the separate inline ciphertext has never been posted.
    let found = client
        .read_threshold_object(ObjectKind::Document, &stored.id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(found.object, stored.object);
    assert!(client
        .read_threshold_object(ObjectKind::Document, &inline.id, 1, &trusted)
        .await
        .unwrap()
        .record
        .is_none());
    for id in [&stored.id, &inline.id, &audit, &wrong_audit] {
        let registered = client
            .native_register_object(&worker, policy_bytes, id, "document")
            .await
            .unwrap();
        confirmed(&client, registered.transaction_hash, &trusted).await;
    }
    let permission = Permissions {
        client: &client,
        worker: &worker,
        trusted: &trusted,
        policy: policy_bytes,
        reader: &reader.signer.did_uri,
    };
    let documents = [(&stored, Delivery::Stored), (&inline, Delivery::Inline)];
    let checks = PreChecks::new(endpoint(&addresses[0]), &reader, Some(&audit));
    let missing_target = PreChecks::new(endpoint(&addresses[0]), &reader, None);
    let wrong_target = PreChecks::new(endpoint(&addresses[0]), &reader, Some(&wrong_audit));
    for (document, delivery) in documents {
        checks
            .denied(document, delivery, tonic::Code::Unauthenticated)
            .await;
        permission.set(&document.id, true).await;
        checks
            .denied(document, delivery, tonic::Code::Unauthenticated)
            .await;
    }
    permission.set(&audit, true).await;
    permission.set(&wrong_audit, true).await;
    for (document, delivery) in documents {
        checks.decrypt(document, delivery).await;
        missing_target
            .denied(document, delivery, tonic::Code::InvalidArgument)
            .await;
        wrong_target
            .denied(document, delivery, tonic::Code::Unauthenticated)
            .await;
    }
    if matches!(scenario, Scenario::ScheduledRefresh) {
        scheduled_refresh::ScheduledRefresh {
            cluster: &cluster,
            client: &client,
            trusted: &trusted,
            ring_id: &ring_id,
            keys: &keys,
            base: base.path(),
            addresses: &addresses,
            infos: &infos,
        }
        .run(&mut nodes, &checks, documents)
        .await;
        return;
    }
    #[cfg(feature = "unsafe-testing")]
    if matches!(scenario, Scenario::ReportFault) {
        report_fault::Reports {
            cluster: &cluster,
            client: &client,
            trusted: &trusted,
            addresses: &addresses,
            infos: &infos,
            ring_id: &ring_id,
            keys: &keys,
            base: base.path(),
            deployment_root: &root.0,
        }
        .run(&checks, &inline)
        .await;
        for node in &mut nodes {
            node.stop().await;
        }
        for index in 0..nodes.len() {
            let directory = base.path().join(format!("node-{index}"));
            let storage = stored_bundle::open(&directory);
            assert_eq!(
                storage.stored_kdf_params().unwrap(),
                local_storage::common::StoredKdfParams {
                    m_cost_kib: 262_144,
                    t_cost: 3,
                    p_cost: 1,
                    version: 0x13,
                },
                "native fault-report stores must retain production KDF parameters"
            );
        }
        return;
    }
    permission.set(&audit, false).await;
    for (document, delivery) in documents {
        checks
            .denied(document, delivery, tonic::Code::Unauthenticated)
            .await;
    }
    permission.set(&audit, true).await;
    for (document, delivery) in documents {
        checks.decrypt(document, delivery).await;
        permission.set(&document.id, false).await;
        checks
            .denied(document, delivery, tonic::Code::Unauthenticated)
            .await;
        permission.set(&document.id, true).await;
        checks.decrypt(document, delivery).await;
    }
    eprintln!("native PET phase=stored-inline-permissions-revocation-regrant");

    let now = unix_now();
    let token = create_scoped_bearer_token(
        &controller,
        worker.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::PolicyCommands,
    )
    .unwrap();
    let grant =
        vera_acp::Relationship::with_entity("ring", &ring_id, "operator", actor.parse().unwrap());
    let call = vera_modules::acp::abi::IAcp::bearerPolicyCmdCall {
        bearerToken: token,
        policyId: policy_bytes,
        cmd: serde_json::to_vec(&vera_modules::acp::types::PolicyCmd::SetRelationship(grant))
            .unwrap()
            .into(),
    }
    .abi_encode();
    let wire = worker
        .sign_native_tx(vera_client::ACP_ADDRESS, call.into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    confirmed(&client, id, &trusted).await;
    if matches!(scenario, Scenario::MemberReplacement) {
        member_replacement::MemberReplacement {
            cluster: &cluster,
            client: &client,
            trusted: &trusted,
            deployment,
            deployment_root: &root.0,
            controller: &controller,
            worker: &worker,
            policy: &policy,
            ring_id: &ring_id,
            keys: &keys,
            base: base.path(),
            addresses: &addresses,
            infos: &infos,
        }
        .run(&mut nodes, &reader, &audit, documents, &baseline)
        .await;
        return;
    }
    let previous = client
        .read_threshold_ring(&ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    let mut target: Vec<_> = infos[..2]
        .iter()
        .map(|info| info.node_key.clone())
        .collect();
    target.sort();
    let now = unix_now();
    let token = create_scoped_bearer_token(
        &controller,
        worker.did(),
        deployment,
        now,
        now + 300,
        DelegationScope::ManageRings,
    )
    .unwrap();
    submit(
        &client,
        &worker,
        &trusted,
        encode_ring_command(
            &RingCommand::Update {
                ring_id: ring_id.clone(),
                expected_sequence: previous.sequence,
                update: RingUpdate::StartReshare {
                    peer_node_keys: Some(target.clone()),
                    threshold: Some(2),
                },
            },
            &token,
        )
        .unwrap(),
        "start PET reshare",
        &cluster,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            let Some(current) = read_ring(&client, &trusted, &ring_id).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            assert!(current.config.requires_pet);
            assert_eq!(current.state, RingState::Active { keys: keys.clone() });
            let settings = current.current_settings();
            if settings.peer_node_keys == target && settings.pending_reshare.is_none() {
                assert_eq!(settings.threshold, 2);
                assert_eq!(current.sequence, previous.sequence + 2);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("native paired reshare must finalize");
    let reshared = wait_polynomials(&addresses[..2], &ring_id, &keys, Some(&baseline[..2])).await;
    nodes[2].stop().await;
    let surviving = PreChecks::new(endpoint(&addresses[1]), &reader, Some(&audit));
    for (document, delivery) in documents {
        surviving.decrypt(document, delivery).await;
    }
    eprintln!("native PET phase=reshared-pre members=2 threshold=2 both-polynomials-changed=true");

    for node in &mut nodes[..2] {
        assert!(node.0.try_wait().unwrap().is_none());
        node.0.kill().unwrap();
        assert!(!node.0.wait().unwrap().success());
    }
    for index in 0..2 {
        let log = base.path().join(format!("node-{index}/pet-restart.log"));
        nodes[index] = Node::restart(cluster.project_name(), index, &log);
        addresses[index] = nodes[index].endpoint();
        let recovered = nodes[index].ready(&addresses[index], &log).await;
        assert_eq!(recovered.node_key, infos[index].node_key);
        assert_eq!(recovered.peer_id, infos[index].peer_id);
        assert_eq!(recovered.p2p_address, infos[index].p2p_address);
        assert_eq!(recovered.public_address, infos[index].public_address);
        assert_eq!(recovered.managed_ring_count, 1);
    }
    assert_eq!(
        wait_polynomials(&addresses[..2], &ring_id, &keys, None).await,
        reshared
    );
    let restored = client
        .read_threshold_ring(&ring_id, 1, &trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(restored.state, RingState::Active { keys });
    assert_eq!(restored.current_settings().peer_node_keys, target);
    let surviving = surviving.reconnect(endpoint(&addresses[1]));
    for (document, delivery) in documents {
        surviving.decrypt(document, delivery).await;
    }
    eprintln!("native PET phase=restart-pre preserved-main-and-pet-shares=true");
    for node in &mut nodes[..2] {
        node.stop().await;
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn endpoint(addr: &str) -> Endpoint {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .timeout(Duration::from_secs(30))
}

async fn read_ring(
    client: &VeraClient,
    trusted: &ConsensusPublicKey,
    id: &str,
) -> Option<RingRecord> {
    match client.read_threshold_ring(id, 1, trusted).await {
        Ok(response) => Some(response.record.expect("created ring must remain present")),
        Err(error) if error.is_throttled() => None,
        Err(error) => panic!("certified PET ring read failed: {error}"),
    }
}

struct Permissions<'a> {
    client: &'a VeraClient,
    worker: &'a BlsSigner,
    trusted: &'a ConsensusPublicKey,
    policy: B256,
    reader: &'a str,
}

impl Permissions<'_> {
    async fn set(&self, object: &str, grant: bool) {
        let outcome = if grant {
            self.client
                .native_set_relationship(
                    self.worker,
                    self.policy,
                    "document",
                    object,
                    "reader",
                    self.reader,
                )
                .await
        } else {
            self.client
                .native_delete_relationship(
                    self.worker,
                    self.policy,
                    "document",
                    object,
                    "reader",
                    self.reader,
                )
                .await
        }
        .unwrap();
        confirmed(self.client, outcome.transaction_hash, self.trusted).await;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Polynomials {
    main: String,
    pet: String,
}

async fn wait_polynomials(
    addresses: &[String],
    ring_id: &str,
    keys: &RingPublicKeys,
    previous: Option<&[Polynomials]>,
) -> Vec<Polynomials> {
    assert!(!addresses.is_empty());
    if let Some(previous) = previous {
        assert_eq!(previous.len(), addresses.len());
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let mut states = Vec::new();
            for addr in addresses {
                let mut client = InfoServiceClient::connect(endpoint(addr)).await.unwrap();
                let main = client
                    .get_ring_state(GetRingStateRequest {
                        ring_pk_hex: keys.public_key.clone(),
                    })
                    .await;
                let pet = client
                    .get_pet_ring_state(GetPetRingStateRequest {
                        ring_id: ring_id.into(),
                    })
                    .await;
                match (main, pet) {
                    (Ok(main), Ok(pet)) => states.push(Polynomials {
                        main: main.into_inner().public_polynomial,
                        pet: pet.into_inner().public_polynomial,
                    }),
                    _ => break,
                }
            }
            if states.len() == addresses.len()
                && !states[0].main.is_empty()
                && !states[0].pet.is_empty()
                && states.iter().all(|state| state == &states[0])
                && previous.is_none_or(|old| {
                    states
                        .iter()
                        .zip(old)
                        .all(|(now, old)| now.main != old.main && now.pet != old.pet)
                })
            {
                return states;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("all members must hold the same main and PET polynomial generation")
}
