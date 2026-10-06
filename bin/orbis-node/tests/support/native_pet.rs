use super::{confirmed, submit, Node};
use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use proto::{
    info_service::{
        info_service_client::InfoServiceClient, GetPetRingStateRequest, GetRingStateRequest,
    },
    v0::dkg::{dkg_service_client::DkgServiceClient, StartDkgRequest},
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

#[path = "native_pet/document.rs"]
mod document;
use document::{Delivery, Document, PreChecks, Reader};

#[cfg(feature = "unsafe-testing")]
#[path = "native_pet/report_fault.rs"]
mod report_fault;

pub enum Scenario {
    Lifecycle,
    #[cfg(feature = "unsafe-testing")]
    ReportFault,
}

pub async fn run(scenario: Scenario) {
    let (deployment, report_fault) = match scenario {
        Scenario::Lifecycle => (9075, false),
        #[cfg(feature = "unsafe-testing")]
        Scenario::ReportFault => (9076, true),
    };
    let super::native_workflow::NativeWorkflow {
        cluster,
        client,
        trusted,
        root: _root,
        controller,
        controller_key,
        actor,
        base,
        mut nodes,
        addresses,
        infos,
        worker,
        policy,
        policy_bytes,
        ring_id,
        headers: _headers,
        ..
    } = super::native_workflow::NativeWorkflow::start(deployment, true, report_fault).await;
    let response = DkgServiceClient::connect(endpoint(&addresses[0]))
        .await
        .unwrap()
        .start_dkg(StartDkgRequest {
            ring_id: ring_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!response.session_id.is_empty());
    let record = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let Some(record) = read_ring(&client, &trusted, &ring_id).await else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            match record.state {
                RingState::Active { .. } => break record,
                RingState::Pending { .. } => (),
                state => panic!("paired DKG terminated: {state:?}"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("paired DKG must finalize within the native deadline");
    assert!(record.config.requires_pet);
    let RingState::Active { keys } = record.state else {
        unreachable!()
    };
    assert!(!keys.public_key.is_empty());
    assert!(keys
        .pet_public_key
        .as_ref()
        .is_some_and(|key| !key.is_empty()));
    assert_ne!(Some(&keys.public_key), keys.pet_public_key.as_ref());
    let baseline = wait_polynomials(&addresses, &ring_id, &keys, None).await;
    eprintln!("native PET phase=paired-dkg members=3 threshold=2");

    let reader = Reader::new();
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
            deployment_root: &_root.0,
        }
        .run(&checks, &inline)
        .await;
        for node in &mut nodes {
            node.stop().await;
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
        let directory = base.path().join(format!("node-{index}"));
        let log = directory.join("pet-restart.log");
        let bind = infos[index].p2p_address.split_once('@').unwrap().1;
        nodes[index] =
            Node::start_bound(&directory, &addresses[index], &controller_key, &log, bind);
        let recovered = nodes[index].ready(&addresses[index], &log).await;
        assert_eq!(recovered.node_key, infos[index].node_key);
        assert_eq!(recovered.p2p_address, infos[index].p2p_address);
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
struct Polynomials {
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
