use super::{
    dkg_scenario, endpoint, unix_now, wait_polynomials, Delivery, Document, Node, Permissions,
    Polynomials, PreChecks, Reader,
};
use authn::jwt_builder::create_authenticated_request;
use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
use proto::v0::sign::{sign_service_client::SignServiceClient, StartSignRequest};
use std::time::Duration;
use tokio::time::Instant;
use vera_client::{
    create_scoped_bearer_token,
    rings::RingPublicKeys,
    threshold_objects::{encode_threshold_object, KeyDerivation, ObjectKind, ThresholdObject},
    DelegationScope,
};

use super::super::native_workflow::NativeWorkflow;

const ACTIVE_DURATION: Duration = Duration::from_secs(900);

struct Signing {
    id: String,
    ring_key: crypto::GroupAffine,
    derived_key: crypto::GroupAffine,
}

impl Signing {
    async fn create(workflow: &NativeWorkflow, keys: &RingPublicKeys) -> Self {
        let derivation = KeyDerivation {
            ring_id: workflow.ring_id.clone(),
            derivation: "native-threshold-soak".into(),
            policy_id: workflow.policy.clone(),
            resource: "document".into(),
            permission: "read".into(),
        };
        let object = ThresholdObject::KeyDerivation(derivation.clone());
        let id = object.id().unwrap();
        let now = unix_now();
        let token = create_scoped_bearer_token(
            &workflow.controller,
            workflow.worker.did(),
            workflow.deployment,
            now,
            now + 300,
            DelegationScope::StoreThresholdObject,
        )
        .unwrap();
        super::submit(
            &workflow.client,
            &workflow.worker,
            &workflow.trusted,
            encode_threshold_object(&object, &token).unwrap(),
            "store soak key derivation",
            &workflow.cluster,
        )
        .await;
        let ring_key =
            crypto::GroupAffine::from_bytes(&hex::decode(&keys.public_key).unwrap()).unwrap();
        let metadata = crypto::SignImpl::encode_metadata(&workflow.policy, "document", "read");
        let derived_key = crypto::SignImpl::derive_public_key(
            &ring_key,
            derivation.derivation.as_bytes(),
            Some(&metadata),
        )
        .unwrap();
        Self {
            id,
            ring_key,
            derived_key,
        }
    }

    async fn request(
        &self,
        address: &str,
        reader: &Reader,
        cycle: u64,
    ) -> Result<proto::v0::sign::StartSignResponse, tonic::Status> {
        let message = cycle.to_le_bytes().to_vec();
        let token = reader.signer.create_sign_jwt(&self.id, &message).unwrap();
        let request = create_authenticated_request(
            StartSignRequest {
                message,
                derivation_id: self.id.clone(),
                valid_window: None,
            },
            &token,
        )
        .unwrap();
        Ok(SignServiceClient::connect(endpoint(address))
            .await
            .unwrap()
            .start_sign(request)
            .await?
            .into_inner())
    }

    async fn verify(&self, address: &str, reader: &Reader, cycle: u64) {
        let signed = self.request(address, reader, cycle).await.unwrap();
        let signature = <crypto::SignImpl as ThresholdSigner>::Signature::from_bytes(
            &hex::decode(signed.signature).unwrap(),
        )
        .unwrap();
        let message = cycle.to_le_bytes();
        crypto::SignImpl::new()
            .verify(&self.derived_key, &message, &signature)
            .unwrap();
        assert!(crypto::SignImpl::new()
            .verify(&self.ring_key, &message, &signature)
            .is_err());
    }

    async fn denied(&self, address: &str, reader: &Reader, cycle: u64) {
        assert_eq!(
            self.request(address, reader, cycle)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
}

async fn restart(workflow: &mut NativeWorkflow, keys: &RingPublicKeys, baseline: &[Polynomials]) {
    for node in &mut workflow.nodes {
        assert!(node.0.try_wait().unwrap().is_none());
        node.0.kill().unwrap();
        assert!(!node.0.wait().unwrap().success());
    }
    for index in 0..workflow.nodes.len() {
        let log = workflow
            .base
            .path()
            .join(format!("node-{index}/soak-restart.log"));
        workflow.nodes[index] = Node::restart(workflow.cluster.project_name(), index, &log);
        workflow.addresses[index] = workflow.nodes[index].endpoint();
    }
    for index in 0..workflow.nodes.len() {
        let log = workflow
            .base
            .path()
            .join(format!("node-{index}/soak-restart.log"));
        let recovered = workflow.nodes[index]
            .ready(&workflow.addresses[index], &log)
            .await;
        let initial = &workflow.infos[index];
        assert_eq!(recovered.node_key, initial.node_key);
        assert_eq!(recovered.peer_id, initial.peer_id);
        assert_eq!(recovered.p2p_address, initial.p2p_address);
        assert_eq!(recovered.public_address, initial.public_address);
        assert_eq!(recovered.managed_ring_count, 1);
    }
    assert_eq!(
        wait_polynomials(&workflow.addresses, &workflow.ring_id, keys, None)
            .await
            .as_slice(),
        baseline
    );
}

pub async fn run() {
    let (mut workflow, keys, baseline) = dkg_scenario(9081, false).await;
    let reader = Reader::new(vera_client::rings::ring_deployment_label(
        workflow.root.0,
        9081,
    ));
    let audit = cli_tool::reader_did_from_seed("native-soak-owner");
    let documents = [
        Document::new(
            &workflow.ring_id,
            &keys,
            &workflow.policy,
            &audit,
            b"stored soak document",
        ),
        Document::new(
            &workflow.ring_id,
            &keys,
            &workflow.policy,
            &audit,
            b"inline soak document",
        ),
    ];
    documents[0]
        .store(endpoint(&workflow.addresses[0]), &reader)
        .await;
    let signing = Signing::create(&workflow, &keys).await;
    let objects = [&documents[0].id, &documents[1].id, &signing.id, &audit];
    for id in objects {
        let registered = workflow
            .client
            .native_register_object(&workflow.worker, workflow.policy_bytes, id, "document")
            .await
            .unwrap();
        super::confirmed(
            &workflow.client,
            registered.transaction_hash,
            &workflow.trusted,
        )
        .await;
    }
    let ring = workflow
        .client
        .read_threshold_ring(&workflow.ring_id, 1, &workflow.trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    let started = Instant::now();
    let mut cycles = 0u64;
    let mut restarts = 0u32;
    while started.elapsed() < ACTIVE_DURATION {
        let address = &workflow.addresses[cycles as usize % workflow.addresses.len()];
        let checks = PreChecks::new(endpoint(address), &reader, Some(&audit));
        let permission = Permissions {
            client: &workflow.client,
            worker: &workflow.worker,
            trusted: &workflow.trusted,
            policy: workflow.policy_bytes,
            reader: &reader.signer.did_uri,
        };
        if cycles == 0 {
            checks
                .denied(
                    &documents[0],
                    Delivery::Stored,
                    tonic::Code::Unauthenticated,
                )
                .await;
            checks
                .denied(
                    &documents[1],
                    Delivery::Inline,
                    tonic::Code::Unauthenticated,
                )
                .await;
            signing.denied(address, &reader, cycles).await;
            for id in objects {
                permission.set(id, true).await;
            }
        }
        let target = cycles as usize % objects.len();
        permission.set(objects[target], false).await;
        match target {
            0 => {
                checks
                    .denied(
                        &documents[0],
                        Delivery::Stored,
                        tonic::Code::Unauthenticated,
                    )
                    .await
            }
            1 => {
                checks
                    .denied(
                        &documents[1],
                        Delivery::Inline,
                        tonic::Code::Unauthenticated,
                    )
                    .await
            }
            2 => signing.denied(address, &reader, cycles).await,
            _ => {
                checks
                    .denied(
                        &documents[0],
                        Delivery::Stored,
                        tonic::Code::Unauthenticated,
                    )
                    .await;
                checks
                    .denied(
                        &documents[1],
                        Delivery::Inline,
                        tonic::Code::Unauthenticated,
                    )
                    .await;
            }
        }
        permission.set(objects[target], true).await;
        tokio::join!(
            checks.decrypt(&documents[0], Delivery::Stored),
            checks.decrypt(&documents[1], Delivery::Inline),
            signing.verify(address, &reader, cycles),
        );
        assert_eq!(
            workflow
                .client
                .read_threshold_ring(&workflow.ring_id, 1, &workflow.trusted)
                .await
                .unwrap()
                .record
                .unwrap(),
            ring
        );
        cycles += 1;
        if restarts < 2 && started.elapsed() >= ACTIVE_DURATION / 3 * (restarts + 1) {
            restart(&mut workflow, &keys, &baseline).await;
            restarts += 1;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        cycles >= 20,
        "soak must complete repeated authorization cycles"
    );
    assert_eq!(restarts, 2, "soak must exercise both restart boundaries");
    let active_seconds = started.elapsed().as_secs();
    let permission = Permissions {
        client: &workflow.client,
        worker: &workflow.worker,
        trusted: &workflow.trusted,
        policy: workflow.policy_bytes,
        reader: &reader.signer.did_uri,
    };
    for id in &objects[..3] {
        permission.set(id, false).await;
    }
    restart(&mut workflow, &keys, &baseline).await;
    for address in &workflow.addresses {
        let checks = PreChecks::new(endpoint(address), &reader, Some(&audit));
        checks
            .denied(
                &documents[0],
                Delivery::Stored,
                tonic::Code::Unauthenticated,
            )
            .await;
        checks
            .denied(
                &documents[1],
                Delivery::Inline,
                tonic::Code::Unauthenticated,
            )
            .await;
        signing.denied(address, &reader, cycles).await;
    }
    let permission = Permissions {
        client: &workflow.client,
        worker: &workflow.worker,
        trusted: &workflow.trusted,
        policy: workflow.policy_bytes,
        reader: &reader.signer.did_uri,
    };
    for id in &objects[..3] {
        permission.set(id, true).await;
    }
    for address in &workflow.addresses {
        let checks = PreChecks::new(endpoint(address), &reader, Some(&audit));
        tokio::join!(
            checks.decrypt(&documents[0], Delivery::Stored),
            checks.decrypt(&documents[1], Delivery::Inline),
            signing.verify(address, &reader, cycles),
        );
    }
    let stored = workflow
        .client
        .read_threshold_object(ObjectKind::Document, &documents[0].id, 1, &workflow.trusted)
        .await
        .unwrap()
        .record
        .unwrap();
    assert_eq!(stored.object, documents[0].object);
    assert!(workflow
        .client
        .read_threshold_object(ObjectKind::Document, &documents[1].id, 1, &workflow.trusted)
        .await
        .unwrap()
        .record
        .is_none());
    for node in &mut workflow.nodes {
        node.stop().await;
    }
    eprintln!("native_threshold_soak={{\"cycles\":{cycles},\"active_seconds\":{active_seconds},\"restarts\":3}}");
}
