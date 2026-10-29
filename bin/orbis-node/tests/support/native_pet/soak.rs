use super::{
    dkg_scenario, endpoint, wait_polynomials, Delivery, Document, Node, Permissions, Polynomials,
    PreChecks, Reader,
};
use std::time::Duration;
use tokio::time::Instant;
use vera_client::{rings::RingPublicKeys, threshold_objects::ObjectKind};

use super::{super::native_workflow::NativeWorkflow, signing::Signing};

const ACTIVE_DURATION: Duration = Duration::from_secs(900);

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
    let signing = Signing::create(&workflow, &keys, "native-threshold-soak").await;
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
