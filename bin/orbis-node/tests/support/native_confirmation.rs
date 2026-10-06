use alloy_primitives::{Bytes, B256};
use std::time::Duration;
use vera_client::{BlsSigner, VeraClient};
use vera_domain::{ConsensusPublicKey, NativeTx, Tx};
use vera_harness::cluster::TestCluster;

pub async fn confirmed(client: &VeraClient, id: B256, trusted: &ConsensusPublicKey) {
    wait(client, id, trusted, "native receipt", None, None).await;
}

pub async fn submit(
    client: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    call: Bytes,
    phase: &str,
    cluster: &TestCluster,
) {
    let wire = worker
        .sign_native_tx(vera_client::VERA_ADDRESS, call)
        .unwrap();
    let id = NativeTx::decode_wire(&wire).unwrap().tx_id().0;
    let wire_hash = Tx::new(wire.clone().into()).id().0;
    assert_eq!(client.send_native_tx(&wire).await.unwrap(), id);
    eprintln!("native submission phase={phase:?} submission={id} wire_tx={wire_hash}");
    wait(client, id, trusted, phase, Some(wire_hash), Some(cluster)).await;
}

async fn wait(
    client: &VeraClient,
    id: B256,
    trusted: &ConsensusPublicKey,
    phase: &str,
    wire_hash: Option<B256>,
    cluster: Option<&TestCluster>,
) {
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(proof) = client.read_receipt(id, trusted).await.unwrap() {
                assert!(proof.verify(id, trusted).unwrap().success());
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if result.is_err() {
        let observations = match cluster {
            Some(cluster) => observe_replicas(cluster, id, trusted).await,
            None => Vec::new(),
        };
        panic!(
            "native receipt timed out after 30s: phase={phase:?} submission={id} \
             wire_tx={wire_hash:?} replicas={observations:?}"
        );
    }
}

async fn observe_replicas(
    cluster: &TestCluster,
    id: B256,
    trusted: &ConsensusPublicKey,
) -> Vec<String> {
    futures::future::join_all((0..cluster.node_count()).map(|index| async move {
        let client = VeraClient::new(cluster.node(index).rpc_url());
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let (height, receipt) =
                tokio::join!(client.block_number(), client.read_receipt(id, trusted));
            let height = height.map_or_else(|_| "error".to_string(), |height| height.to_string());
            let receipt = match receipt {
                Ok(Some(proof)) => match proof.verify(id, trusted) {
                    Ok(receipt) if receipt.success() => "verified-success",
                    Ok(_) => "verified-failure",
                    Err(_) => "verification-error",
                },
                Ok(None) => "absent",
                Err(_) => "error",
            };
            format!("node{index}: height={height}, receipt={receipt}")
        })
        .await;
        observed.unwrap_or_else(|_| format!("node{index}: observation timed out"))
    }))
    .await
}
