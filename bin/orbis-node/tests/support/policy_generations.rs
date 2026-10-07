use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use vera_client::{BlsSigner, VeraClient};
use vera_domain::ConsensusPublicKey;
use vera_modules::acp::abi::IAcp;

pub fn definition(signer: bool, reader: bool) -> String {
    let signer_relation = if signer {
        "    relations:\n      - name: signer\n"
    } else {
        ""
    };
    let reader_relation = if reader {
        "    relations:\n      - name: reader\n"
    } else {
        ""
    };
    let sign_expression = if signer { "signer" } else { "owner" };
    let read_expression = if reader { "reader" } else { "owner" };
    format!(
        "name: native_threshold
resources:
  - name: ring_policy
    relations:
      - name: creator
    permissions:
      - name: create_ring
        expr: creator
  - name: ring
    relations:
      - name: operator
    permissions:
      - name: update_ring
        expr: operator
  - name: key
{signer_relation}    permissions:
      - name: sign
        expr: {sign_expression}
  - name: document
{reader_relation}    permissions:
      - name: read
        expr: {read_expression}
"
    )
}

pub async fn replace(
    client: &VeraClient,
    worker: &BlsSigner,
    trusted: &ConsensusPublicKey,
    policy: B256,
    definition: String,
) {
    let call = IAcp::editPolicyCall {
        policyId: policy,
        policy: definition.into_bytes().into(),
        marshalType: 1,
    };
    let wire = worker
        .sign_native_tx(vera_client::ACP_ADDRESS, call.abi_encode().into())
        .unwrap();
    let id = client.send_native_tx(&wire).await.unwrap();
    super::confirmed(client, id, trusted).await;
}

pub async fn assert_relationship(
    client: &VeraClient,
    policy: B256,
    trusted: &ConsensusPublicKey,
    expected: &vera_acp::Relationship,
) {
    let mut cursor = None;
    let mut minimum = 1;
    let mut found = false;
    // A small page size exercises continuation even for this fixed fixture.
    for _ in 0..32 {
        let page = client
            .read_relationship_page(policy, cursor.clone(), 2, minimum, trusted)
            .await
            .unwrap();
        minimum = page.revision;
        found |= page
            .records
            .iter()
            .any(|record| !record.archived && record.relationship == *expected);
        match page.continuation {
            Some(next) => {
                if let Some(previous) = cursor {
                    assert!(next > previous, "relationship cursor must advance");
                }
                cursor = Some(next);
            }
            None => {
                assert!(
                    found,
                    "current relationship was absent from certified pages"
                );
                return;
            }
        }
    }
    panic!("relationship enumeration exceeded the fixture's page budget");
}
