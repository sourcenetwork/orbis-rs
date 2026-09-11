//! Registered-key evaluation and encrypted Shieldd collection; no auditor secret is needed.
use anyhow::{ensure, Context, Result};
use authn::{create_authenticated_request, JwtSigner};
use bulletin::{
    lakey::{committee_id, registered_key, Evaluation},
    r#trait::RingPayload,
};
use crypto::{
    lakey::{self, Identity, PreShare},
    CryptoDeserialize, CryptoSerialize, GroupAffine,
};
use futures::future::join_all;
use proto::v0::{
    pre::{pre_service_client::PreServiceClient, ReencryptShielddRequest},
    sign::{sign_service_client::SignServiceClient, EvaluateShielddAuditKeyRequest},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEndpoint {
    pub node_key: String,
    pub endpoint: String,
}

fn ordered_nodes<'a>(
    ring: &RingPayload,
    nodes: &'a [NodeEndpoint],
) -> Result<Vec<&'a NodeEndpoint>> {
    committee_id(ring)?;
    ensure!(nodes.len() == 5, "all five MPC endpoints are required");
    let mut nodes: Vec<_> = nodes.iter().collect();
    nodes.sort_by(|a, b| a.node_key.cmp(&b.node_key));
    let mut keys = ring.peer_node_keys.clone();
    keys.sort();
    for (node, key) in nodes.iter().zip(keys) {
        ensure!(
            node.node_key == key,
            "endpoint does not match the trusted committee"
        );
    }
    Ok(nodes)
}

async fn channel(endpoint: &str) -> Result<tonic::transport::Channel> {
    Ok(
        tonic::transport::Endpoint::from_shared(endpoint.to_owned())?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(150))
            .connect()
            .await?,
    )
}

/// The caller supplies authoritative ring metadata and endpoints, never metadata from a submission.
pub async fn evaluate(
    ring: &RingPayload,
    nodes: &[NodeEndpoint],
    identity: &Identity,
    session: [u8; 32],
    signer: &JwtSigner,
) -> Result<(GroupAffine, Vec<Evaluation>)> {
    let nodes = ordered_nodes(ring, nodes)?;
    let message = lakey::evaluation_request_bytes(identity, &session)?;
    let object = lakey::registration_object_id(identity)?;
    let token = signer.create_sign_jwt(&object, &message)?;
    let request = EvaluateShielddAuditKeyRequest {
        identity_json: serde_json::to_vec(identity)?,
        session: session.to_vec(),
    };
    let responses = join_all(nodes.iter().map(|node| {
        let request = request.clone();
        let token = &token;
        async move {
            let mut client = SignServiceClient::new(channel(&node.endpoint).await?)
                .max_decoding_message_size(65536);
            let response = client
                .evaluate_shieldd_audit_key(create_authenticated_request(request, token)?)
                .await?
                .into_inner();
            let evaluation: Evaluation = serde_json::from_slice(&response.evaluation_json)?;
            ensure!(
                evaluation.session == session,
                "MPC evaluation session mismatch"
            );
            Ok::<_, anyhow::Error>(evaluation)
        }
    }))
    .await;
    let evaluations: Vec<_> = responses.into_iter().collect::<Result<_>>()?;
    let key = registered_key(
        identity,
        committee_id(ring)?,
        &ring.peer_node_keys,
        &evaluations,
    )?;
    Ok((key, evaluations))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedCollection {
    pub version: u32,
    pub accepted_selection: Vec<u8>,
    pub reader: Vec<u8>,
    pub shares: Vec<PreShare>,
}

/// Rechecks every share against separately authenticated selection bytes and registered key.
pub fn verify(
    collection: &EncryptedCollection,
    accepted_selection: &[u8],
    registered_key: &GroupAffine,
    epk: &GroupAffine,
    reader: &GroupAffine,
) -> Result<GroupAffine> {
    ensure!(
        collection.version == 1,
        "unsupported encrypted collection version"
    );
    ensure!(
        collection.accepted_selection == accepted_selection,
        "accepted selection substitution"
    );
    ensure!(
        collection.reader == reader.to_bytes()?,
        "recipient substitution"
    );
    lakey::recover(&collection.shares, 3, 5, registered_key, epk, reader)
}

/// One selection runs across all five MPC nodes; the returned material remains encrypted.
pub async fn collect(
    ring: &RingPayload,
    nodes: &[NodeEndpoint],
    request: ReencryptShielddRequest,
    token: &str,
    accepted_selection: &[u8],
    registered_key: &GroupAffine,
    epk: &GroupAffine,
) -> Result<EncryptedCollection> {
    let nodes = ordered_nodes(ring, nodes)?;
    ensure!(
        accepted_selection.len() <= 1024 * 1024,
        "accepted selection too large"
    );
    ensure!(
        request.selection_json.len() <= 65536
            && request.session.len() == 32
            && request.session.iter().any(|b| *b != 0),
        "invalid collection request"
    );
    let reader = GroupAffine::from_bytes(&request.rdr_pk)?;
    let responses = join_all(nodes.iter().enumerate().map(|(index, node)| {
        let request = request.clone();
        async move {
            let mut client = PreServiceClient::new(channel(&node.endpoint).await?)
                .max_decoding_message_size(2 * 1024 * 1024);
            let response = client
                .reencrypt_shieldd(create_authenticated_request(request, token)?)
                .await?
                .into_inner();
            ensure!(
                response.accepted_selection_json == accepted_selection,
                "node resolved different transaction data"
            );
            ensure!(
                response.share_index == index as u32 + 1,
                "node returned another participant's share"
            );
            ensure!(
                response.threshold == 3 && response.ring_public_key == hex::decode(&ring.ring_pk)?,
                "ring substitution"
            );
            Ok::<_, anyhow::Error>(PreShare {
                index: response.share_index,
                public_share: response.public_share,
                ciphertext_share: response.share,
                challenge: response.challenge,
                proof: response.proof,
            })
        }
    }))
    .await;
    let shares = responses
        .into_iter()
        .collect::<Result<Vec<_>>>()
        .context("collection incomplete; no result released")?;
    let collection = EncryptedCollection {
        version: 1,
        accepted_selection: accepted_selection.to_vec(),
        reader: reader.to_bytes()?,
        shares,
    };
    verify(
        &collection,
        accepted_selection,
        registered_key,
        epk,
        &reader,
    )?;
    Ok(collection)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationKey {
    pub identity: Identity,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationStatement {
    pub version: u32,
    pub object_id: String,
    pub ring_id: String,
    pub ring_public_key: [u8; 32],
    pub keys: [RegistrationKey; 3],
    pub message: Vec<u8>,
}

/// The statement must come from the local Shieldd SDK; the returned certificate is verified locally.
pub async fn certify(
    ring: &RingPayload,
    endpoint: &str,
    registration: Vec<u8>,
    statement: &RegistrationStatement,
    evaluations: [Vec<Evaluation>; 3],
    signer: &JwtSigner,
) -> Result<Vec<u8>> {
    use crypto::{decaf377::sign::SchnorrSignature, r#trait::ThresholdSigner, SignImpl};
    ensure!(
        registration.len() <= 65536 && statement.version == 1,
        "invalid registration"
    );
    let root = GroupAffine::from_bytes(&hex::decode(&ring.ring_pk)?)?;
    ensure!(
        root.to_bytes()? == statement.ring_public_key,
        "registration root mismatch"
    );
    let committee = committee_id(ring)?;
    for (key, evidence) in statement.keys.iter().zip(&evaluations) {
        ensure!(
            key.identity.ring == statement.ring_id,
            "registration ring mismatch"
        );
        ensure!(
            registered_key(&key.identity, committee, &ring.peer_node_keys, evidence)?.to_bytes()?
                == key.public_key,
            "registration derived key mismatch"
        );
    }
    let token = signer.create_sign_jwt(&statement.object_id, &statement.message)?;
    let request = proto::v0::sign::SignShielddAuditRegistrationRequest {
        registration_json: registration,
        evaluations_json: serde_json::to_vec(&evaluations)?,
    };
    let mut client =
        SignServiceClient::new(channel(endpoint).await?).max_decoding_message_size(65536);
    let response = client
        .sign_shieldd_audit_registration(create_authenticated_request(request, &token)?)
        .await?
        .into_inner();
    let bytes = hex::decode(response.signature)?;
    let signature = SchnorrSignature::from_bytes(&bytes)?;
    SignImpl::new().verify(&root, &statement.message, &signature)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{
        r#trait::{PriShare, ThresholdDealer},
        PreImpl, ScalarField,
    };

    #[test]
    fn stored_collection_rejects_evidence_and_recipient_substitution() {
        let secret = ScalarField::from(17u64);
        let key = GroupAffine::GENERATOR * secret;
        let epk = GroupAffine::GENERATOR * ScalarField::from(11u64);
        let (reader_secret, reader) = crypto::helpers::generate_keypair().unwrap();
        let pop = PreImpl::prove_reader_key(&reader_secret, &reader).unwrap();
        let shares = (1..=5)
            .map(|i| {
                let x = ScalarField::from(i as u64);
                lakey::reencrypt(
                    PriShare {
                        i,
                        v: secret + ScalarField::from(3u64) * x + ScalarField::from(7u64) * x * x,
                    },
                    &epk.to_bytes().unwrap(),
                    &reader,
                    &pop,
                )
                .unwrap()
            })
            .collect();
        let collection = EncryptedCollection {
            version: 1,
            accepted_selection: b"accepted".to_vec(),
            reader: reader.to_bytes().unwrap(),
            shares,
        };
        assert_eq!(
            verify(&collection, b"accepted", &key, &epk, &reader).unwrap() - key * reader_secret,
            epk * secret
        );
        assert!(verify(&collection, b"changed", &key, &epk, &reader).is_err());
        assert!(verify(
            &collection,
            b"accepted",
            &key,
            &epk,
            &(reader + GroupAffine::GENERATOR)
        )
        .is_err());
        assert!(verify(
            &collection,
            b"accepted",
            &(key + GroupAffine::GENERATOR),
            &epk,
            &reader
        )
        .is_err());
        let mut changed = collection.clone();
        changed.version += 1;
        assert!(verify(&changed, b"accepted", &key, &epk, &reader).is_err());
        changed = collection.clone();
        changed.shares[0].proof[0] ^= 1;
        assert!(verify(&changed, b"accepted", &key, &epk, &reader).is_err());
        changed = collection;
        changed.shares[4] = changed.shares[0].clone();
        assert!(verify(&changed, b"accepted", &key, &epk, &reader).is_err());
    }
}
