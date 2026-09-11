//! Authenticated LaKey public evaluations bound to a registered Orbis committee.
use anyhow::{ensure, Result};
use common::blockchain::verify_node_message;
use crypto::r#trait::PubPoly;
use crypto::{
    lakey::{public_polynomial, Identity},
    CryptoDeserialize, CryptoSerialize, GroupAffine,
};
use serde::{Deserialize, Serialize};

pub fn committee_id(ring: &crate::r#trait::RingPayload) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    ensure!(
        ring.threshold == 3 && ring.peer_node_keys.len() == 5,
        "unsupported LaKey committee"
    );
    let mut keys = ring.peer_node_keys.clone();
    keys.sort();
    keys.dedup();
    ensure!(keys.len() == 5, "duplicate LaKey node");
    let mut hash = Sha256::new();
    hash.update(b"orbis.lakey.committee.v1\0");
    hash.update(GroupAffine::from_bytes(&hex::decode(&ring.ring_pk)?)?.to_bytes()?);
    hash.update(ring.threshold.to_le_bytes());
    for key in keys {
        let bytes = hex::decode(key)?;
        hash.update((bytes.len() as u32).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub identity: Identity,
    pub session: [u8; 32],
    pub committee: [u8; 32],
    pub index: u32,
    pub public_share: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Evaluation {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        ensure!((1..=5).contains(&self.index), "invalid LaKey node index");
        ensure!(self.session != [0; 32], "missing LaKey session");
        let point = GroupAffine::from_bytes(&self.public_share)?;
        ensure!(
            point.to_bytes()? == self.public_share,
            "noncanonical public share"
        );
        let mut bytes = b"orbis.lakey.public-evaluation.v1\0".to_vec();
        bytes.extend_from_slice(&self.identity.encode()?);
        bytes.extend_from_slice(&self.session);
        bytes.extend_from_slice(&self.committee);
        bytes.extend_from_slice(&self.index.to_le_bytes());
        bytes.extend_from_slice(&self.public_share);
        Ok(bytes)
    }
}

/// All five authenticated evaluations are required to certify derivation.
pub fn registered_key(
    identity: &Identity,
    committee: [u8; 32],
    node_keys: &[String],
    evidence: &[Evaluation],
) -> Result<GroupAffine> {
    ensure!(
        node_keys.len() == 5 && evidence.len() == 5,
        "LaKey registration requires all five nodes"
    );
    let mut keys = node_keys.to_vec();
    keys.sort();
    keys.dedup();
    ensure!(keys.len() == 5, "duplicate LaKey committee node");
    let session = evidence[0].session;
    let mut points = [None; 5];
    for item in evidence {
        ensure!(
            &item.identity == identity && item.committee == committee && item.session == session,
            "LaKey evaluation context mismatch"
        );
        let bytes = item.signing_bytes()?;
        let index = item.index as usize - 1;
        ensure!(points[index].is_none(), "duplicate LaKey evaluation");
        verify_node_message(&keys[index], &bytes, &item.signature)?;
        points[index] = Some(GroupAffine::from_bytes(&item.public_share)?);
    }
    let points: Vec<_> = points
        .into_iter()
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow::anyhow!("missing LaKey node"))?;
    Ok(public_polynomial(&points, 3)?.eval(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::blockchain::{ChainConfig, TxSigner};
    use crypto::lakey::{Field, Scope};
    use crypto::ScalarField;

    #[test]
    fn certification_requires_every_authenticated_mpc_evaluation() {
        let mut signers: Vec<_> = (1..=5)
            .map(|n| TxSigner::new(&[n; 32], ChainConfig::local()).unwrap())
            .collect();
        signers.sort_by_key(TxSigner::public_key_hex);
        let node_keys: Vec<_> = signers.iter().map(TxSigner::public_key_hex).collect();
        let identity = Identity {
            chain: "chain".into(),
            ring: "ring".into(),
            epoch: 1,
            scope: Scope::General,
            field: Field::Amount,
        };
        let poly = crypto::decaf377::common::PubPoly {
            commits: [17u64, 19, 23]
                .map(|v| GroupAffine::GENERATOR * ScalarField::from(v))
                .to_vec(),
        };
        let evidence: Vec<_> = signers
            .iter()
            .enumerate()
            .map(|(i, signer)| {
                let mut item = Evaluation {
                    identity: identity.clone(),
                    session: [1; 32],
                    committee: [2; 32],
                    index: i as u32 + 1,
                    public_share: poly.eval(i as u32 + 1).to_bytes().unwrap(),
                    signature: Vec::new(),
                };
                item.signature = signer
                    .sign_node_message(&item.signing_bytes().unwrap())
                    .unwrap();
                item
            })
            .collect();
        assert_eq!(
            registered_key(&identity, [2; 32], &node_keys, &evidence).unwrap(),
            poly.eval(0)
        );
        assert!(registered_key(&identity, [2; 32], &node_keys, &evidence[..3]).is_err());
        let mut changed = evidence.clone();
        // Two corrupt nodes can authenticate their own false points, but cannot
        // change the constant fixed by the other three honest evaluations.
        for i in [0, 1] {
            changed[i].public_share = (poly.eval(i as u32 + 1) + GroupAffine::GENERATOR)
                .to_bytes()
                .unwrap();
            changed[i].signature = signers[i]
                .sign_node_message(&changed[i].signing_bytes().unwrap())
                .unwrap();
        }
        assert!(registered_key(&identity, [2; 32], &node_keys, &changed).is_err());
        for i in 0..5 {
            let mut changed = evidence.clone();
            changed[i].session = [3; 32];
            assert!(registered_key(&identity, [2; 32], &node_keys, &changed).is_err());
            changed = evidence.clone();
            changed[i].signature[0] ^= 1;
            assert!(registered_key(&identity, [2; 32], &node_keys, &changed).is_err());
        }
        let mut wrong_identity = identity.clone();
        wrong_identity.field = Field::Sender;
        assert!(registered_key(&wrong_identity, [2; 32], &node_keys, &evidence).is_err());
        assert!(registered_key(&identity, [3; 32], &node_keys, &evidence).is_err());
        let mut duplicate = evidence.clone();
        duplicate[4] = duplicate[0].clone();
        assert!(registered_key(&identity, [2; 32], &node_keys, &duplicate).is_err());
    }
}
