//! Canonical LaKey identities and public commitments for Decaf377 PRE.
use anyhow::{ensure, Result};
use decaf377::{Element, Fr};
use serde::{Deserialize, Serialize};
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::{decaf377::common::PubPoly, r#trait::PubPoly as _};

pub const MASTER_SCALARS: usize = 512;
pub const MATRIX_ROWS: usize = 16;
const DOMAIN: &[u8] = b"orbis.lakey.identity.v1\0";

/// Canonical authentication input for one public-key MPC evaluation.
pub fn evaluation_request_bytes(identity: &Identity, session: &[u8; 32]) -> Result<Vec<u8>> {
    ensure!(*session != [0; 32], "missing LaKey session");
    let mut bytes = b"orbis.lakey.evaluate.v1\0".to_vec();
    bytes.extend_from_slice(&identity.encode()?);
    bytes.extend_from_slice(session);
    Ok(bytes)
}

pub fn registration_object_id(identity: &Identity) -> Result<String> {
    Ok(format!(
        "shieldd:registration:{}",
        hex::encode(identity.encode()?)
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub chain: String,
    pub ring: String,
    pub epoch: u64,
    pub scope: Scope,
    pub field: Field,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    General,
    Person { identity: Vec<u8> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Field {
    Amount = 0,
    Sender = 1,
    Receiver = 2,
}

impl Identity {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(self.epoch != 0, "LaKey epoch must be nonzero");
        let mut out = DOMAIN.to_vec();
        for value in [self.chain.as_bytes(), self.ring.as_bytes()] {
            ensure!(
                !value.is_empty() && value.len() <= 1024,
                "invalid LaKey namespace"
            );
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.epoch.to_le_bytes());
        match &self.scope {
            Scope::General => out.push(0),
            Scope::Person { identity } => {
                ensure!(
                    !identity.is_empty() && identity.len() <= 512,
                    "invalid LaKey person identity"
                );
                out.push(1);
                out.extend_from_slice(&(identity.len() as u32).to_le_bytes());
                out.extend_from_slice(identity);
            }
        }
        out.push(self.field as u8);
        Ok(out)
    }

    /// REG32 matrix expansion; caller cannot supply a different matrix.
    pub fn matrix(&self) -> Result<Vec<u32>> {
        let mut hash = sha3::Shake256::default();
        hash.update(&self.encode()?);
        let mut bytes = vec![0; MATRIX_ROWS * MASTER_SCALARS * 4];
        hash.finalize_xof().read(&mut bytes);
        Ok(bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect())
    }
}

/// Reconstruct public coefficients from ordered node commitments, never secret shares.
pub fn public_polynomial(points: &[Element], threshold: usize) -> Result<PubPoly> {
    let points: Vec<_> = points
        .iter()
        .enumerate()
        .map(|(i, p)| (i as u32 + 1, *p))
        .collect();
    polynomial_from_evaluations(&points, threshold)
}

fn polynomial_from_evaluations(points: &[(u32, Element)], threshold: usize) -> Result<PubPoly> {
    ensure!(
        threshold >= 2 && threshold <= points.len() && points.len() <= 32,
        "invalid LaKey committee"
    );
    let mut seen = std::collections::BTreeSet::new();
    for (i, _) in points {
        ensure!(
            *i > 0 && *i <= 32 && seen.insert(*i),
            "invalid LaKey node index"
        );
    }
    let mut commits = vec![Element::default(); threshold];
    for (i, (index, point)) in points[..threshold].iter().enumerate() {
        let x = Fr::from(*index as u64);
        let mut coeff = vec![Fr::from(1u64)];
        let mut denominator = Fr::from(1u64);
        for (j, (other, _)) in points[..threshold].iter().enumerate() {
            if i == j {
                continue;
            }
            let y = Fr::from(*other as u64);
            let mut next = vec![Fr::from(0u64); coeff.len() + 1];
            for (k, c) in coeff.iter().enumerate() {
                next[k] -= *c * y;
                next[k + 1] += c;
            }
            coeff = next;
            denominator *= x - y;
        }
        let weighted = *point * denominator.inverse().unwrap();
        for (target, coefficient) in commits.iter_mut().zip(coeff) {
            *target += weighted * coefficient;
        }
    }
    let polynomial = PubPoly { commits };
    ensure!(
        !polynomial.eval(0).is_identity(),
        "identity LaKey public key"
    );
    for (i, point) in points {
        ensure!(
            polynomial.eval(*i) == *point,
            "inconsistent LaKey node commitment"
        );
    }
    Ok(polynomial)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            chain: "chain".into(),
            ring: "ring".into(),
            epoch: 1,
            scope: Scope::Person {
                identity: vec![7; 48],
            },
            field: Field::Amount,
        }
    }
    #[test]
    fn namespaces_and_scopes_are_distinct() {
        let original = identity();
        let base = original.matrix().unwrap();
        assert_eq!(base.len(), MATRIX_ROWS * MASTER_SCALARS);
        let mut variants = vec![original.clone(); 6];
        variants[0].chain.push('x');
        variants[1].ring.push('x');
        variants[2].epoch += 1;
        variants[3].scope = Scope::General;
        variants[4].scope = Scope::Person {
            identity: vec![8; 48],
        };
        variants[5].field = Field::Sender;
        for v in variants {
            assert_ne!(v.matrix().unwrap(), base);
        }
        let mut a = original.clone();
        a.chain = "a/b".into();
        a.ring = "c".into();
        let mut b = original;
        b.chain = "a".into();
        b.ring = "b/c".into();
        assert_ne!(a.encode().unwrap(), b.encode().unwrap());
        b.scope = Scope::Person { identity: vec![] };
        assert!(b.encode().is_err());
    }
    #[test]
    fn fresh_pre_shares_match_registration_and_reject_substitutions() {
        use crate::{
            r#trait::{PriShare, ThresholdDealer},
            PreImpl,
        };
        let (reader_sk, reader) = PreImpl::generate_keypair();
        let pop = PreImpl::prove_reader_key(&reader_sk, &reader).unwrap();
        let secret = Fr::from(17u64);
        let key = Element::GENERATOR * secret;
        let epk = Element::GENERATOR * Fr::from(11u64);
        for refresh in [0u64, 1] {
            let shares: Vec<_> = (1..=5)
                .map(|i| {
                    let x = Fr::from(i as u64);
                    let v = secret + Fr::from(3 + refresh) * x + Fr::from(7 + refresh) * x * x;
                    reencrypt(PriShare { i, v }, &epk.vartime_compress().0, &reader, &pop).unwrap()
                })
                .collect();
            let selected = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
            let result = recover(&selected, 3, 5, &key, &epk, &reader).unwrap();
            assert_eq!(result - key * reader_sk, epk * secret);
            assert!(recover(&selected, 3, 5, &(key + Element::GENERATOR), &epk, &reader).is_err());
            assert!(recover(&selected, 3, 5, &key, &(epk + Element::GENERATOR), &reader).is_err());
            assert!(recover(&selected, 3, 5, &key, &epk, &(reader + Element::GENERATOR)).is_err());
            assert!(recover(&selected[..2], 3, 5, &key, &epk, &reader).is_err());
            let mut changed = selected.clone();
            changed[1] = changed[0].clone();
            assert!(recover(&changed, 3, 5, &key, &epk, &reader).is_err());
            changed = selected.clone();
            changed[0].proof[0] ^= 1;
            assert!(recover(&changed, 3, 5, &key, &epk, &reader).is_err());
        }
    }

    #[test]
    fn commitments_bind_all_nodes_and_threshold() {
        let secret = Fr::from(17u64);
        let points: Vec<_> = (1..=5)
            .map(|i| {
                let x = Fr::from(i as u64);
                Element::GENERATOR * (secret + Fr::from(3u64) * x + Fr::from(5u64) * x * x)
            })
            .collect();
        let poly = public_polynomial(&points, 3).unwrap();
        assert_eq!(poly.eval(0), Element::GENERATOR * secret);
        let mut changed = points.clone();
        changed[4] += Element::GENERATOR;
        assert!(public_polynomial(&changed, 3).is_err());
        assert!(public_polynomial(&points, 2).is_err());
        assert!(public_polynomial(&points, 0).is_err());
        assert!(public_polynomial(&vec![Element::default(); 5], 3).is_err());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub identity: Identity,
    pub session: [u8; 32],
    pub operation: Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    PublicKey,
    Pre {
        epk: [u8; 32],
        reader: Vec<u8>,
        reader_proof: crate::r#trait::ReaderKeyProof,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicShare {
    pub index: u32,
    pub public_share: Vec<u8>,
}

/// One node's PRE result under its transient LaKey share.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreShare {
    pub index: u32,
    pub public_share: Vec<u8>,
    pub ciphertext_share: Vec<u8>,
    pub challenge: Vec<u8>,
    pub proof: Vec<u8>,
}

pub fn reencrypt(
    share: crate::r#trait::PriShare<Fr>,
    epk: &[u8],
    reader: &Element,
    reader_proof: &crate::r#trait::ReaderKeyProof,
) -> Result<PreShare> {
    use crate::{
        r#trait::{DistKeyShare, ThresholdDealer},
        CryptoSerialize, PreImpl,
    };
    let public_share = Element::GENERATOR * share.v;
    let reply = PreImpl::new().reencrypt_commitment(
        &DistKeyShare { pri_share: share },
        epk,
        reader,
        reader_proof,
        None,
    )?;
    Ok(PreShare {
        index: reply.share.i,
        public_share: public_share.to_bytes()?,
        ciphertext_share: reply.share.v.to_bytes()?,
        challenge: CryptoSerialize::to_bytes(&reply.challenge)?,
        proof: CryptoSerialize::to_bytes(&reply.proof)?,
    })
}

/// Verify fresh node commitments against the registered key before reconstructing PRE.
pub fn recover(
    shares: &[PreShare],
    threshold: usize,
    nodes: usize,
    registered_key: &Element,
    epk: &Element,
    reader: &Element,
) -> Result<Element> {
    use crate::{
        r#trait::{PubShare, ReencryptReply, ThresholdDealer},
        CryptoDeserialize, PreImpl,
    };
    ensure!(
        threshold >= 2 && threshold <= nodes && nodes <= 32,
        "invalid LaKey committee"
    );
    ensure!(
        shares.len() >= threshold && shares.len() <= nodes,
        "insufficient LaKey PRE shares"
    );
    ensure!(
        !registered_key.is_identity(),
        "identity registered LaKey key"
    );
    let dealer = PreImpl::new();
    let mut replies = Vec::with_capacity(shares.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut points = Vec::new();
    for item in shares {
        ensure!(
            item.index > 0 && item.index as usize <= nodes && seen.insert(item.index),
            "invalid or duplicate LaKey node index"
        );
        let point = Element::from_bytes(&item.public_share)?;
        let reply = ReencryptReply {
            share: PubShare {
                i: item.index,
                v: Element::from_bytes(&item.ciphertext_share)?,
            },
            challenge: <Fr as CryptoDeserialize>::from_bytes(&item.challenge)?,
            proof: <Fr as CryptoDeserialize>::from_bytes(&item.proof)?,
        };
        dealer.verify(
            reader,
            &PubPoly {
                commits: vec![point],
            },
            epk,
            &reply,
            None,
        )?;
        points.push((item.index, point));
        replies.push(reply.share.clone());
    }
    let polynomial = polynomial_from_evaluations(&points, threshold)?;
    ensure!(
        polynomial.eval(0) == *registered_key,
        "derived LaKey key does not match registration"
    );
    dealer
        .recover(&replies, threshold, nodes)?
        .ok_or_else(|| anyhow::anyhow!("missing PRE result"))
}
