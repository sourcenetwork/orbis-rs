//! Lifecycle test: Fresh DKG → PRE → SIGN → Reshare → PRE → SIGN → Refresh → PRE → SIGN
//!
//! Verifies that ciphertext encrypted before key rotation can still be
//! decrypted after reshare and refresh rounds, and that signatures still
//! verify after each rotation.
//!
//! The SAME ciphertext is used throughout all three rounds, proving the
//! shared secret is preserved across key rotations.

use crate::context::CiphertextContext;
use crate::error::{CryptoError, Result};
use crate::r#trait::{
    DistKeyShare, DistributedShare, DkgMode, DkgRole, PriShare, PubPoly as PubPolyTrait, PubShare,
    ReencryptReply, Secret, ThresholdDealer, ThresholdSigner,
};
use crate::test_helper::{DKGCoordinator, TestDkgNode};
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::fmt::Debug;

/// Fixed [`CiphertextContext`] used for the single encryption exercised across
/// every rotation round in this lifecycle test.
fn lifecycle_ctx() -> CiphertextContext {
    CiphertextContext {
        ring_pk: b"lifecycle-ring-pk".to_vec(),
        policy_id: "lifecycle-policy".to_string(),
        resource: "lifecycle-resource".to_string(),
        permission: "read".to_string(),
        tier: None,
        timestamp: None,
        salt: None,
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Run a full threshold PRE roundtrip: reencrypt t shares, recover xnc_cmt, decrypt.
fn pre_roundtrip<T, SV, PK, PP>(
    shares: &[PriShare<SV>],
    threshold: usize,
    total: usize,
    agg_pk: &PK,
    enc_cmt: &PK,
    encrypted_secret: &Secret,
    rdr_sk: &SV,
    rdr_pk: &PK,
    pub_poly: &PP,
) -> Result<Vec<u8>>
where
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    SV: Clone + zeroize::Zeroize,
    PK: Clone + PartialEq + Debug,
    PP: PubPolyTrait<PublicKey = PK>,
{
    let dealer = T::new();
    let mut replies = Vec::new();

    for share in shares.iter().take(threshold) {
        let dks = DistKeyShare {
            pri_share: share.clone(),
        };
        let reply = dealer.reencrypt(&dks, encrypted_secret, rdr_pk, None)?;
        dealer.verify(rdr_pk, pub_poly, enc_cmt, &reply, None)?;
        replies.push(reply);
    }

    let pub_shares: Vec<PubShare<PK>> = replies.iter().map(|r| r.share.clone()).collect();
    let xnc_cmt = dealer
        .recover(&pub_shares, threshold, total)?
        .expect("recovery must succeed with threshold shares");

    T::decrypt_secret(agg_pk, &xnc_cmt, rdr_sk, encrypted_secret, &lifecycle_ctx())
}

/// Run a full threshold SIGN roundtrip: sign with t shares, recover signature, verify.
fn sign_roundtrip<S, SV, PK, PP>(
    signer: &S,
    shares: &[PriShare<SV>],
    threshold: usize,
    total: usize,
    pub_poly: &PP,
    agg_pk: &PK,
    msg: &[u8],
) -> Result<()>
where
    S: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    S::SigShare: Clone,
    S::NonceCommitment: Clone,
    SV: Clone + zeroize::Zeroize,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
{
    let participants: Vec<_> = shares.iter().take(threshold).collect();

    let mut commitments: Vec<(u32, S::NonceCommitment)> = Vec::new();
    let mut signing_states = Vec::new();

    for share in &participants {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let (commitment, state) = signer.generate_nonces(&dks)?;
        commitments.push((share.i, commitment));
        signing_states.push(state);
    }

    let mut sig_shares = Vec::new();
    for (idx, share) in participants.iter().enumerate() {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let sig_share = signer.sign(
            &dks,
            msg,
            pub_poly,
            Some(&signing_states[idx]),
            &commitments,
            None,
            None,
        )?;
        sig_shares.push(sig_share);
    }

    let sig = signer
        .recover(&sig_shares, threshold, total, msg, &commitments)?
        .expect("signature recovery must succeed");

    signer.verify(agg_pk, msg, &sig)?;
    Ok(())
}

/// Run a same-committee reshare ceremony.
///
/// All `n` nodes act as `DealerReceiver`. Returns `(new_pk, new_shares, new_pub_poly)`.
fn run_reshare_ceremony<Node, SV, PK, PP, NF>(
    node_factory: &NF,
    n: usize,
    t: usize,
    old_shares: &[PriShare<SV>],
    old_pk: &PK,
) -> Result<(PK, Vec<PriShare<SV>>, PP)>
where
    Node: TestDkgNode<ShareValue = SV, PublicKey = PK, PubPoly = PP>,
    Node::PolynomialCommitment: Clone,
    SV: Clone + zeroize::Zeroize,
    PK: Clone + CanonicalSerialize + Debug,
    PP: Clone + PubPolyTrait<PublicKey = PK>,
    NF: Fn(u32, usize, usize, u128, DkgRole) -> Result<Box<Node>>,
{
    use rand_core::{OsRng, RngCore};
    let mut rng = OsRng;
    let mut session_id_bytes = [0u8; 16];
    rng.fill_bytes(&mut session_id_bytes);
    let session_id = u128::from_le_bytes(session_id_bytes);

    let participating_ids: Vec<u32> = (1..=n as u32).collect();
    let mut share_map: HashMap<u32, SV> = old_shares.iter().map(|s| (s.i, s.v.clone())).collect();

    let mut nodes: Vec<Box<Node>> = (1..=n as u32)
        .map(|i| node_factory(i, t, n, session_id, DkgRole::DealerReceiver))
        .collect::<Result<Vec<_>>>()?;

    // Generate resharing polynomials
    for node in &mut nodes {
        let id = node.node_id();
        node.generate_polynomial(DkgMode::Reshare {
            old_share: share_map.remove(&id).unwrap(),
            participating_ids: participating_ids.clone(),
            new_threshold: t,
            new_total_nodes: n,
            new_node_id: None,
        })?;
    }

    // Broadcast commitments
    let commitments: Vec<(u32, Node::PolynomialCommitment)> = nodes
        .iter()
        .map(|nd| (nd.node_id(), nd.commitment().clone()))
        .collect();

    for node in &mut nodes {
        for (from_id, comm) in &commitments {
            if *from_id != node.node_id() {
                node.receive_commitment(*from_id, comm.clone())?;
            }
        }
    }

    // Generate and distribute shares (skip self)
    let all_shares: Vec<Vec<DistributedShare<SV>>> = nodes
        .iter()
        .map(|nd| nd.generate_shares())
        .collect::<Result<Vec<_>>>()?;

    for batch in &all_shares {
        for share in batch {
            if share.from_id != share.to_id {
                let recipient = nodes
                    .iter_mut()
                    .find(|nd| nd.node_id() == share.to_id)
                    .ok_or_else(|| {
                        CryptoError::DKGError(format!("Recipient node {} not found", share.to_id))
                    })?;
                recipient.receive_share(share.clone())?;
            }
        }
    }

    // Verify PK preserved and collect new shares
    let mut new_shares = Vec::new();
    for node in &nodes {
        let pk = node.compute_aggregate_public_key()?;
        let mut pk_bytes = Vec::new();
        let mut old_pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;
        old_pk
            .serialize_compressed(&mut old_pk_bytes)
            .map_err(|e| CryptoError::DKGError(format!("Serialization error: {}", e)))?;
        assert_eq!(
            pk_bytes,
            old_pk_bytes,
            "Node {}: reshare must preserve aggregate public key",
            node.node_id()
        );
        new_shares.push(node.compute_secret_share()?);
    }

    let new_pub_poly = nodes[0].compute_public_polynomial()?;
    let new_pk = nodes[0].compute_aggregate_public_key()?;

    Ok((new_pk, new_shares, new_pub_poly))
}

// ============================================================================
// Public entry point
// ============================================================================

/// Run the full key-rotation lifecycle test.
///
/// # Phases
/// 1. **Fresh DKG** — encrypt a secret; verify PRE decryption and threshold signature.
/// 2. **Reshare** (same committee) — rotate shares; verify SAME ciphertext still decrypts
///    and signatures still verify.
/// 3. **Refresh** — add delta shares; verify SAME ciphertext still decrypts and signatures
///    still verify.
///
/// # Arguments
/// * `node_factory`  — creates a DKG node `(id, threshold, total_nodes, session_id, role)`.
/// * `make_keypair`  — returns a random reader `(secret_key, public_key)` pair.
/// * `add_shares`    — adds two share values: used for refresh `new_share = old + delta`.
/// * `add_pub_poly`  — adds two public polynomials coefficient-wise: used to compute the
///   combined pub_poly after refresh (`reshare_poly + delta_poly`).
pub fn run_lifecycle_test<Node, T, S, SV, PK, PP, NF, MK, AS, APK>(
    node_factory: NF,
    make_keypair: MK,
    add_shares: AS,
    add_pub_poly: APK,
) -> Result<()>
where
    Node: TestDkgNode<ShareValue = SV, PublicKey = PK, PubPoly = PP>,
    Node::PolynomialCommitment: Clone,
    T: ThresholdDealer<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        Secret = Secret,
        DistKeyShare = DistKeyShare<SV>,
        ReencryptReply = ReencryptReply<SV, PK>,
    >,
    S: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    S::SigShare: Clone,
    S::NonceCommitment: Clone,
    SV: Clone + zeroize::Zeroize,
    PK: Clone + PartialEq + Debug + CanonicalSerialize,
    PP: Clone + PubPolyTrait<PublicKey = PK>,
    NF: Fn(u32, usize, usize, u128, DkgRole) -> Result<Box<Node>> + Clone,
    MK: Fn() -> (SV, PK),
    AS: Fn(&SV, &SV) -> SV,
    APK: Fn(&PP, &PP) -> PP,
{
    let n = 3usize;
    let t = 2usize;
    let msg = b"lifecycle test message";
    let plaintext = b"lifecycle secret data";

    // ── Round 1: Fresh DKG ────────────────────────────────────────────────
    let mut coord = DKGCoordinator::new(node_factory.clone(), n, t)?;
    let (agg_pk, shares_v1, pub_poly_v1) = coord.run_dkg()?;

    let (rdr_sk, rdr_pk) = make_keypair();
    let (enc_cmt, encrypted_secret, _) =
        T::encrypt_secret(&agg_pk, plaintext, None, &lifecycle_ctx())?;

    // PRE round 1
    let decrypted_v1 = pre_roundtrip::<T, SV, PK, PP>(
        &shares_v1,
        t,
        n,
        &agg_pk,
        &enc_cmt,
        &encrypted_secret,
        &rdr_sk,
        &rdr_pk,
        &pub_poly_v1,
    )?;
    assert_eq!(
        decrypted_v1, plaintext,
        "Round 1: PRE decryption must match original plaintext"
    );

    // SIGN round 1
    let signer = S::new();
    sign_roundtrip(&signer, &shares_v1, t, n, &pub_poly_v1, &agg_pk, msg)?;

    // ── Round 2: Reshare (same committee, DealerReceiver) ─────────────────
    let (new_pk, shares_v2, pub_poly_v2) =
        run_reshare_ceremony::<Node, SV, PK, PP, NF>(&node_factory, n, t, &shares_v1, &agg_pk)?;

    // Sanity: reshare PK must equal original (also asserted inside reshare_ceremony)
    {
        let mut pk_bytes = Vec::new();
        let mut agg_bytes = Vec::new();
        new_pk.serialize_compressed(&mut pk_bytes).unwrap();
        agg_pk.serialize_compressed(&mut agg_bytes).unwrap();
        assert_eq!(
            pk_bytes, agg_bytes,
            "Round 2: reshared PK must equal original PK"
        );
    }

    // PRE round 2 — SAME ciphertext, new shares
    let decrypted_v2 = pre_roundtrip::<T, SV, PK, PP>(
        &shares_v2,
        t,
        n,
        &agg_pk,
        &enc_cmt,
        &encrypted_secret,
        &rdr_sk,
        &rdr_pk,
        &pub_poly_v2,
    )?;
    assert_eq!(
        decrypted_v2, plaintext,
        "Round 2: same ciphertext must decrypt after reshare"
    );

    // SIGN round 2
    sign_roundtrip(&signer, &shares_v2, t, n, &pub_poly_v2, &agg_pk, msg)?;

    // ── Round 3: Refresh ──────────────────────────────────────────────────
    let mut refresh_coord = DKGCoordinator::new(node_factory.clone(), n, t)?;
    let (_delta_pk, delta_shares, delta_pub_poly) =
        refresh_coord.run_dkg_with_mode(|_| DkgMode::Refresh)?;

    // Apply delta to get final shares: final_share_i = reshared_share_i + delta_i
    let share_map_v2: HashMap<u32, SV> = shares_v2.iter().map(|s| (s.i, s.v.clone())).collect();
    let delta_map: HashMap<u32, SV> = delta_shares.iter().map(|s| (s.i, s.v.clone())).collect();

    let shares_v3: Vec<PriShare<SV>> = (1..=n as u32)
        .map(|i| PriShare {
            i,
            v: add_shares(&share_map_v2[&i], &delta_map[&i]),
        })
        .collect();

    // Combined pub_poly for verification: reshare_poly + delta_poly (coefficient-wise)
    let pub_poly_v3 = add_pub_poly(&pub_poly_v2, &delta_pub_poly);

    // PRE round 3 — SAME ciphertext, refreshed shares
    let decrypted_v3 = pre_roundtrip::<T, SV, PK, PP>(
        &shares_v3,
        t,
        n,
        &agg_pk,
        &enc_cmt,
        &encrypted_secret,
        &rdr_sk,
        &rdr_pk,
        &pub_poly_v3,
    )?;
    assert_eq!(
        decrypted_v3, plaintext,
        "Round 3: same ciphertext must decrypt after refresh"
    );

    // SIGN round 3
    sign_roundtrip(&signer, &shares_v3, t, n, &pub_poly_v3, &agg_pk, msg)?;

    Ok(())
}
