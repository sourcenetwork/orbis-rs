//! Generic test suite for `ThresholdSigner` implementations.
//!
//! Mirrors the structure of `dkg_tests.rs` and `pre_tests.rs`.
//! Invoke via the impl-specific `sign_tests.rs` wrappers.

use crate::error::Result;
use crate::r#trait::{DistKeyShare, PriShare, PubPoly as PubPolyTrait, ThresholdSigner};

// ============================================================================
// Public entry point
// ============================================================================

/// Run every generic `ThresholdSigner` test.
///
/// # Type parameters
/// * `T`  – the signer implementation
/// * `SV` – scalar / share-value type (`T::ShareValue`)
/// * `PK` – public-key type (`T::PublicKey`)
/// * `PP` – public-polynomial type (`T::PubPoly`)
/// * `MK` – factory for a random `(secret_key, public_key)` pair
/// * `MP` – factory for a `PP` from a list of `PK` commitments
/// * `RD` – runs a full DKG and returns `(agg_pk, shares, pub_poly)`
/// * `TS` – mutates a `T::SigShare` to an invalid value (for tamper tests)
pub fn run_all_tests<T, SV, PK, PP, MK, MP, RD, TS>(
    make_keypair: MK,
    make_pub_poly: MP,
    run_dkg: RD,
    tamper_sig_share: TS,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK) + Clone,
    MP: Fn(Vec<PK>) -> PP + Clone,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)> + Clone,
    TS: Fn(&mut T::SigShare) + Clone,
{
    let signer = T::new();

    // Single-key tests (no DKG needed)
    test_sign_verify_single_key(&signer, make_keypair.clone(), make_pub_poly.clone())?;
    test_wrong_message_fails(&signer, make_keypair.clone(), make_pub_poly.clone())?;
    test_wrong_key_fails(&signer, make_keypair.clone(), make_pub_poly.clone())?;
    test_empty_message(&signer, make_keypair.clone(), make_pub_poly.clone())?;
    test_large_message(&signer, make_keypair.clone(), make_pub_poly.clone())?;

    // DKG-based tests
    test_full_flow_3_of_5(&signer, run_dkg.clone())?;
    test_single_key_threshold_1(&signer, run_dkg.clone())?;
    test_different_subsets_valid(&signer, run_dkg.clone())?;
    test_insufficient_shares(&signer, run_dkg.clone())?;
    test_tampered_share_rejected(&signer, run_dkg.clone(), tamper_sig_share.clone())?;

    Ok(())
}

// ============================================================================
// Sign-round helper
// ============================================================================

/// Run a complete sign round (nonce generation + signing) for the given participants.
///
/// Works for both interactive (FROST) and non-interactive (BLS) signers — BLS simply
/// ignores the nonce commitments and signing state.
fn run_sign_round<T>(
    signer: &T,
    participants: &[&PriShare<T::ShareValue>],
    pub_poly: &T::PubPoly,
    msg: &[u8],
) -> Result<(Vec<T::SigShare>, Vec<(u32, T::NonceCommitment)>)>
where
    T: ThresholdSigner<DistKeyShare = DistKeyShare<<T as ThresholdSigner>::ShareValue>>,
    T::ShareValue: Clone,
    T::NonceCommitment: Clone,
{
    // Round 1: generate nonces / commitments for every participant
    let mut commitments: Vec<(u32, T::NonceCommitment)> = Vec::new();
    let mut signing_states: Vec<T::SigningState> = Vec::new();

    for share in participants {
        let dks = DistKeyShare {
            pri_share: (*share).clone(),
        };
        let (commitment, state) = signer.generate_nonces(&dks)?;
        commitments.push((share.i, commitment));
        signing_states.push(state);
    }

    // Round 2: sign
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
        )?;
        sig_shares.push(sig_share);
    }

    Ok((sig_shares, commitments))
}

// ============================================================================
// Single-key tests
// ============================================================================

pub fn test_sign_verify_single_key<T, SV, PK, PP, MK, MP>(
    signer: &T,
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (sk, pk) = make_keypair();
    let pub_poly = make_pub_poly(vec![pk.clone()]);
    let share = PriShare { i: 1, v: sk };
    let msg = b"Hello, threshold signing!";

    let (sig_shares, commitments) = run_sign_round(signer, &[&share], &pub_poly, msg)?;
    let sig = signer
        .recover(&sig_shares, 1, 1, msg, &commitments)?
        .expect("should recover a signature from single key");

    signer.verify(&pk, msg, &sig)?;

    Ok(())
}

pub fn test_wrong_message_fails<T, SV, PK, PP, MK, MP>(
    signer: &T,
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (sk, pk) = make_keypair();
    let pub_poly = make_pub_poly(vec![pk.clone()]);
    let share = PriShare { i: 1, v: sk };
    let msg = b"correct message";

    let (sig_shares, commitments) = run_sign_round(signer, &[&share], &pub_poly, msg)?;
    let sig = signer
        .recover(&sig_shares, 1, 1, msg, &commitments)?
        .expect("should recover");

    assert!(signer.verify(&pk, msg, &sig).is_ok());
    assert!(
        signer.verify(&pk, b"wrong message", &sig).is_err(),
        "should fail with wrong message"
    );

    Ok(())
}

pub fn test_wrong_key_fails<T, SV, PK, PP, MK, MP>(
    signer: &T,
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (sk, pk) = make_keypair();
    let (_, wrong_pk) = make_keypair();
    let pub_poly = make_pub_poly(vec![pk.clone()]);
    let share = PriShare { i: 1, v: sk };
    let msg = b"test message";

    let (sig_shares, commitments) = run_sign_round(signer, &[&share], &pub_poly, msg)?;
    let sig = signer
        .recover(&sig_shares, 1, 1, msg, &commitments)?
        .expect("should recover");

    assert!(
        signer.verify(&wrong_pk, msg, &sig).is_err(),
        "should fail with wrong public key"
    );

    Ok(())
}

pub fn test_empty_message<T, SV, PK, PP, MK, MP>(
    signer: &T,
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (sk, pk) = make_keypair();
    let pub_poly = make_pub_poly(vec![pk.clone()]);
    let share = PriShare { i: 1, v: sk };
    let msg = b"";

    let (sig_shares, commitments) = run_sign_round(signer, &[&share], &pub_poly, msg)?;
    let sig = signer
        .recover(&sig_shares, 1, 1, msg, &commitments)?
        .expect("should recover for empty message");

    signer.verify(&pk, msg, &sig)?;

    Ok(())
}

pub fn test_large_message<T, SV, PK, PP, MK, MP>(
    signer: &T,
    make_keypair: MK,
    make_pub_poly: MP,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    MK: Fn() -> (SV, PK),
    MP: Fn(Vec<PK>) -> PP,
{
    let (sk, pk) = make_keypair();
    let pub_poly = make_pub_poly(vec![pk.clone()]);
    let share = PriShare { i: 1, v: sk };
    let msg = vec![0xABu8; 10_000];

    let (sig_shares, commitments) = run_sign_round(signer, &[&share], &pub_poly, &msg)?;
    let sig = signer
        .recover(&sig_shares, 1, 1, &msg, &commitments)?
        .expect("should recover for large message");

    signer.verify(&pk, &msg, &sig)?;

    Ok(())
}

// ============================================================================
// DKG-based tests
// ============================================================================

pub fn test_full_flow_3_of_5<T, SV, PK, PP, RD>(signer: &T, run_dkg: RD) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
{
    let n = 5;
    let t = 3;
    let (agg_pk, shares, pub_poly) = run_dkg(n, t)?;
    assert_eq!(shares.len(), n);

    let msg = b"Threshold signature test!";
    let participants: Vec<_> = shares.iter().take(t).collect();
    let (sig_shares, commitments) = run_sign_round(signer, &participants, &pub_poly, msg)?;

    // Every individual share should verify
    for share in &sig_shares {
        signer
            .verify_share(msg, &pub_poly, share, &commitments, None)
            .expect("each sig share should verify");
    }

    let sig = signer
        .recover(&sig_shares, t, n, msg, &commitments)?
        .expect("should recover full signature");

    signer.verify(&agg_pk, msg, &sig)?;

    Ok(())
}

pub fn test_single_key_threshold_1<T, SV, PK, PP, RD>(signer: &T, run_dkg: RD) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
{
    let n = 3;
    let t = 1;
    let (agg_pk, shares, pub_poly) = run_dkg(n, t)?;

    let msg = b"threshold-1 test";
    let (sig_shares, commitments) = run_sign_round(signer, &[&shares[0]], &pub_poly, msg)?;

    assert!(signer
        .verify_share(msg, &pub_poly, &sig_shares[0], &commitments, None)
        .is_ok());

    let sig = signer
        .recover(&sig_shares, t, n, msg, &commitments)?
        .expect("should recover with threshold 1");

    signer.verify(&agg_pk, msg, &sig)?;

    Ok(())
}

pub fn test_different_subsets_valid<T, SV, PK, PP, RD>(signer: &T, run_dkg: RD) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
{
    let n = 5;
    let t = 3;
    let (agg_pk, shares, pub_poly) = run_dkg(n, t)?;

    let msg = b"Different subsets test";

    // Subset {0, 1, 2}
    let p1: Vec<_> = shares.iter().take(3).collect();
    let (s1, cmts1) = run_sign_round(signer, &p1, &pub_poly, msg)?;
    let sig1 = signer
        .recover(&s1, t, n, msg, &cmts1)?
        .expect("should recover from subset {0,1,2}");

    // Subset {2, 3, 4}
    let p2: Vec<_> = shares.iter().skip(2).take(3).collect();
    let (s2, cmts2) = run_sign_round(signer, &p2, &pub_poly, msg)?;
    let sig2 = signer
        .recover(&s2, t, n, msg, &cmts2)?
        .expect("should recover from subset {2,3,4}");

    // Both must produce valid signatures against the aggregate key
    signer.verify(&agg_pk, msg, &sig1)?;
    signer.verify(&agg_pk, msg, &sig2)?;

    Ok(())
}

pub fn test_insufficient_shares<T, SV, PK, PP, RD>(signer: &T, run_dkg: RD) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
{
    let n = 3;
    let t = 2;
    let (_agg_pk, shares, pub_poly) = run_dkg(n, t)?;

    let msg = b"insufficient shares test";

    // Only 1 participant signs, but threshold is 2
    let (sig_shares, commitments) = run_sign_round(signer, &[&shares[0]], &pub_poly, msg)?;

    let result = signer.recover(&sig_shares, t, n, msg, &commitments)?;
    assert!(
        result.is_none(),
        "should return None with insufficient shares"
    );

    Ok(())
}

pub fn test_tampered_share_rejected<T, SV, PK, PP, RD, TS>(
    signer: &T,
    run_dkg: RD,
    tamper_sig_share: TS,
) -> Result<()>
where
    T: ThresholdSigner<
        ShareValue = SV,
        PublicKey = PK,
        PubPoly = PP,
        DistKeyShare = DistKeyShare<SV>,
    >,
    T::SigShare: Clone,
    T::NonceCommitment: Clone,
    SV: Clone,
    PK: Clone,
    PP: PubPolyTrait<PublicKey = PK>,
    RD: Fn(usize, usize) -> Result<(PK, Vec<PriShare<SV>>, PP)>,
    TS: Fn(&mut T::SigShare),
{
    let n = 3;
    let t = 2;
    let (_agg_pk, shares, pub_poly) = run_dkg(n, t)?;

    let msg = b"tamper test";
    let participants: Vec<_> = shares.iter().take(t).collect();
    let (mut sig_shares, commitments) = run_sign_round(signer, &participants, &pub_poly, msg)?;

    // Tamper the first share using the impl-supplied closure
    tamper_sig_share(&mut sig_shares[0]);

    assert!(
        signer
            .verify_share(msg, &pub_poly, &sig_shares[0], &commitments, None)
            .is_err(),
        "tampered share should not verify"
    );

    Ok(())
}
