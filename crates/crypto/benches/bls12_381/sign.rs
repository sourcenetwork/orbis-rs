use ark_bls12_381::Fr;

use crypto::bls12_381::dkg::DKGNode;
use crypto::bls12_381::sign::ThresholdBlsSigner;
use crypto::r#trait::{DistKeyShare, Dkg, ThresholdSigner};
use crypto::test_helper::DKGCoordinator;

use crate::{SignBenchFixture, SignBenchSetup, MSG};

pub struct Bls12381SignBench;

impl SignBenchSetup for Bls12381SignBench {
    type Signer = ThresholdBlsSigner;

    fn create_fixture(t: usize, n: usize) -> SignBenchFixture<ThresholdBlsSigner> {
        let mut coordinator = DKGCoordinator::new(
            |id: u32,
             threshold: usize,
             total_nodes: usize,
             session_id: u128,
             role: crypto::r#trait::DkgRole| {
                <DKGNode as Dkg>::new(id, threshold, total_nodes, session_id, role)
            },
            n,
            t,
        )
        .unwrap();
        let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

        let dist_key_shares: Vec<DistKeyShare<Fr>> = secret_shares
            .iter()
            .take(t)
            .map(|s| DistKeyShare {
                pri_share: s.clone(),
            })
            .collect();

        let participant_ids: Vec<u32> = secret_shares.iter().take(t).map(|s| s.i).collect();

        let signer = ThresholdBlsSigner::new();

        // BLS is non-interactive: no nonce commitments or signing state.
        let commitments: Vec<(
            u32,
            <ThresholdBlsSigner as ThresholdSigner>::NonceCommitment,
        )> = Vec::new();
        let signing_states: Vec<<ThresholdBlsSigner as ThresholdSigner>::SigningState> = Vec::new();

        // Pre-compute signature shares
        let mut sig_shares = Vec::with_capacity(t);
        for dks in &dist_key_shares {
            let share = signer
                .sign(dks, MSG, &pub_poly, None, &[], None, None)
                .unwrap();
            sig_shares.push(share);
        }

        // Recover the full signature
        let full_sig = signer
            .recover(&sig_shares, t, n, &aggregate_pk, MSG, &[])
            .unwrap()
            .unwrap();

        SignBenchFixture {
            signer,
            aggregate_pk,
            pub_poly,
            dist_key_shares,
            participant_ids,
            commitments,
            signing_states,
            sig_shares,
            full_sig,
            t,
            n,
        }
    }
}
