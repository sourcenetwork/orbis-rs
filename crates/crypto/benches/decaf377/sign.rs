use decaf377::Fr;

use crypto::decaf377::dkg::DKGNode;
use crypto::decaf377::sign::ThresholdDecafSigner;
use crypto::r#trait::{DistKeyShare, Dkg, ThresholdSigner};
use crypto::test_helper::DKGCoordinator;

use crate::{SignBenchFixture, SignBenchSetup, MSG};

pub struct Decaf377SignBench;

impl SignBenchSetup for Decaf377SignBench {
    type Signer = ThresholdDecafSigner;

    fn create_fixture(t: usize, n: usize) -> SignBenchFixture<ThresholdDecafSigner> {
        let mut coordinator = DKGCoordinator::new(
            |id: u32, threshold: usize, total_nodes: usize| {
                <DKGNode as Dkg>::new(id, threshold, total_nodes)
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

        let signer = ThresholdDecafSigner::new();

        // FROST is interactive: Round 1 generates nonce commitments and secret state.
        let mut commitments: Vec<(
            u32,
            <ThresholdDecafSigner as ThresholdSigner>::NonceCommitment,
        )> = Vec::with_capacity(t);
        let mut signing_states: Vec<<ThresholdDecafSigner as ThresholdSigner>::SigningState> =
            Vec::with_capacity(t);

        for (i, dks) in dist_key_shares.iter().enumerate() {
            let (commitment, state) = signer.generate_nonces(dks).unwrap();
            commitments.push((participant_ids[i], commitment));
            signing_states.push(state);
        }

        // Pre-compute signature shares using the stored nonces
        let mut sig_shares = Vec::with_capacity(t);
        for (i, dks) in dist_key_shares.iter().enumerate() {
            let share = signer
                .sign(dks, MSG, &pub_poly, Some(&signing_states[i]), &commitments)
                .unwrap();
            sig_shares.push(share);
        }

        // Recover the full signature
        let full_sig = signer
            .recover(&sig_shares, t, n, MSG, &commitments)
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
