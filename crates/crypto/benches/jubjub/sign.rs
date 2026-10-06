use crypto::jubjub::common::Fr;

use crypto::jubjub::dkg::DKGNode;
use crypto::jubjub::sign::ThresholdJubjubSigner;
use crypto::r#trait::{DistKeyShare, Dkg, ThresholdSigner};
use crypto::test_helper::DKGCoordinator;

use crate::{SignBenchFixture, SignBenchSetup, MSG};

pub struct JubjubSignBench;

impl SignBenchSetup for JubjubSignBench {
    type Signer = ThresholdJubjubSigner;

    fn create_fixture(t: usize, n: usize) -> SignBenchFixture<ThresholdJubjubSigner> {
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

        let signer = ThresholdJubjubSigner::new();

        // FROST is interactive: Round 1 generates nonce commitments and secret state.
        let mut commitments: Vec<(
            u32,
            <ThresholdJubjubSigner as ThresholdSigner>::NonceCommitment,
        )> = Vec::with_capacity(t);
        let mut signing_states: Vec<<ThresholdJubjubSigner as ThresholdSigner>::SigningState> =
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
                .sign(
                    dks,
                    MSG,
                    &pub_poly,
                    Some(&signing_states[i]),
                    &commitments,
                    None,
                    None,
                )
                .unwrap();
            sig_shares.push(share);
        }

        // Recover the full signature
        let full_sig = signer
            .recover(&sig_shares, t, n, &aggregate_pk, MSG, &commitments)
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
