use decaf377::{Element, Fr};
use rand_core::OsRng;

use crypto::decaf377::pre::ThresholdDealerNode;
use crypto::r#trait::{DistKeyShare, PubShare, ThresholdDealer};
use crypto::test_helper::DKGCoordinator;

use crate::{BenchFixture, BenchSetup};

pub struct Decaf377Bench;

impl BenchSetup for Decaf377Bench {
    type Dealer = ThresholdDealerNode;

    fn create_fixture(t: usize, n: usize) -> BenchFixture<ThresholdDealerNode> {
        let mut coordinator = DKGCoordinator::new(
            |id: u32,
             threshold: usize,
             total_nodes: usize,
             session_id: u64,
             role: crypto::r#trait::DkgRole| {
                <crypto::decaf377::dkg::DKGNode as crypto::r#trait::Dkg>::new(
                    id,
                    threshold,
                    total_nodes,
                    session_id,
                    role,
                )
            },
            n,
            t,
        )
        .unwrap();
        let (aggregate_pk, secret_shares, pub_poly) = coordinator.run_dkg().unwrap();

        let mut rng = OsRng;
        let rdr_sk = Fr::rand(&mut rng);
        let rdr_pk = Element::GENERATOR * rdr_sk;

        let data = b"benchmark secret payload - 36 bytes!";
        let (enc_cmt, secret, proof) =
            ThresholdDealerNode::encrypt_secret(&aggregate_pk, data, None, None).unwrap();

        let dealer = ThresholdDealerNode::new();
        let dist_key_shares: Vec<DistKeyShare<Fr>> = secret_shares
            .into_iter()
            .map(|s| DistKeyShare { pri_share: s })
            .collect();

        // Pre-compute reencrypt replies and pub_shares
        let mut pub_shares = Vec::with_capacity(t);
        let mut replies = Vec::with_capacity(t);
        for dks in dist_key_shares.iter().take(t) {
            let reply = dealer.reencrypt(dks, &secret, &rdr_pk, None).unwrap();
            pub_shares.push(reply.share.clone());
            replies.push(reply);
        }
        let reencrypt_reply = replies.swap_remove(0);

        let xnc_cmt = dealer.recover(&pub_shares, t, n).unwrap().unwrap();

        BenchFixture {
            dealer,
            aggregate_pk,
            pub_poly,
            dist_key_shares,
            rdr_sk,
            rdr_pk,
            enc_cmt,
            secret,
            proof,
            reencrypt_reply,
            pub_shares,
            xnc_cmt,
            t,
            n,
        }
    }

    fn extract_pub_share(
        reply: &<ThresholdDealerNode as ThresholdDealer>::ReencryptReply,
    ) -> PubShare<Element> {
        reply.share.clone()
    }
}
