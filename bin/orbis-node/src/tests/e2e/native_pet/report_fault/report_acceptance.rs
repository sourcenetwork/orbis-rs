use super::Reports;
use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use orbis_reporting::{
    InvalidCryptoResponse, INVALID_CRYPTO_RESPONSE_REPORT_TYPE, PET_BLIND_DECRYPT_RESPONSE_DOMAIN,
};
use serde::Deserialize;
use std::{fs::File, io::Read, time::Duration};
use vera_client::rings::SignedReport;
use vera_domain::NativeTx;
use vera_modules::vera::abi::IVera;

#[derive(Deserialize)]
struct Journal {
    version: u8,
    pending: Option<Bytes>,
}

impl Reports<'_> {
    pub(super) async fn verify_submission(&self, retained_id: &str, accepted_height: u64) {
        let mut matched = false;
        for index in 0..2 {
            let path = self
                .base
                .join(format!("node-{index}/native-vera"))
                .join(hex::encode(self.deployment_root))
                .join("state.json");
            let limit = 2 * vera_domain::MAX_TX_BYTES + 4096;
            let mut bytes = Vec::new();
            File::open(path)
                .unwrap()
                .take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() <= limit, "worker journal exceeds its bound");
            let journal: Journal = serde_json::from_slice(&bytes).expect("worker journal JSON");
            assert_eq!(journal.version, 1);
            let Some(wire) = journal.pending else {
                continue;
            };
            let tx = NativeTx::decode_wire(&wire).expect("retained native submission");
            if tx.target != vera_client::VERA_ADDRESS
                || !tx
                    .calldata
                    .starts_with(&IVera::submitRingReportCall::SELECTOR)
            {
                continue;
            }
            let call = IVera::submitRingReportCall::abi_decode(&tx.calldata).unwrap();
            let signed: SignedReport = serde_json::from_slice(&call.request).unwrap();
            if signed.report_id != retained_id {
                continue;
            }
            let report = signed.report;
            assert_eq!(report.report_id(), retained_id);
            assert_eq!(report.report_type, INVALID_CRYPTO_RESPONSE_REPORT_TYPE);
            assert_eq!(report.ring_id, self.ring_id);
            assert_eq!(report.ring_pk, self.keys.public_key);
            assert_eq!(report.accused_node_key, self.infos[2].node_key);
            assert!(self.infos[..2]
                .iter()
                .any(|node| node.node_key == report.reporter_node_key));
            let InvalidCryptoResponse::PetBlindDecrypt { statement, .. } =
                InvalidCryptoResponse::from_canonical_bytes(&report.payload).unwrap()
            else {
                panic!("accepted report is not PET decrypt evidence")
            };
            assert_eq!(statement.domain, PET_BLIND_DECRYPT_RESPONSE_DOMAIN);
            assert_eq!(statement.domain, "orbis-pet-blind-decrypt-response-v2");
            assert_eq!(statement.responder_node_key, self.infos[2].node_key);
            assert_eq!(statement.ring_id, self.ring_id);
            assert_eq!(statement.attempt_id, report.session_id);
            let id = tx.tx_id().0;
            let proof = tokio::time::timeout(Duration::from_secs(60), async {
                loop {
                    match self.client.read_receipt(id, self.trusted).await {
                        Ok(Some(proof)) => break proof,
                        Ok(None) => (),
                        Err(error) if error.is_throttled() => (),
                        Err(error) => panic!("accepted report receipt proof failed: {error}"),
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("accepted report receipt available within 60 seconds");
            assert_eq!(proof.revision.height, accepted_height);
            assert!(proof.verify(id, self.trusted).unwrap().success());
            matched = true;
        }
        assert!(
            matched,
            "no retained healthy-member submission matches the certified report"
        );
    }
}
