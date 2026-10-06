use super::{endpoint, Delivery, Document, PreChecks};
use crypto::r#trait::CryptoDeserialize as _;
use proto::{
    info_service::GetNodeInfoResponse,
    unsafe_testing::{
        unsafe_testing_service_client::UnsafeTestingServiceClient, GetLocalStorageRequest,
        LocalStorageAccessMode, LocalStorageKey, LocalStorageKeyType, SetPetDecryptFaultRequest,
    },
};
use std::{path::Path, time::Duration};

#[path = "report_acceptance.rs"]
mod report_acceptance;
use vera_client::{rings::RingPublicKeys, ClientError, ModuleId, VeraClient, RECORD_PROOF_BYTES};
use vera_domain::ConsensusPublicKey;
use vera_harness::cluster::TestCluster;

pub struct Reports<'a> {
    pub cluster: &'a TestCluster,
    pub client: &'a VeraClient,
    pub trusted: &'a ConsensusPublicKey,
    pub addresses: &'a [String],
    pub infos: &'a [GetNodeInfoResponse],
    pub ring_id: &'a str,
    pub keys: &'a RingPublicKeys,
    pub base: &'a Path,
    pub deployment_root: &'a [u8; 32],
}

impl Reports<'_> {
    pub async fn run(&self, checks: &PreChecks<'_>, document: &Document) {
        assert_eq!(self.infos.len(), 3);
        let minimum = self
            .client
            .read_finalized_revision(1, self.trusted)
            .await
            .unwrap()
            .height;
        self.read_state_retry(self.client, minimum, 0).await;
        let before = self.bundles().await;
        let mut control = UnsafeTestingServiceClient::connect(endpoint(&self.addresses[2]))
            .await
            .unwrap();
        control
            .set_pet_decrypt_fault(SetPetDecryptFaultRequest {
                ring_id: self.ring_id.into(),
                enabled: true,
            })
            .await
            .unwrap();
        // Exactly one request: a successful PRE still requires the two honest decrypt shares.
        checks.decrypt(document, Delivery::Inline).await;

        let accepted_height = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match self
                    .client
                    .read_threshold_node_demerits(
                        self.ring_id,
                        &self.infos[2].node_key,
                        minimum,
                        self.trusted,
                    )
                    .await
                {
                    Ok(response) => {
                        if let Some(score) = response.record {
                            assert_eq!(
                                score.points, 1,
                                "one fault must produce exactly one demerit"
                            );
                            break score.revision.block_height;
                        }
                    }
                    Err(error) if error.is_throttled() => (),
                    Err(error) => panic!("report score proof failed: {error}"),
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("signed PET fault must reach certified native state within 60 seconds");
        // The faulty reply may arrive in the coordinator's post-threshold drain.
        control
            .set_pet_decrypt_fault(SetPetDecryptFaultRequest {
                ring_id: self.ring_id.into(),
                enabled: false,
            })
            .await
            .unwrap();
        assert!(
            before == self.bundles().await,
            "fault changed encrypted main/PET bundles"
        );
        let mut report_id = None;
        for node in 0..self.cluster.node_count() {
            let client = VeraClient::new(self.cluster.node(node).rpc_url());
            let observed = self.read_state_retry(&client, accepted_height, 1).await;
            if let Some(expected) = &report_id {
                assert_eq!(&observed, expected, "replicas disagree on retained report");
            } else {
                report_id = Some(observed);
            }
        }
        let report_id = report_id.flatten().expect("one certified retained report");
        self.verify_submission(&report_id, accepted_height).await;
        eprintln!(
            "native PET phase=fault-report accepted_height={accepted_height} replicas=4 accused_demerits=1 retained_sessions=1 bundles_unchanged=true"
        );
    }

    async fn bundles(&self) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        let main_key =
            crypto::GroupAffine::from_bytes(&hex::decode(&self.keys.public_key).unwrap())
                .unwrap()
                .to_string();
        for address in self.addresses {
            let mut client = UnsafeTestingServiceClient::connect(endpoint(address))
                .await
                .unwrap();
            for (kind, key) in [
                (LocalStorageKeyType::RingKey, main_key.as_str()),
                (LocalStorageKeyType::PetRingKey, self.ring_id),
            ] {
                let value = client
                    .get_local_storage(GetLocalStorageRequest {
                        key: Some(LocalStorageKey {
                            key_type: kind as i32,
                            ring_key: key.into(),
                        }),
                        access_mode: LocalStorageAccessMode::Encrypted as i32,
                    })
                    .await
                    .unwrap()
                    .into_inner();
                assert!(
                    value.found && !value.value.is_empty(),
                    "missing encrypted key bundle"
                );
                values.push(value.value);
            }
        }
        values
    }

    async fn read_state_retry(
        &self,
        client: &VeraClient,
        minimum: u64,
        points: u64,
    ) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                match self.read_state(client, minimum, points).await {
                    Ok(report) => break report,
                    Err(error) if error.is_throttled() => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(error) => panic!("report retention or score proof failed: {error}"),
                }
            }
        })
        .await
        .expect("certified report state must be available within 60 seconds")
    }

    async fn read_state(
        &self,
        client: &VeraClient,
        minimum: u64,
        points: u64,
    ) -> Result<Option<String>, ClientError> {
        for (index, info) in self.infos.iter().enumerate() {
            let response = client
                .read_threshold_node_demerits(self.ring_id, &info.node_key, minimum, self.trusted)
                .await?;
            if index == 2 && points > 0 {
                assert_eq!(
                    response.record.expect("accused score missing").points,
                    points
                );
            } else {
                assert!(response.record.is_none(), "healthy member has a demerit");
            }
        }
        let prefix = format!("orbis/reports/v1/{}/", self.ring_id).into_bytes();
        let response = client
            .read_current_prefix(
                ModuleId::Vera,
                &prefix,
                minimum,
                self.trusted,
                RECORD_PROOF_BYTES,
            )
            .await?;
        let proof = response
            .verify(
                ModuleId::Vera,
                &prefix,
                minimum,
                self.trusted,
                RECORD_PROOF_BYTES,
            )
            .expect("complete report prefix verification");
        if points == 0 {
            assert!(
                proof.entries.is_empty(),
                "unexpected report before fault injection"
            );
            return Ok(None);
        }
        assert_eq!(
            proof.entries.len(),
            3,
            "one report needs count, session and expiry entries"
        );
        let count_key = [prefix.as_slice(), b"count"].concat();
        let count = proof
            .entries
            .iter()
            .find(|entry| entry.key == count_key)
            .unwrap();
        assert_eq!(count.value.as_ref(), 1u32.to_be_bytes());
        let session_prefix = [prefix.as_slice(), b"session/"].concat();
        let sessions: Vec<_> = proof
            .entries
            .iter()
            .filter(|entry| entry.key.starts_with(&session_prefix))
            .collect();
        assert_eq!(sessions.len(), 1);
        let session = sessions[0];
        assert_eq!(session.key.len(), session_prefix.len() + 64);
        assert_eq!(session.value.len(), 72);
        let session_id = &session.key[session_prefix.len()..];
        let report_id = &session.value[8..];
        for encoded in [session_id, report_id] {
            assert!(encoded
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
        }
        let expiry = u64::from_be_bytes(session.value[..8].try_into().unwrap());
        assert!(
            expiry > response.revision.timestamp,
            "report retention already expired"
        );
        let expiry_key = [
            prefix.as_slice(),
            b"expiry/",
            &session.value[..8],
            session_id,
        ]
        .concat();
        let index = proof
            .entries
            .iter()
            .find(|entry| entry.key == expiry_key)
            .unwrap();
        assert!(index.value.is_empty());
        Ok(Some(String::from_utf8(report_id.to_vec()).unwrap()))
    }
}
