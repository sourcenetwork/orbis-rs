use super::super::native_workflow::NativeWorkflow;
use super::{endpoint, unix_now, Reader};
use authn::jwt_builder::create_authenticated_request;
use crypto::r#trait::{CryptoDeserialize, ThresholdSigner};
use proto::v0::sign::{sign_service_client::SignServiceClient, StartSignRequest};
use vera_client::{
    create_scoped_bearer_token,
    rings::RingPublicKeys,
    threshold_objects::{encode_threshold_object, KeyDerivation, ThresholdObject},
    DelegationScope,
};

pub(super) struct Signing {
    pub(super) id: String,
    ring_key: crypto::GroupAffine,
    derived_key: crypto::GroupAffine,
}

impl Signing {
    pub(super) async fn create(
        workflow: &NativeWorkflow,
        keys: &RingPublicKeys,
        derivation: &str,
    ) -> Self {
        let derivation = KeyDerivation {
            ring_id: workflow.ring_id.clone(),
            derivation: derivation.into(),
            policy_id: workflow.policy.clone(),
            resource: "document".into(),
            permission: "read".into(),
        };
        let object = ThresholdObject::KeyDerivation(derivation.clone());
        let id = object.id().unwrap();
        let now = unix_now();
        let token = create_scoped_bearer_token(
            &workflow.controller,
            workflow.worker.did(),
            workflow.deployment,
            now,
            now + 300,
            DelegationScope::StoreThresholdObject,
        )
        .unwrap();
        super::submit(
            &workflow.client,
            &workflow.worker,
            &workflow.trusted,
            encode_threshold_object(&object, &token).unwrap(),
            "store key derivation",
            &workflow.cluster,
        )
        .await;
        let ring_key =
            crypto::GroupAffine::from_bytes(&hex::decode(&keys.public_key).unwrap()).unwrap();
        let metadata = crypto::SignImpl::encode_metadata(&workflow.policy, "document", "read");
        let derived_key = crypto::SignImpl::derive_public_key(
            &ring_key,
            derivation.derivation.as_bytes(),
            Some(&metadata),
        )
        .unwrap();
        Self {
            id,
            ring_key,
            derived_key,
        }
    }

    async fn request(
        &self,
        address: &str,
        reader: &Reader,
        cycle: u64,
    ) -> Result<proto::v0::sign::StartSignResponse, tonic::Status> {
        let message = cycle.to_le_bytes().to_vec();
        let token = reader.signer.create_sign_jwt(&self.id, &message).unwrap();
        let request = create_authenticated_request(
            StartSignRequest {
                message,
                derivation_id: self.id.clone(),
                valid_window: None,
            },
            &token,
        )
        .unwrap();
        Ok(SignServiceClient::connect(endpoint(address))
            .await
            .unwrap()
            .start_sign(request)
            .await?
            .into_inner())
    }

    pub(super) async fn verify(&self, address: &str, reader: &Reader, cycle: u64) {
        let signed = self.request(address, reader, cycle).await.unwrap();
        let signature = <crypto::SignImpl as ThresholdSigner>::Signature::from_bytes(
            &hex::decode(signed.signature).unwrap(),
        )
        .unwrap();
        let message = cycle.to_le_bytes();
        crypto::SignImpl::new()
            .verify(&self.derived_key, &message, &signature)
            .unwrap();
        assert!(crypto::SignImpl::new()
            .verify(&self.ring_key, &message, &signature)
            .is_err());
    }

    pub(super) async fn denied(&self, address: &str, reader: &Reader, cycle: u64) {
        assert_eq!(
            self.request(address, reader, cycle)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
}
