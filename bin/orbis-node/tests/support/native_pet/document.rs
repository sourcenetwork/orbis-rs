use authn::jwt_builder::{create_authenticated_request, JwtSigner};
use crypto::r#trait::{CryptoDeserialize, CryptoSerialize, EncryptionProof, ThresholdDealer};
use proto::v0::{
    pre::{
        pre_service_client::PreServiceClient, InlineDocument, PetTagAttachment,
        ReaderAuthorizationSignature, StartPreRequest,
    },
    store_secret::{store_secret_service_client::StoreSecretServiceClient, StoreSecretRequest},
};
use tonic::transport::Endpoint;
use vera_client::threshold_objects::{EncryptedDocument, ThresholdObject};

pub struct Reader {
    pub signer: JwtSigner,
    chain_id: String,
    secret: crypto::ScalarField,
    public: Vec<u8>,
}

impl Reader {
    pub fn new(chain_id: String) -> Self {
        let signer = JwtSigner::from_key_pair(did_key::generate::<did_key::Ed25519KeyPair>(Some(
            &[92; 32],
        )));
        let (secret, public) = crypto::helpers::generate_keypair().unwrap();
        Self {
            signer,
            chain_id,
            secret,
            public: public.to_bytes().unwrap(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Delivery {
    Stored,
    Inline,
}

pub struct PreChecks<'a> {
    endpoint: Endpoint,
    reader: &'a Reader,
    audit: Option<&'a str>,
}

impl<'a> PreChecks<'a> {
    pub fn new(endpoint: Endpoint, reader: &'a Reader, audit: Option<&'a str>) -> Self {
        Self {
            endpoint,
            reader,
            audit,
        }
    }

    pub fn reconnect(&self, endpoint: Endpoint) -> Self {
        Self::new(endpoint, self.reader, self.audit)
    }

    pub async fn decrypt(&self, document: &Document, delivery: Delivery) {
        document
            .pre(self.endpoint.clone(), self.reader, delivery, self.audit)
            .await
            .unwrap();
    }

    pub async fn denied(&self, document: &Document, delivery: Delivery, expected: tonic::Code) {
        assert_eq!(
            document
                .pre(self.endpoint.clone(), self.reader, delivery, self.audit)
                .await
                .unwrap_err()
                .code(),
            expected
        );
    }
}

pub struct Document {
    pub id: String,
    pub object: ThresholdObject,
    inline: InlineDocument,
    prepared: cli_tool::PreparedSecret,
    plaintext: Vec<u8>,
}

impl Document {
    pub fn new(
        ring_id: &str,
        keys: &vera_client::rings::RingPublicKeys,
        policy: &str,
        owner: &str,
        plaintext: &[u8],
    ) -> Self {
        let pet_pk = keys.pet_public_key.as_ref().unwrap();
        let (tag, randomness) = cli_tool::generate_pet_tag(pet_pk, owner).unwrap();
        let binding = crypto::context::PetTagBinding {
            ring_id: ring_id.into(),
            pet_pk: hex::decode(pet_pk).unwrap(),
            ephemeral_point: tag.ephemeral_point.clone(),
            masked_fingerprint: tag.masked_fingerprint.clone(),
        };
        let prepared = cli_tool::prepare_secret(
            plaintext,
            &keys.public_key,
            None,
            policy.into(),
            "document".into(),
            "read".into(),
            None,
            None,
            None,
            Some(binding),
        )
        .unwrap();
        let pet =
            cli_tool::prove_pet_tag_knowledge(&prepared, ring_id, pet_pk, tag, randomness).unwrap();
        let document = EncryptedDocument {
            ring_id: ring_id.into(),
            document: String::from_utf8(prepared.encrypted_document.clone()).unwrap(),
            proof: EncryptionProof {
                challenge: prepared.challenge.clone(),
                response: prepared.response.clone(),
            }
            .try_into()
            .unwrap(),
            policy_id: policy.into(),
            resource: "document".into(),
            permission: "read".into(),
            tier: None,
            timestamp: None,
            pet_tag: Some(pet.tag.clone().try_into().unwrap()),
            pet_tag_proof: Some(pet.tag_proof.clone().try_into().unwrap()),
        };
        let id = common::blockchain::orbis::generate_document_id(
            &document.ring_id,
            &document.document,
            &document.proof,
            &document.policy_id,
            &document.resource,
            &document.permission,
            None,
            None,
            document.pet_tag.as_deref(),
            document.pet_tag_proof.as_deref(),
        )
        .unwrap();
        let object = ThresholdObject::Document(document);
        assert_eq!(object.id().unwrap(), id);
        let inline = InlineDocument {
            ring_id: ring_id.into(),
            encrypted_document: prepared.encrypted_document.clone(),
            enc_cmt: prepared.enc_cmt.clone(),
            policy_id: policy.into(),
            resource: "document".into(),
            permission: "read".into(),
            challenge: prepared.challenge.clone(),
            response: prepared.response.clone(),
            tier: None,
            timestamp: None,
            pet_tag: Some(PetTagAttachment {
                ephemeral_point: pet.tag.ephemeral_point,
                masked_fingerprint: pet.tag.masked_fingerprint,
                knowledge_proof_challenge: pet.tag_proof.challenge,
                knowledge_proof_response: pet.tag_proof.response,
            }),
        };
        Self {
            id,
            object,
            inline,
            prepared,
            plaintext: plaintext.to_vec(),
        }
    }

    pub async fn store(&self, endpoint: Endpoint, reader: &Reader) {
        let d = &self.inline;
        let tag = d.pet_tag.as_ref().unwrap();
        let token = reader
            .signer
            .create_store_secret_jwt(
                &d.encrypted_document,
                d.enc_cmt.clone(),
                &d.ring_id,
                &d.policy_id,
                &d.resource,
                &d.permission,
                d.challenge.clone(),
                d.response.clone(),
                false,
                None,
                None,
            )
            .unwrap();
        let request = create_authenticated_request(
            StoreSecretRequest {
                encrypted_document: d.encrypted_document.clone(),
                enc_cmt: d.enc_cmt.clone(),
                ring_id: d.ring_id.clone(),
                policy_id: d.policy_id.clone(),
                resource: d.resource.clone(),
                permission: d.permission.clone(),
                challenge: d.challenge.clone(),
                response: d.response.clone(),
                with_proof: false,
                tier: None,
                timestamp: None,
                pet_tag: Some(proto::v0::store_secret::PetTagAttachment {
                    ephemeral_point: tag.ephemeral_point.clone(),
                    masked_fingerprint: tag.masked_fingerprint.clone(),
                    knowledge_proof_challenge: tag.knowledge_proof_challenge.clone(),
                    knowledge_proof_response: tag.knowledge_proof_response.clone(),
                }),
            },
            &token,
        )
        .unwrap();
        let response = StoreSecretServiceClient::connect(endpoint)
            .await
            .unwrap()
            .store_secret(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.object_id, self.id);
    }

    async fn pre(
        &self,
        endpoint: Endpoint,
        reader: &Reader,
        delivery: Delivery,
        audit: Option<&str>,
    ) -> Result<(), tonic::Status> {
        let (token, token_metadata) = reader
            .signer
            .create_pre_jwt(reader.public.clone(), &self.id, None, None)
            .unwrap();
        let authorization_context = crypto::context::ReaderAuthorizationContext {
            chain_id: reader.chain_id.clone(),
            ring_pk: self.prepared.context.ring_pk.clone(),
            jwt_issuer: reader.signer.did_uri.clone(),
            jwt_subject: None,
            resolved_actor: reader.signer.did_uri.clone(),
            jwt_id: token_metadata.jwt_id,
            jwt_issued_time: token_metadata.issued_time,
            jwt_expiration_time: token_metadata.expiration_time,
            jwt_not_before: token_metadata.not_before,
            object_id: self.id.clone(),
            recipient_pk: reader.public.clone(),
            derivation: None,
            salt: None,
            valid_window: None,
            audit_target_object_id: audit.map(str::to_owned),
        };
        let reader_public = crypto::GroupAffine::from_bytes(&reader.public).unwrap();
        let signature = crypto::PreImpl::sign_reader_authorization(
            &reader.secret,
            &reader_public,
            &authorization_context,
        )
        .unwrap();
        let request = create_authenticated_request(
            StartPreRequest {
                rdr_pk: reader.public.clone(),
                object_id: self.id.clone(),
                derivation: None,
                salt: None,
                valid_window: None,
                document: matches!(delivery, Delivery::Inline).then(|| self.inline.clone()),
                audit_target_object_id: audit.map(str::to_owned),
                rdr_pk_signature: Some(ReaderAuthorizationSignature {
                    challenge: signature.challenge,
                    response: signature.response,
                }),
            },
            &token,
        )
        .unwrap();
        let response = PreServiceClient::connect(endpoint)
            .await
            .unwrap()
            .start_pre(request)
            .await?
            .into_inner();
        let value: serde_json::Value = serde_json::from_slice(&response.encrypted_secret).unwrap();
        let point = crypto::GroupAffine::from_bytes(
            &hex::decode(value["xnc_cmt"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let key = crypto::GroupAffine::from_bytes(&self.prepared.context.ring_pk).unwrap();
        let secret = serde_json::from_slice(&self.prepared.encrypted_document).unwrap();
        assert_eq!(
            crypto::PreImpl::decrypt_secret(
                &key,
                &point,
                &reader.secret,
                &secret,
                &self.prepared.context
            )
            .unwrap(),
            self.plaintext
        );
        Ok(())
    }
}
