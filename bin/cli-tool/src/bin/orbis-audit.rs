//! Bounded JSON executable interface for audit clients and the Bankd intermediary.
use anyhow::{ensure, Result};
use bulletin::{lakey::Evaluation, r#trait::RingPayload};
use cli_tool::lakey::{self, EncryptedCollection, NodeEndpoint, RegistrationStatement};
use crypto::{
    lakey::Identity,
    r#trait::{ReaderKeyProof, ThresholdDealer},
    CryptoDeserialize, CryptoSerialize, GroupAffine, PreImpl, ScalarField,
};
use serde::Deserialize;
use std::io::{Read, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u32,
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Capabilities {},
    AuthenticationIdentity {
        authentication_seed: [u8; 32],
    },
    RegistrationObject {
        identity: Identity,
    },
    ReadRing {
        chain: common::blockchain::ChainConfig,
        ring_id: String,
    },
    GenerateReader {},
    VerifyReader {
        reader: Vec<u8>,
        proof: ReaderKeyProof,
    },
    Evaluate {
        ring: RingPayload,
        nodes: Vec<NodeEndpoint>,
        identity: Identity,
        session: [u8; 32],
        authentication_seed: [u8; 32],
    },
    VerifyRegistration {
        ring: RingPayload,
        identity: Identity,
        evaluations: Vec<Evaluation>,
    },
    Certify {
        ring: RingPayload,
        endpoint: String,
        registration: Vec<u8>,
        statement: RegistrationStatement,
        evaluations: [Vec<Evaluation>; 3],
        authentication_seed: [u8; 32],
    },
    Collect {
        ring: RingPayload,
        nodes: Vec<NodeEndpoint>,
        selection: Vec<u8>,
        object_id: String,
        reader: Vec<u8>,
        proof: ReaderKeyProof,
        session: [u8; 32],
        authentication_seed: [u8; 32],
        auditor: String,
        accepted_selection: Vec<u8>,
        registered_key: Vec<u8>,
        epk: Vec<u8>,
    },
    Verify {
        collection: EncryptedCollection,
        accepted_selection: Vec<u8>,
        registered_key: Vec<u8>,
        epk: Vec<u8>,
        reader: Vec<u8>,
    },
    Decrypt {
        collection: EncryptedCollection,
        accepted_selection: Vec<u8>,
        registered_key: Vec<u8>,
        epk: Vec<u8>,
        reader_secret: Vec<u8>,
    },
}

fn signer(mut seed: [u8; 32]) -> authn::JwtSigner {
    use zeroize::Zeroize;
    let key = did_key::generate::<did_key::Ed25519KeyPair>(Some(&seed));
    seed.zeroize();
    authn::JwtSigner::from_key_pair(key)
}

async fn run(request: Request) -> Result<serde_json::Value> {
    use serde_json::json;
    ensure!(request.version == 1, "unsupported interface version");
    match request.operation {
        Operation::Capabilities {} => Ok(json!({"protocol":1,"lakey":1,"shieldd_selection":2})),
        Operation::AuthenticationIdentity {
            authentication_seed,
        } => Ok(json!({"did":signer(authentication_seed).did_uri})),
        Operation::RegistrationObject { identity } => {
            Ok(json!({"object_id":crypto::lakey::registration_object_id(&identity)?}))
        }
        Operation::ReadRing { chain, ring_id } => {
            use bulletin::r#trait::{Bulletin, BulletinKind};
            let bulletin = bulletin::vera::VeraBulletin {
                chain_client: common::blockchain::VeraClient::new(chain).await?,
            };
            let ring = RingPayload::try_from(bulletin.read(ring_id, BulletinKind::Ring).await?)?;
            Ok(json!({"ring":ring}))
        }
        Operation::GenerateReader {} => {
            let (secret, reader) = crypto::helpers::generate_keypair()?;
            let secret = zeroize::Zeroizing::new(secret);
            let proof = PreImpl::prove_reader_key(&secret, &reader)?;
            let bytes = CryptoSerialize::to_bytes(&*secret)?;
            Ok(json!({"secret":bytes,"reader":reader.to_bytes()?,"proof":proof}))
        }
        Operation::VerifyReader { reader, proof } => {
            PreImpl::verify_reader_key(&GroupAffine::from_bytes(&reader)?, &proof)?;
            Ok(json!({"verified":true}))
        }
        Operation::Evaluate {
            ring,
            nodes,
            identity,
            session,
            authentication_seed,
        } => {
            let (key, evaluations) = lakey::evaluate(
                &ring,
                &nodes,
                &identity,
                session,
                &signer(authentication_seed),
            )
            .await?;
            Ok(json!({"public_key":key.to_bytes()?,"evaluations":evaluations}))
        }
        Operation::VerifyRegistration {
            ring,
            identity,
            evaluations,
        } => {
            let key = bulletin::lakey::registered_key(
                &identity,
                bulletin::lakey::committee_id(&ring)?,
                &ring.peer_node_keys,
                &evaluations,
            )?;
            Ok(json!({"public_key":key.to_bytes()?}))
        }
        Operation::Certify {
            ring,
            endpoint,
            registration,
            statement,
            evaluations,
            authentication_seed,
        } => {
            let certificate = lakey::certify(
                &ring,
                &endpoint,
                registration,
                &statement,
                evaluations,
                &signer(authentication_seed),
            )
            .await?;
            Ok(json!({"certificate":certificate}))
        }
        Operation::Collect {
            ring,
            nodes,
            selection,
            object_id,
            reader,
            proof,
            session,
            authentication_seed,
            auditor,
            accepted_selection,
            registered_key,
            epk,
        } => {
            let token = signer(authentication_seed).sign_for_actor(
                auditor,
                authn::PreClaims {
                    rdr_pk: reader.clone(),
                    object_id: object_id.clone(),
                    derivation: None,
                    salt: Some(hex::encode(session)),
                },
                std::time::Duration::from_secs(300),
            )?;
            let request = proto::v0::pre::ReencryptShielddRequest {
                selection_json: selection,
                object_id,
                rdr_pk: reader,
                rdr_pk_proof: Some(proto::v0::pre::ReaderKeyProof {
                    challenge: proof.challenge,
                    response: proof.response,
                }),
                session: session.to_vec(),
            };
            let collection = lakey::collect(
                &ring,
                &nodes,
                request,
                &token,
                &accepted_selection,
                &GroupAffine::from_bytes(&registered_key)?,
                &GroupAffine::from_bytes(&epk)?,
            )
            .await?;
            Ok(serde_json::to_value(collection)?)
        }
        Operation::Verify {
            collection,
            accepted_selection,
            registered_key,
            epk,
            reader,
        } => {
            lakey::verify(
                &collection,
                &accepted_selection,
                &GroupAffine::from_bytes(&registered_key)?,
                &GroupAffine::from_bytes(&epk)?,
                &GroupAffine::from_bytes(&reader)?,
            )?;
            Ok(json!({"verified":true}))
        }
        Operation::Decrypt {
            collection,
            accepted_selection,
            registered_key,
            epk,
            reader_secret,
        } => {
            let bytes = zeroize::Zeroizing::new(reader_secret);
            let secret = zeroize::Zeroizing::new(ScalarField::from_bytes(&bytes)?);
            let reader = GroupAffine::GENERATOR * *secret;
            let key = GroupAffine::from_bytes(&registered_key)?;
            let result = lakey::verify(
                &collection,
                &accepted_selection,
                &key,
                &GroupAffine::from_bytes(&epk)?,
                &reader,
            );
            let shared = result.map(|point| point - key * *secret);
            Ok(json!({"shared_point":shared?.to_bytes()?}))
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let outcome = async {
        let mut input = zeroize::Zeroizing::new(Vec::new());
        std::io::stdin()
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut input)?;
        ensure!(input.len() <= 2 * 1024 * 1024, "request too large");
        let request: Request = match serde_json::from_slice(&input) {
            Ok(request) => request,
            Err(error) => {
                std::io::stdout().write_all(b"{\"status\":\"rejected\"}")?;
                return Err(error.into());
            }
        };
        drop(input);
        // These operations have no external effects: a completed validation error is definitive.
        let validation = matches!(&request.operation, Operation::VerifyRegistration { .. });
        let response = match run(request).await {
            Ok(response) => response,
            Err(error) => {
                let denied = error.downcast_ref::<tonic::Status>().is_some_and(|status| {
                    matches!(
                        status.code(),
                        tonic::Code::PermissionDenied | tonic::Code::InvalidArgument
                    )
                });
                if validation || denied {
                    std::io::stdout().write_all(b"{\"status\":\"rejected\"}")?;
                }
                return Err(error);
            }
        };
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&response)?);
        std::io::stdout().write_all(&bytes)?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if outcome.is_err() {
        // External errors can contain request material; never echo them through the adapter.
        eprintln!("audit operation failed");
        std::process::exit(1);
    }
}
