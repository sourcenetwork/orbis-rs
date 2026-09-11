use crate::{
    app_state::AppState,
    helpers::{
        auth::{current_unix_time, request_actor},
        protocol_version::read_ring_for_route,
        shieldd_sdk::invoke,
    },
    sign::v0::helpers::validate_sign_claims,
};
use anyhow::{ensure, Context, Result};
use bulletin::lakey::{committee_id, registered_key, Evaluation};
use bulletin::r#trait::RingPayload;
use crypto::{lakey::Identity, r#trait::Dkg, CryptoSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationContext {
    pub token_string: String,
    pub registration_json: Vec<u8>,
    pub evaluations: [Vec<Evaluation>; 3],
}

impl RegistrationContext {
    pub fn nonce_context(&self) -> Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"orbis.shieldd.registration.nonce.v1\0");
        hash.update((self.registration_json.len() as u64).to_le_bytes());
        hash.update(&self.registration_json);
        hash.update(serde_json::to_vec(&self.evaluations)?);
        Ok(format!(
            "shieldd-registration:{}",
            hex::encode(hash.finalize())
        ))
    }
}

#[derive(Deserialize)]
struct Capabilities {
    protocol: u32,
    audit_registration_version: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    identity: Identity,
    public_key: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub version: u32,
    pub object_id: String,
    pub ring_id: String,
    pub ring_public_key: [u8; 32],
    pub keys: [Key; 3],
    pub message: Vec<u8>,
}
pub struct Validated {
    pub statement: Statement,
    pub ring: RingPayload,
}

/// Every signer reconstructs the certificate and checks the five MPC evaluations per field.
pub async fn validate<D>(
    state: &AppState<D>,
    version: u64,
    context: &RegistrationContext,
    message: Option<&[u8]>,
    replay_namespace: Option<&str>,
) -> Result<Validated>
where
    D: Dkg + Clone + Send + Sync + 'static,
{
    ensure!(
        context.registration_json.len() <= 65536
            && context.token_string.len() <= crate::constants::MAX_JWT_BYTES,
        "oversized registration request"
    );
    ensure!(
        context.evaluations.iter().all(|items| items.len() == 5),
        "all five evaluations per field are required"
    );
    ensure!(
        serde_json::to_vec(&context.evaluations)?.len() <= 65536,
        "oversized registration evidence"
    );
    let token = authn::resolve_jwt_did::<authn::SignClaims>(
        &context.token_string,
        current_unix_time().map_err(anyhow::Error::msg)?,
        crate::constants::MAX_TOKEN_LIFETIME_SECS,
        crate::constants::MAX_JWT_BYTES,
        crate::constants::JWT_CLOCK_SKEW_LEEWAY_SECS,
    )?;
    let executable =
        std::env::var("SHIELDD_AUDIT_VERIFIER").context("Shieldd verifier is not configured")?;
    let node =
        std::env::var("SHIELDD_AUDIT_NODE").context("chosen Shieldd node is not configured")?;
    let capabilities: Capabilities =
        serde_json::from_slice(&invoke(&executable, &["disclosure", "capabilities"], &[]).await?)?;
    ensure!(
        capabilities.protocol == 1 && capabilities.audit_registration_version == 1,
        "incompatible registration verifier"
    );
    let statement: Statement = serde_json::from_slice(
        &invoke(
            &executable,
            &["disclosure", "audit-registration", "-", "--node", &node],
            &context.registration_json,
        )
        .await?,
    )?;
    ensure!(
        statement.version == 1
            && statement.message.len() <= crate::constants::MAX_SIGN_MESSAGE_BYTES,
        "invalid registration statement"
    );
    if let Some(message) = message {
        ensure!(
            message == statement.message,
            "certificate message substitution"
        );
    }
    validate_sign_claims(&token, &statement.object_id, Some(&statement.message))?;
    let ring = read_ring_for_route(&*state.bulletin, &statement.ring_id, version)
        .await
        .map_err(anyhow::Error::msg)?;
    ensure!(
        hex::decode(&ring.ring_pk)? == statement.ring_public_key,
        "registration root key mismatch"
    );
    ensure!(
        ring.peer_node_keys.contains(&state.node_key),
        "signer is not a ring member"
    );
    let committee = committee_id(&ring)?;
    for (key, evaluations) in statement.keys.iter().zip(&context.evaluations) {
        ensure!(
            key.identity.ring == statement.ring_id,
            "registration key ring mismatch"
        );
        let actual = registered_key(&key.identity, committee, &ring.peer_node_keys, evaluations)?;
        ensure!(
            actual.to_bytes()? == key.public_key,
            "registration key is not the MPC-derived key"
        );
    }
    let actor = request_actor(&token, ring.trusted_auth_relay_dids.as_deref())
        .map_err(anyhow::Error::msg)?;
    let policy = ring
        .policy_id
        .as_ref()
        .filter(|id| !id.is_empty())
        .context("registration policy unavailable")?;
    let access = authz::vera::AccessCheckRequest::new(
        policy.clone(),
        "audit_registration".into(),
        statement.object_id.clone(),
        "certify".into(),
        None,
        None,
        None,
    )
    .to_bytes()?;
    ensure!(
        state.authz.check(access, &actor).await?,
        "ACP denied registration certification"
    );
    // Node/policy queries can outlast the caller's token.
    authn::resolve_jwt_did::<authn::SignClaims>(
        &context.token_string,
        current_unix_time().map_err(anyhow::Error::msg)?,
        crate::constants::MAX_TOKEN_LIFETIME_SECS,
        crate::constants::MAX_JWT_BYTES,
        crate::constants::JWT_CLOCK_SKEW_LEEWAY_SECS,
    )?;
    if let Some(namespace) = replay_namespace {
        state
            .jti_guard
            .check_and_record(&token.jwt_id, token.expiration_time, namespace)
            .await
            .map_err(|error| anyhow::anyhow!("registration replay guard: {error}"))?;
    }
    Ok(Validated { statement, ring })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_context_binds_registration_and_evaluations() {
        let context = RegistrationContext {
            token_string: "first token".into(),
            registration_json: b"registration".to_vec(),
            evaluations: [vec![], vec![], vec![]],
        };
        let original = context.nonce_context().unwrap();
        let mut changed = context.clone();
        changed.registration_json.push(0);
        assert_ne!(original, changed.nonce_context().unwrap());
        changed = context.clone();
        changed.evaluations[0].push(Evaluation {
            identity: Identity {
                chain: "chain".into(),
                ring: "ring".into(),
                epoch: 1,
                scope: crypto::lakey::Scope::General,
                field: crypto::lakey::Field::Amount,
            },
            session: [1; 32],
            committee: [2; 32],
            index: 1,
            public_share: vec![],
            signature: vec![],
        });
        assert_ne!(original, changed.nonce_context().unwrap());
        // Token validity and actor permissions are checked separately at every signing stage.
        changed = context;
        changed.token_string = "fresh token".into();
        assert_eq!(original, changed.nonce_context().unwrap());
    }
}
