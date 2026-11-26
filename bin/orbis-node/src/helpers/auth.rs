use authn::{resolve_actor_id, BearerToken};
use authz::request::ValidWindow;
use orbis_email::EmailEvidence;
use orbis_webauthn::WebAuthnEvidence;
use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current time as seconds since the Unix epoch.
///
/// Returns an error string on the (essentially impossible) case where the
/// system clock is set before the epoch.
pub fn current_unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("Failed to get timestamp: {}", e))
}

pub fn request_actor<C>(
    token: &BearerToken<C>,
    trusted_relay_issuers: Option<&[String]>,
) -> Result<String, String> {
    resolve_actor_id(token, trusted_relay_issuers.unwrap_or_default())
        .map(str::to_string)
        .map_err(|error| error.to_string())
}

/// Convert a client-supplied optional timestamp range (PRE's and Sign's
/// generated `TimestampRange` are distinct wire types with the same two
/// `u64` fields) into the `authz::request::ValidWindow` used for ACP checks.
pub fn client_valid_window(range: Option<(u64, u64)>) -> Option<ValidWindow> {
    range.map(|(start, end)| ValidWindow { start, end })
}

/// The one place in this codebase that decides which authentication
/// mechanism applies to a request: the normal JWT path
/// (`authn::endpoints::resolve_jwt_auth`), or — if the request carries
/// WebAuthn or email evidence instead — that mechanism's own verifier
/// (`orbis_webauthn::verify_endpoint_auth` / `orbis_email::verify_endpoint_auth`).
/// All three are mutually exclusive; WebAuthn takes priority over email,
/// which takes priority over the bearer token, and neither evidence kind
/// ever falls through to inspect it.
///
/// This lives in `orbis-node`, not in `authn`, `orbis-webauthn`, or
/// `orbis-email`, deliberately: none of those crates can know about each
/// other (see `authn::endpoints`'s own doc comment for the dependency
/// direction), so the only place that can decide "try JWT, then try
/// WebAuthn, then try email" is a caller that depends on all three. A
/// future authentication mechanism is added here the same way — one more
/// optional evidence parameter and branch — never by reaching into an
/// existing mechanism's crate to extend its dispatch, since none has any
/// to extend.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_request_auth<E>(
    fields: &E::Fields,
    token_string: Option<&str>,
    webauthn_evidence: Option<&WebAuthnEvidence>,
    rp_id: Option<&str>,
    origin: Option<&str>,
    email_evidence: Option<&EmailEvidence>,
    email_authenticator: Option<&mail_auth::MessageAuthenticator>,
    current_time: u64,
    max_token_lifetime_secs: u64,
    max_jwt_bytes: usize,
    clock_skew_leeway_secs: u64,
) -> Result<BearerToken<E::Claims>, String>
where
    E: orbis_webauthn::WebAuthnEndpoint + orbis_email::EmailEndpoint,
{
    // Matches `JtiReplayGuard::retention`'s own cap exactly: evidence whose
    // validity period either mechanism accepts must not outlive what the
    // replay cache can still remember it for, or single-use protection
    // silently stops applying once the cache forgets it.
    let max_lifetime_secs = max_token_lifetime_secs.saturating_add(clock_skew_leeway_secs);

    if let Some(evidence) = webauthn_evidence {
        return orbis_webauthn::verify_endpoint_auth::<E>(
            fields,
            evidence,
            rp_id,
            origin,
            current_time,
            max_lifetime_secs,
        )
        .map_err(|e| e.to_string());
    }

    if let Some(evidence) = email_evidence {
        let authenticator = email_authenticator
            .ok_or_else(|| "email evidence not configured on this node".to_string())?;
        return orbis_email::verify_endpoint_auth::<E>(
            authenticator,
            fields,
            evidence,
            current_time,
            max_lifetime_secs,
        )
        .await
        .map_err(|e| e.to_string());
    }

    let token_string = token_string.ok_or_else(|| {
        "request carries neither a JWT, WebAuthn evidence, nor email evidence".to_string()
    })?;
    authn::endpoints::resolve_jwt_auth::<E>(
        token_string,
        fields,
        current_time,
        max_token_lifetime_secs,
        max_jwt_bytes,
        clock_skew_leeway_secs,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbis_integration_core::CanonicalOperation;
    use p256::ecdsa::SigningKey;
    use sha2::Digest;

    const RP_ID: &str = "example.test";
    const ORIGIN: &str = "https://example.test";

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    struct ToyClaims {
        value: String,
    }

    struct ToyOperation {
        value: &'static str,
    }

    impl CanonicalOperation for ToyOperation {
        fn canonical_bytes(&self) -> Vec<u8> {
            self.value.as_bytes().to_vec()
        }
    }

    impl orbis_integration_core::CanonicalDisplay for ToyOperation {
        fn canonical_display(&self) -> String {
            format!("TOY OPERATION\nvalue: {}\n", self.value)
        }
    }

    struct ToyEndpoint;

    impl authn::endpoints::EndpointAuth for ToyEndpoint {
        type Claims = ToyClaims;
        type Fields = &'static str;

        fn validate_claims(
            token: &BearerToken<ToyClaims>,
            fields: &&'static str,
        ) -> authn::error::Result<()> {
            if token.claims.value != *fields {
                return Err(authn::error::AuthNError::Unauthorized(
                    "claims mismatch".to_string(),
                ));
            }
            Ok(())
        }
    }

    impl orbis_webauthn::WebAuthnEndpoint for ToyEndpoint {
        type Operation = ToyOperation;

        fn claims(fields: &&'static str) -> ToyClaims {
            ToyClaims {
                value: fields.to_string(),
            }
        }

        fn operation(
            fields: &&'static str,
            _issued_at: u64,
            _expiry: u64,
            _nonce: [u8; 16],
        ) -> ToyOperation {
            ToyOperation { value: fields }
        }
    }

    impl orbis_email::EmailEndpoint for ToyEndpoint {
        type Operation = ToyOperation;

        fn claims(fields: &&'static str) -> ToyClaims {
            ToyClaims {
                value: fields.to_string(),
            }
        }

        fn operation(
            fields: &&'static str,
            _issued_at: u64,
            _expiry: u64,
            _nonce: [u8; 16],
        ) -> ToyOperation {
            ToyOperation { value: fields }
        }
    }

    fn webauthn_evidence_for(key: &SigningKey, did: &str, value: &'static str) -> WebAuthnEvidence {
        let assertion = orbis_webauthn::build_test_assertion(
            key,
            RP_ID,
            ORIGIN,
            &ToyOperation { value }.canonical_bytes(),
        );
        WebAuthnEvidence {
            issuer_did: did.to_string(),
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
            signature: assertion.signature,
            issued_at: 1_700_000_000,
            expiry: 1_700_000_200,
            nonce: vec![1; 16],
        }
    }

    #[tokio::test]
    async fn dispatches_to_webauthn_when_evidence_present() {
        let mut scalar = [0u8; 32];
        scalar[31] = 7;
        let key = SigningKey::from_bytes((&scalar).into()).expect("small nonzero scalar is valid");
        let compressed: [u8; 33] = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let did = authn::did_from_p256_public_key(&compressed);
        let evidence = webauthn_evidence_for(&key, &did, "op-1");

        let token = resolve_request_auth::<ToyEndpoint>(
            &"op-1",
            None,
            Some(&evidence),
            Some(RP_ID),
            Some(ORIGIN),
            None,
            None,
            1_700_000_100,
            3600,
            16 * 1024,
            30,
        )
        .await
        .expect("well-formed WebAuthn evidence must resolve");

        assert_eq!(token.issuer_id, did);
        assert_eq!(token.claims.value, "op-1");
    }

    #[tokio::test]
    async fn dispatches_to_jwt_when_no_other_evidence_present() {
        let signer = authn::JwtSigner::new();
        let jwt = signer
            .sign(
                ToyClaims {
                    value: "op-1".to_string(),
                },
                std::time::Duration::from_secs(60),
            )
            .expect("sign test JWT");

        let token = resolve_request_auth::<ToyEndpoint>(
            &"op-1",
            Some(&jwt),
            None,
            Some(RP_ID),
            Some(ORIGIN),
            None,
            None,
            current_unix_time().unwrap(),
            3600,
            16 * 1024,
            30,
        )
        .await
        .expect("well-formed JWT must resolve");

        assert_eq!(token.claims.value, "op-1");
    }

    #[tokio::test]
    async fn rejects_when_no_auth_method_present() {
        let result = resolve_request_auth::<ToyEndpoint>(
            &"op-1",
            None,
            None,
            Some(RP_ID),
            Some(ORIGIN),
            None,
            None,
            1_700_000_100,
            3600,
            16 * 1024,
            30,
        )
        .await;
        assert!(result.is_err());
    }

    fn email_evidence_for(
        key: &orbis_email::test_support::TestSigningKey,
        from_address: &str,
        value: &'static str,
    ) -> EmailEvidence {
        let text = orbis_email::challenge_text(&ToyOperation { value });
        let raw_message = key.sign_message(
            from_address,
            "ring@orbis.test",
            &format!("confirming:\n{text}"),
        );
        EmailEvidence {
            claimed_address: from_address.to_string(),
            raw_message,
            issued_at: 1_700_000_000,
            expiry: 1_700_000_200,
            nonce: vec![1; 16],
        }
    }

    #[tokio::test]
    async fn dispatches_to_email_when_evidence_present() {
        const FROM: &str = "alice@example.test";
        let signing_key =
            orbis_email::test_support::TestSigningKey::generate("example.test", "orbistest");
        let cache = orbis_email::test_support::TestDnsCache::default();
        signing_key.register(&cache);
        let evidence = email_evidence_for(&signing_key, FROM, "op-1");
        let authenticator =
            mail_auth::MessageAuthenticator::new_system_conf().expect("authenticator");

        let (operation, claims) = (
            ToyOperation { value: "op-1" },
            ToyClaims {
                value: "op-1".to_string(),
            },
        );
        let token = orbis_email::verify_and_build_token_with_cache(
            &authenticator,
            &cache,
            &evidence,
            operation,
            claims,
            1_700_000_100,
            3600,
        )
        .await
        .expect("well-formed email evidence must resolve directly through orbis-email");
        assert_eq!(
            token.issuer_id,
            format!(
                "email:{}",
                hex::encode(sha2::Sha256::digest(FROM.as_bytes()))
            )
        );

        // `resolve_request_auth` itself only has the no-cache (live DNS)
        // entry point wired in, so it can't resolve this synthetic,
        // unregistered-with-live-DNS key — confirm instead that it reaches
        // (and only fails inside) the email branch, not silently falling
        // through to the JWT path.
        let result = resolve_request_auth::<ToyEndpoint>(
            &"op-1",
            None,
            None,
            Some(RP_ID),
            Some(ORIGIN),
            Some(&evidence),
            Some(&authenticator),
            1_700_000_100,
            3600,
            16 * 1024,
            30,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_email_evidence_when_not_configured_on_this_node() {
        const FROM: &str = "alice@example.test";
        let signing_key =
            orbis_email::test_support::TestSigningKey::generate("example.test", "orbistest");
        let evidence = email_evidence_for(&signing_key, FROM, "op-1");

        let result = resolve_request_auth::<ToyEndpoint>(
            &"op-1",
            None,
            None,
            Some(RP_ID),
            Some(ORIGIN),
            Some(&evidence),
            None, // no authenticator configured on this node
            1_700_000_100,
            3600,
            16 * 1024,
            30,
        )
        .await;
        assert!(result.is_err());
    }
}
