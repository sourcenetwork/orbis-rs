use authn::{resolve_actor_id, BearerToken};
use authz::request::ValidWindow;
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
/// WebAuthn evidence instead — that mechanism's own verifier
/// (`orbis_webauthn::verify_endpoint_auth`). The two are mutually
/// exclusive; WebAuthn, when present, takes priority and the bearer
/// token, if any, is never even inspected.
///
/// This lives in `orbis-node`, not in `authn` or `orbis-webauthn`,
/// deliberately: neither of those crates can know about the other (see
/// `authn::endpoints`'s own doc comment for the dependency direction),
/// so the only place that can decide "try JWT, then try WebAuthn" is a
/// caller that depends on both. A future authentication mechanism (e.g.
/// a DKIM-verified email flow) is added here the same way — one more
/// optional evidence parameter and branch — never by reaching into
/// `orbis-webauthn` to extend its dispatch, since it has none to extend.
#[allow(clippy::too_many_arguments)]
pub fn resolve_request_auth<E: orbis_webauthn::WebAuthnEndpoint>(
    fields: &E::Fields,
    token_string: Option<&str>,
    webauthn_evidence: Option<&WebAuthnEvidence>,
    rp_id: Option<&str>,
    origin: Option<&str>,
    current_time: u64,
    max_token_lifetime_secs: u64,
    max_jwt_bytes: usize,
    clock_skew_leeway_secs: u64,
) -> Result<BearerToken<E::Claims>, String> {
    if let Some(evidence) = webauthn_evidence {
        // Matches `JtiReplayGuard::retention`'s own cap exactly: evidence whose
        // validity period this function accepts must not outlive what the
        // replay cache can still remember it for, or single-use protection
        // silently stops applying once the cache forgets it.
        let max_lifetime_secs = max_token_lifetime_secs.saturating_add(clock_skew_leeway_secs);
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

    let token_string = token_string
        .ok_or_else(|| "request carries neither a JWT nor WebAuthn evidence".to_string())?;
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

    #[test]
    fn dispatches_to_webauthn_when_evidence_present() {
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
            1_700_000_100,
            3600,
            16 * 1024,
            30,
        )
        .expect("well-formed WebAuthn evidence must resolve");

        assert_eq!(token.issuer_id, did);
        assert_eq!(token.claims.value, "op-1");
    }

    #[test]
    fn dispatches_to_jwt_when_no_webauthn_evidence_present() {
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
            current_unix_time().unwrap(),
            3600,
            16 * 1024,
            30,
        )
        .expect("well-formed JWT must resolve");

        assert_eq!(token.claims.value, "op-1");
    }

    #[test]
    fn rejects_when_neither_auth_method_present() {
        let result = resolve_request_auth::<ToyEndpoint>(
            &"op-1",
            None,
            None,
            Some(RP_ID),
            Some(ORIGIN),
            1_700_000_100,
            3600,
            16 * 1024,
            30,
        );
        assert!(result.is_err());
    }
}
