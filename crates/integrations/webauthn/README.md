# orbis-webauthn

`verify_assertion` checks a raw WebAuthn assertion directly against a
caller-supplied compressed P-256 credential public key and an exact
expected challenge — no session/ceremony state, no credential storage.

`verify_and_build_token` wraps `verify_assertion` with the operation-binding
and identity-resolution steps every protocol needs identically, generic
over that protocol's own operation (`orbis_integration_core::CanonicalOperation`
— `SignOperation`, `PreOperation`, `StoreSecretOperation`) and claims
(`authn::endpoints::sign::SignClaims`, `pre::PreClaims`,
`store_secret::StoreSecretClaims`) types, and returns an
`authn::BearerToken<Claims>` — the same shape a verified JWT already
produces, so every downstream check in a protocol's request pipeline runs
unchanged regardless of which authentication method was used.

`verify_endpoint_auth::<E: WebAuthnEndpoint>` goes one step further: it's
the complete WebAuthn authentication path for one endpoint, generic over
that endpoint's own `WebAuthnEndpoint` impl (`endpoints::sign`,
`endpoints::pre`, `endpoints::store_secret` — one file per endpoint,
mirroring `authn::endpoints`' own layout). `WebAuthnEndpoint` extends
`authn::endpoints::EndpointAuth` (the normal, JWT-only shape that crate
defines) with what WebAuthn specifically needs: the canonically-encodable
operation its challenge must commit to, and how to synthesize that
endpoint's claims from the request's fields directly (there being no
pre-existing JWT to pull them from).

This crate deliberately has **no notion of a JWT fallback** — it only
verifies WebAuthn evidence, nothing else. Deciding "try JWT, then fall
back to WebAuthn if the request carries it" is `orbis-node`'s job
(`crate::helpers::auth::resolve_request_auth`, generic over the same
`WebAuthnEndpoint` bound), not this crate's: neither `authn` nor
`orbis-webauthn` can depend on each other, let alone on a future third
mechanism's crate, so only a caller that depends on all of them can
orchestrate between them. Each protocol's own `webauthn_auth` module in
orbis-node (`sign::v0::webauthn_auth`, `pre::v0::webauthn_auth`,
`store_secret::v0::webauthn_auth`) is just the wire-level proto →
`WebAuthnEvidence` conversion; the call sites in
`*::v0::service::stages`/`coordinator::handlers` call orbis-node's
orchestrator directly, identical apart from which endpoint's marker type
they pass — see this crate's own tests for a worked example with a toy
endpoint/operation/claims type.

It deliberately does not use `webauthn-rs`'s higher-level ceremony API
(`Webauthn`/`AuthenticationState`): that API always generates its own
random challenge internally — there's no public way to pin a caller-chosen
one — which doesn't fit a model where the credential's own public key *is*
the identity and the challenge must be an exact, independently-recomputable
commitment to the operation being authorized (see `orbis-integration-core`).
The actual cryptographic verification (`COSEKey::verify_signature`) is
still reused directly from `webauthn-rs-core`, not reimplemented — only the
orchestration of the handful of checks (`type`, challenge, origin,
`rpIdHash`, the User Present flag) that its higher-level API would
otherwise do internally is ours.

This library serves both [passkey-sign](../../../bin/example-integrations/passkey-sign/README.md)
and [yubikey-sign](../../../bin/example-integrations/yubikey-sign/README.md). The YubiKey example
uses FIDO2/WebAuthn, not PIV, OpenPGP, or OTP.

Credential enrollment is just an ACP grant of the `did:key` derived from the
credential's public key (see `authn::did_from_p256_public_key`) — there is
no separate enrollment registry. Browser calls (building the
`navigator.credentials.get()` options, running the ceremony) remain in the
example frontend; this crate and orbis-node handle verification.
