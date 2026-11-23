# orbis-webauthn

`verify_assertion` checks a raw WebAuthn assertion directly against a
caller-supplied compressed P-256 credential public key and an exact
expected challenge — no session/ceremony state, no credential storage.

`verify_and_build_token` wraps `verify_assertion` with the operation-binding
and identity-resolution steps every protocol needs identically, generic
over that protocol's own operation (`orbis_integration_core::CanonicalOperation`
— `SignOperation`, `PreOperation`, `StoreSecretOperation`) and claims
(`authn::SignClaims`, `PreClaims`, `StoreSecretClaims`) types, and returns
an `authn::BearerToken<Claims>` — the same shape a verified JWT already
produces, so every downstream check in a protocol's request pipeline runs
unchanged regardless of which authentication method was used.

`resolve_request_auth::<E: authn::endpoints::EndpointAuth>` goes one step
further: it's the single entry point every endpoint's node-side code
actually calls, resolving a request's identity via *either* a JWT bearer
string or WebAuthn evidence (mutually exclusive — WebAuthn, when present,
takes priority) and returning the same `BearerToken<E::Claims>` either way.
Each endpoint's marker type (`authn::endpoints::sign::SignEndpoint`,
`pre::PreEndpoint`, `store_secret::StoreSecretEndpoint`) supplies the
claims-validation and operation-building logic specific to that endpoint;
everything else — JWT resolution, nonce decoding, the WebAuthn signature
check — is shared. Each protocol's own `webauthn_auth` module in
orbis-node (`sign::v0::webauthn_auth`, `pre::v0::webauthn_auth`,
`store_secret::v0::webauthn_auth`) is now only the wire-level proto → `WebAuthnEvidence`
conversion; the call sites in `*::v0::service::stages`/`coordinator::handlers`
call `resolve_request_auth` directly, identical apart from which marker
type they pass — see this crate's own tests for a worked example with a
toy endpoint/operation/claims type.

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
