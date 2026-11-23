# orbis-webauthn

`verify_assertion` checks a raw WebAuthn assertion directly against a
caller-supplied compressed P-256 credential public key and an exact
expected challenge — no session/ceremony state, no credential storage. This
is the one function both orbis-node (independently, per ring node) and the
example apps' own local checks call, so verification logic exists in exactly
one place.

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
