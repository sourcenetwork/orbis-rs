# orbis-email

DKIM-verified email evidence, mirroring `orbis-webauthn`'s own design: a
reader proves control of a mailbox by producing a DKIM-signed email, and
every participating ring node independently verifies it in place of a JWT
before treating the reader as authenticated. See `orbis-webauthn/README.md`
for the shared shape (`CanonicalOperation`, `ChallengeEvidence`,
per-endpoint marker types) this crate reuses unchanged.

DKIM alone proves *who sent this*, not *which request it authorizes*.
[`challenge_text`] closes that gap: a deterministic, human-legible
rendering of the operation's *entire* canonical state — for PRE that
necessarily includes `rdr_pk`, the exact reader key — that a challenge
email asks the reader to read, approve, and reply to verbatim, and that
[`verify_email_message`] looks for as a substring of the DKIM-verified
body. This is an exact match on the full text, not a hash: unlike a short
derived code, there's no collision space to reason about, and it doubles
as informed consent — the reader sees exactly what they're approving
before replying, not an opaque token. See `orbis_integration_core::CanonicalDisplay`
and `challenge_text`'s own doc comments for the construction and why this
is a separate textual rendering from the binary `canonical_bytes()`
WebAuthn uses.

The actual DKIM cryptography and RFC 5322/6376 parsing are reused directly
from [`mail-auth`](https://docs.rs/mail-auth) (its pure-Rust `rust-crypto`
backend) — never hand-rolled, the same principle `orbis-webauthn` follows
for its own ECDSA verification. This crate only adds the checks `mail-auth`
doesn't do itself: mandatory DMARC-style `d=`/`From:` alignment (skipping it
lets any domain forge a validly-signed message claiming to be any address),
the challenge-text binding, and the identity/claims resolution every
protocol needs identically (`verify_and_build_token`, `EmailEndpoint`,
`verify_endpoint_auth` — all mirroring their `orbis-webauthn` namesakes).

Key resolution defaults to live DNS (`mail_auth::MessageAuthenticator`'s own
resolver) with zero extra code. For fully offline tests —
[`test_support`] — and, later, a chain-backed pinned-key store, key lookups
go through `mail-auth`'s own public `DnsCache`/`ResolverCache` seam instead
(`verify_email_message_with_cache`/`verify_and_build_token_with_cache`): a
cache is consulted before any live lookup `MessageAuthenticator` would
otherwise perform. A future pinned store implements that same trait pair,
built from chain state instead of a `HashMap` — no change to the
verification logic itself.

## What's out of scope here

The SMTP challenge/capture service that actually sends a challenge email and
receives the reply (an example app's job, not this crate's), and the
`email-decrypt` example app itself.

**TODO(DNSSEC):** key lookups trust plain DNS with no chain-of-trust
validation — confirmed from `mail_auth::dns::DnssecStatus`'s own doc
comment: its built-in resolver backends never validate DNSSEC and always
report `Indeterminate`. A spoofed/poisoned answer for the signing domain's
`_domainkey` TXT record would be trusted as-is. Mitigated today only if a
deployment's own OS resolver happens to validate DNSSEC itself (common for
enterprise/cloud DNS) — an operational assumption, not anything this crate
verifies. Closing this needs two things, not one: a validating
`mail_auth::DnsCache` wired in (the seam already exists —
`verify_email_message_with_cache`), *and* `check_verified_results` actually
reading `RecordSet::dnssec_status` and rejecting anything but `Secure` —
today it doesn't inspect that field at all, so the first half alone
wouldn't be enough.

The identity this crate authenticates as is always `email:sha256(address)`
— a plain string, not a DID — but ACP's `Authz::check` already takes an
arbitrary subject string, so nothing elsewhere needed to change for that.
