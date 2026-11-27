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
[`test_support`] — and for production deployments that would rather pin a
fixed, operator-curated set of keys than depend on live DNS at request time
— [`PinnedDnsCache`], loaded once at node startup from a JSON file via
`--email-dkim-keys-file` (`PinnedDnsCache::load_from_file`) — key lookups go
through `mail-auth`'s own public `DnsCache`/`ResolverCache` seam instead
(`verify_email_message_with_cache`/`verify_and_build_token_with_cache`): a
cache is consulted before any live lookup `MessageAuthenticator` would
otherwise perform, and `verify_email_message_with_cache` itself rejects
outright, before ever calling `authenticator`, if the message's primary
signing key isn't already in that cache. Production pinned-key mode goes
one step further than that pre-check: `orbis-node`'s own `init_node`
builds the `authenticator` it passes in with a resolver that has *zero*
configured nameservers, so none of `mail-auth`'s own lookups — not just
the primary key, but also its ATPS/failure-report TXT lookups, which go
through this same cache on a path the pre-check doesn't enumerate — can
reach the network at all. A future chain-backed store would implement
that same `DnsCache` trait pair, built from chain state instead of a
file — no change to the verification logic itself.
`bin/orbis-node/src/tests/e2e/email_sign_scenario.rs`
exercises the pinned-file path end to end against the real node binary
(there's no live DNS record for a synthetic test domain, so this is also how
that Docker scenario works at all, not just a test convenience).

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

The identity this crate authenticates as is always
`did:emailhash:sha256(address)` — its own dedicated DID method, not a real
decoded key. An earlier version used a plain `email:sha256(address)`
string instead (missing the `did:` scheme entirely); ACP's `Authz::check`
(the read path) happily accepts an arbitrary subject string, so that
worked right up until the Docker e2e scenario tried to actually *grant* a
relationship to one — native `vera.rs`'s ACP module (`vera_identity::Did::new`)
only accepts a short, explicit allowlist of actor-id schemes for a
`set_relationship` write (`did:key:`, `did:opk:<64-hex-digest>`, and now
`did:emailhash:<64-hex-digest>`), regardless of what `Authz::check` itself
would accept. The Cosmos/SourceHub chain's own ACP module only requires a
syntactically valid `did:<method>:<id>` shape and never restricts by
method name, so it accepts this (or any other well-formed method) with no
chain-side change — `email:sha256(address)` failed there only because it
isn't shaped like a DID at all (no `did:` scheme, so it splits into 2
parts instead of the required 3), not because "email" itself was
disallowed.
