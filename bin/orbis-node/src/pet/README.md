# PET Developer Guide

PET checks an ownership tag before PRE releases reencryption shares for a ring
with `requires_pet`. It runs inside PRE; there is no separate public PET service.
The same protocol uses the selected BLS or Jubjub implementation.

## Request and authorization

[PRE's service stages](../pre/v0/service/stages.rs) authenticate the request,
check ACP access to the document, and call
`PetCoordinator::initiate_pet_check`. PET additionally requires the actor to hold
`document.permission` on the audit target under the document's policy and
resource. A successful tag comparison cannot replace either permission check.

Each commit, reveal, and decrypt handler independently validates the JWT and its
object/salt binding, derives the actor, and repeats the audit permission check.
It reads the ring from the bulletin, verifies the document's tag-knowledge proof,
and resolves the authenticated transport peer to a current committee member.
A claimed node index alone does not authenticate a coordinator or contributor.
Every [PRE responder](../pre/v0/coordinator/handlers.rs) independently checks
document ACP and calls `verify_pet_admission` before releasing its share.

`audit_target_object_id` is the plaintext identifier whose fingerprint is
compared with the tag. There is no ACP identity-resolution step. The identifier
is carried to PET participants and PRE responders; it is not hidden from them.

## Commit, reveal, decrypt

The [initiator](v0/coordinator/initiator.rs) creates a fresh attempt and fixes its
ring snapshot and exact canonical PET public polynomial. The
[handlers](v0/coordinator/handlers.rs) run three phases:

1. **Commit.** Each participant checks its stored bundle against the requested
   polynomial and current member index, then commits to a fresh blinding
   contribution for `R` and `T - F(audit_target_object_id)`.
2. **Reveal.** The initiator selects exactly a threshold-sized commitment set.
   Those participants reveal signed openings and proofs bound to that exact
   selection. A shortfall discards the attempt; the selected blinders cannot be
   substituted. Their verified responses form a `PetBlindCertificate`.
3. **Decrypt.** Participants verify the complete certificate before applying
   their PET shares to its aggregate blinded point. The initiator verifies each
   signed DLEQ contribution against the certified polynomial and combines a
   threshold of valid shares. The comparison succeeds only when the result
   equals the certificate's aggregate blinded difference. Decrypt participants
   need not be the same set as the selected reveal participants.

The certificate and signed decrypt responses become `PetBlindEvidence` in the
PRE request. `verify_pet_admission` repeats the audit permission, tag proof,
certificate, contribution, generation, and final comparison checks. Missing or
invalid evidence prevents share release.

## Generation and context binding

[Generation validation](v0/generation.rs) checks bounded canonical polynomial
encoding, its coefficient count, the checking key, and the local share's
consistency and member index. Matching the polynomial's constant term to
`pet_pk` establishes key consistency, not authority for a share generation.

The [v2 reporting types](../../../../crates/reporting/src/pet_blind.rs) bind the
exact polynomial digest into `PetBlindContext`. The context also binds the
chain, protocol and crypto suite, ring snapshot and keys, document locator,
audit target, actor and validity window, coordinator, and attempt. The
certificate carries the polynomial and threshold signed reveals from distinct
current members. Decrypt statements bind the context, complete certificate,
aggregate points, and polynomial; an accused node cannot select a different
polynomial for verification.

PET has fresh DKG, refresh, and reshare paths. Refresh can change the whole
polynomial while preserving `pet_pk`; reshare can also change membership and
threshold. A local bundle, member index, or ring snapshot that no longer matches
the attempt returns `GenerationMismatch`. Collectors can finish with enough
matching peers; otherwise this surfaces through PRE as `ReshareInProgress`
(gRPC `Unavailable`), allowing a fresh request after state converges. A mismatch
is neither an invalid-crypto contribution nor an offline observation. Malformed,
missing, or unbound certificates remain verification errors, not a general
retry classification.

## Reports and publication boundary

The [PET report verifier](../reporting/v0/registry/invalid_crypto/pet.rs)
authenticates the accused's signed response and its context before treating a
cryptographic failure as reportable. Decrypt report validation requires the full
threshold reveal certificate and checks the response against its certified
polynomial, without consulting the validator's local share generation. A genuine
response therefore does not become invalid merely because the validator has
refreshed. Evidence bound to a different current ring or committee is rejected.

Report co-signers receive `PetBlindContext` and the decrypt certificate through
the private, out-of-band `ReportSigningContext`. These are not fields in the
report submitted to Vera. Vera receives the signed report with the accused's
signed statement and opaque context/certificate digests; the statement still
contains public proof material, including the decrypt polynomial. This boundary
does not hide the audit target from protocol participants or report co-signers,
and does not establish a broader privacy guarantee.

Deploy the PET v2 codec, node protocol, and compatible Vera report decoder as a
fresh aligned set. There is no v1 fallback or migration path for old PET
messages, certificates, or reports. Protocol tests and controlled refresh
fixtures do not by themselves qualify a full deployment or the native service's
24-hour scheduled-refresh behavior.
