# PET audit fix checklist

Recorded: 2026-09-26. Current checkout: `e10480d` (`add proof with tag for better verification`).

This consolidates the original six audit findings and the five findings from the
subsequent proof/reporting review. Original numbering is preserved. Items 7–11
are the new findings; they do not replace the deferred items 2–5.

Review basis: static source inspection only. No tests or builds were run. An item
marked addressed means its specific attack appears blocked in the reviewed code,
not that the whole PET protocol is secure or formally audited. Recheck the code
when implementing a fix; source locations can move.

PSS refresh/reshare and the future Jubjub migration remain outside this checklist.
The newly implemented PET invalid-crypto reporting is included. Existing backends
are BLS12-381 and Decaf377.

## Status at a glance

| ID | Priority | Finding | Status |
| --- | --- | --- | --- |
| 1 | P1 | One malicious contribution can force a successful match | Addressed by static review |
| 2 | P1 | Raw contributions expose the owner fingerprint | Fixed 2026-09-28 |
| 3 | P1 | PET responders do not authenticate/authorize the audit request | Fixed 2026-09-26 |
| 4 | P1 | FreshPet DKG can overwrite another ring's stored shares | Fixed 2026-09-26 |
| 5 | P1, conditional disclosure | Copied ciphertext can receive a fresh ownership tag | Fixed 2026-09-26 |
| 6 | P2 | Invalid responses consume honest-node deduplication slots | Addressed by static review |
| 7 | P1 | Document-ID substitution can frame an honest responder | Fixed 2026-09-26 |
| 8 | P2 | Timestamped inline documents cannot produce valid PET reports | Fixed 2026-09-26 |
| 9 | P2 | Signed malformed responses evade automatic reporting | Fixed 2026-09-26 |
| 10 | P2 | Tag-helper refactor introduces variable-time secret multiplication | Fixed 2026-09-26 |
| 11 | P2 | Tag-helper refactor accepts an identity checking key | Fixed 2026-09-26 |

P1 means a high-priority security issue; P2 means a narrower correctness,
availability, reporting, or hardening issue. Priority does not remove the
preconditions explained below.

## Suggested work order

1. Fix **7** first: the new reporting path must not accuse honest nodes using
   mismatched request inputs.
2. Finish the same patch's reporting behavior with **8–9**, and restore the
   tag-helper protections in **10–11**.
3. Give **4** a separate, focused DKG storage-boundary fix.
4. Design **2 and 3 together**: a private equality protocol needs both correct
   blinding and independently authorized participation. They are distinct
   requirements; fixing either one alone is insufficient.
5. Coordinate **5** with the encryptor's envelope/binding contract.

This was the original implementation order, not a deployment recommendation.
As of 2026-09-28 every finding in this checklist (1–11) is fixed or addressed
by static review — see the "Status at a glance" table. That does not mean the
protocol is formally audited, and PSS refresh/reshare for the PET checking key
remains explicitly out of this checklist's scope (line above).

## Original findings

### 1. Prevent a malicious contribution from forcing a match

- [x] Addressed by the reviewed DLEQ implementation and PRE admission checks.

**Problem.** A node's identity signature proves who sent a contribution, not
that the contribution was computed using its real checking-key share. Previously,
one malicious node could choose a contribution that cancelled the honest
contributions and made the final equality pass for the wrong owner.

**Reviewed fix.** Both backends now prove that the same secret share underlies
the participant's public verification key and its PET contribution. The proof
challenge binds the participant index, input point, public share, contribution,
and both nonce commitments under a PET-specific domain. Collection and PRE
admission verify the proof before counting the contribution. The BLS prover uses
fresh nonzero zeroized nonces and constant-time secret arithmetic.

**Keep invariant.** A correctly signed but mathematically false contribution
must fail admission before PRE release, even when combining it without proof
verification would make the final equality pass. Reporting success or failure
must never turn an invalid contribution into an accepted one. Verification must
use the authoritative PET public polynomial, not one supplied by the responder.

**Code:** [BLS PET](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/bls12_381/pet.rs),
[Decaf PET](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/decaf377/pet.rs),
[PET verification](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/verification.rs).

### 2. Replace raw fingerprint decryption with equality-only PET

- [x] Fixed 2026-09-28. Full protocol replacement (Stages 1-9 below) plus the
  reporting-gap audit and the on-chain target-leak privacy fix are all done,
  staged, and passing on both backends (673/669 lib tests, `clippy --all-targets
  -D warnings`/`cargo fmt` clean). Implemented per the staged plan in
  `docs/plans/lazy-gliding-gosling.md`. See
  [the blind equality test design doc](pet-blind-equality-test-design.md)
  for the full protocol: parallel additive ciphertext blinding (distributed
  Jakobsson–Juels PET), three network rounds (commit/reveal/decrypt), no
  committee-size increase, retry/dropout semantics modeled directly on this
  repo's own FROST implementation (`sign/v0/coordinator/rounds`).
  - Stage 1 (done, staged): blinding-correctness Chaum-Pedersen proof —
    `Pet::prove_blinding_correctness`/`verify_blinding_correctness` — in both
    `crates/crypto/src/{bls12_381,decaf377}/pet.rs`, mirroring
    `prove_tag_knowledge`'s constant-time bar. Explicit identity-point rule:
    `A_i = z_i·R` must reject identity (this is how a zero blinding scalar is
    caught without ever seeing `z_i`), but `D = T-Y`/`B_i = z_i·D` may
    legitimately be identity (an exact pre-blinding match) and must not be
    rejected. Generic suite in `crates/crypto/src/pet_tests.rs`
    (round-trip, identity-`D` edge case, wrong-digest/target/tag rejection);
    per-backend suites cover field tampering and a hand-constructed
    zero-scalar proof (proving the `A_i == O` check is load-bearing, not
    redundant with the DLEQ math). 60/54 tests passing (bls12-381/decaf377).
  - Stage 2 (done, staged): canonical digests, signed statements, and the
    certificate type, in new
    `bin/orbis-node/src/reporting/v0/types/pet_blind.rs` — `PetBlindContext`
    (`context_digest`, recomputed independently by every participant, never
    trusted from the coordinator), `pet_blind_commit_hash` (`C_i`),
    `pet_blind_selection_digest`, `PetBlindRevealStatement`,
    `PetBlindDecryptStatement`, `PetBlindSignedReveal`,
    `PetBlindCertificate` (+ `certificate_digest`). Two new fixed-width
    codec primitives (`write_fixed_32`/`read_fixed_32`) added to
    `reporting/v0/types/codec.rs` for the `[u8; 32]` digest fields the design
    doc specifies (not hex strings, unlike `ring_state_sha256`). 12 new
    tests (round-trip, domain separation, every-field-changes-the-digest,
    order-independent selection digest); all pre-existing
    `reporting::v0::types` tests (43) still pass unmodified on both
    backends. Marked `#[allow(dead_code)]`/`#[allow(unused_imports)]` at the
    few spots nothing outside this file's own tests references yet — this is
    a binary crate, so these new types have no external caller until Stage
    3-5 wire them in; remove those allows then.
  - Stages 3-8 (done, staged, 2026-09-28): the old single-round
    `CheckRequest`/`CheckResponse` path is fully removed and replaced —
    `reporting/v0/types/pet.rs` (`PetCheckResponseStatement`) deleted,
    `pet/v0/attestation.rs` rewritten around `PetBlindContext`/
    `PetBlindEvidence`, `PET_CHECK_RESPONSE_DOMAIN` removed.
    - Stage 3 — `pet/v0/messages.rs`: `PetMessage` now has
      `Commit{Request,Response}`/`Reveal{Request,Response}`/
      `Decrypt{Request,Response}`, each request boxed (largest field is
      still the embedded `DocumentPayload`).
    - Stage 4 — new `pet/v0/pending_blind.rs`: a responder-side one-use
      secret store holding `z_i`/`commit_salt_i` between commit and reveal,
      modeled directly on `sign::v0::response_state`'s existing FROST
      nonce-state store (fresh pattern, not invented from scratch) —
      double-bound to a `context_digest` comparison and the raw
      authenticated committing peer's id, TTL-bounded
      (`PET_BLIND_PENDING_TTL` = 45s), capped
      (`MAX_PET_BLIND_PENDING` = 1000). `pet/v0/coordinator/handlers.rs`
      rewritten with the three phase handlers; each independently
      re-verifies auth/tag from scratch (no cached approval) and resolves
      the authenticated coordinator identity from the live peer id via new
      `verification::resolve_coordinator_node_key`, never a claimed field.
      A deliberate crypto-reuse trick avoids any change to Stage 1's crypto
      API: commit-phase calls `prove_blinding_correctness` once with a
      throwaway all-zero digest solely to obtain the deterministic
      `(A_i, B_i)` points for hashing into `C_i`; reveal-phase recomputes
      the *same* points via a second call with the real,
      selection-bound digest, this time keeping the genuine proof — the
      crypto-level challenge binds `selection_digest`/`C_i`, so the proof
      genuinely cannot exist before round 2 regardless.
    - Stage 5 — `pet/v0/coordinator/initiator.rs` rewritten as three
      sequential phases (over-ask/threshold/timeout for commit and decrypt;
      exactly-the-selected-set/no-substitution for reveal, matching the
      design doc's cancellation-attack analysis). The initiator's own local
      contribution, when it's a ring member, calls the *same* handler
      methods in-process with its own peer id rather than duplicating the
      validation/crypto a second time — a simplification beyond what FROST's
      own rounds do (they hand-duplicate local-vs-remote), adopted here to
      keep one code path per phase.
    - Stage 6 — shared `verification::build_and_verify_pet_blind_certificate`:
      validates the selected list shape, every reveal's signature/opening
      (`pet_blind_commit_hash` re-check)/blinding-proof, accumulates
      `ΣA_i`/`ΣB_i`, and rejects a zero aggregate via
      `Dkg::public_key_is_identity`. Used identically by the decrypt-phase
      handler, the initiator's own certificate assembly, and PRE admission.
    - Stage 7 — `pre/v0/messages.rs`'s `PreRequestContext.pet_attestations:
      Vec<PetShareAttestation>` replaced with `pet_evidence:
      Option<PetBlindEvidence>` (certificate + threshold signed decrypt
      responses + claimed coordinator identity). `verification::
      verify_pet_admission` rewritten: recomputes `context_digest`
      independently (the coordinator-identity claim is unauthenticated at
      the wire level but self-correcting — a wrong value fails this digest
      comparison, since every reveal was signed against the *real* resolved
      coordinator), re-validates the certificate via Stage 6, then
      independently re-verifies and Lagrange-combines the decrypt shares
      and compares against the certificate's own `aggregate_diff`.
    - Stage 8 — `InvalidCryptoResponse::Pet` replaced with
      `PetBlindReveal`/`PetBlindDecrypt`, each now carrying a full
      `PetBlindContext` alongside the statement (a design correction made
      mid-implementation: the opaque `context_digest` that keeps live wire
      messages compact cannot be independently reconstructed by a
      third-party report validator, which has no other way to learn
      `object_id`/`salt`/`audit_target_object_id`/etc. — so unlike the live
      protocol, report evidence carries the full context, not just its
      digest). `reporting/v0/registry/invalid_crypto/pet.rs` rewritten
      around this: validates the context hashes to the claimed digest,
      binds it to the report envelope/current ring state, then resolves the
      real tag/pub_poly from the bulletin exactly as the old validator did
      and re-runs the specific failing check.
    - Both backends: `cargo check`/`clippy --all-targets -D warnings`/`cargo
      fmt --check` clean across the whole workspace (`cargo check
      --workspace`, both feature sets). New unit tests: 6 for the shared
      certificate validator in `verification.rs` (happy path with real
      cryptography recovering a nonidentity aggregate; tampered `blinded_r`;
      non-opening commitment; duplicate node id; short reveal list; wrong
      target fingerprint), all passing on both backends. Pre-existing
      `pet::v0` (17), `pre::v0` (36), and `reporting::v0` (110) suites all
      still pass. Docker integration test (`test_cli_calls_dkg_for_pet_ring`)
      confirmed passing against the new 3-round flow, 2026-09-28.
  - Reporting-gap audit (2026-09-28, done, staged): a dedicated pass over
    every failure path in the new protocol against the design doc's
    "Reporting and attributable evidence" section, checking for silently
    non-reported misconduct/offline gaps. Three findings, all fixed:
    - **Missing `node_offline` attribution for peer transport failures in
      all three phases.** The design doc explicitly calls for reusing
      `sign/v0/coordinator/rounds`' scheduling *and background-drain*
      pattern ("Drain late responses for attribution... without changing a
      frozen selection"); Stage 5's initiator let each phase's `JoinSet`
      simply drop at the end of its collection loop — `JoinSet::drop`
      aborts every still-in-flight task, so a peer slower than the
      collection deadline could never be attributed as offline, and no
      `node_offline` report existed for PET at all (confirmed via `git
      show HEAD` that the *old* single-round protocol had this same gap —
      not a regression, but also not something to carry forward silently).
      Fixed: new `reporting::v0::observation::offline_observation_from_pet_error`
      (mirrors `offline_observation_from_pre_error`/`_sign_error_scoped`,
      classifying `NetworkConnection`/`NetworkCommunication` send-or-receive/
      `Timeout` as reportable) plus `PetCoordinator::spawn_pet_offline_drain`,
      called at the end of all three collection loops in `initiator.rs`,
      handing the `JoinSet` to the existing `reporting::v0::spawn_error_drain`
      instead of letting it drop. New test
      `observation::tests::classifies_only_transport_failures` extended to
      cover the PET classifier.
    - **Fragile attributability classification.** `verify_decrypt_response`
      distinguished "signed but wrong" (reportable) from "not this node's
      fault" (not reportable) by matching on the error *message text*
      (`msg.contains("per-share proof verification")`) — a future edit to
      that string would have silently stopped reporting genuine DLEQ
      failures, with no compiler warning. Fixed by introducing a
      `ContributionCheckOutcome<T> { Verified, NotAttributable, Invalid }`
      enum that `verify_one_reveal`/`verify_one_decrypt` return directly,
      tagging each internal check as it's made rather than leaving callers
      to infer intent from an error's shape after the fact.
    - **Duplicated attributability logic.** `verify_reveal_response` had its
      own hand-copied opening/decode/proof-verification logic instead of
      calling the shared `verify_one_reveal` the certificate validator uses
      (unlike `verify_decrypt_response`, which already called
      `verify_one_decrypt`) — a latent risk that a future fix to one copy's
      classification wouldn't reach the other. Now calls
      `verify_one_reveal` directly and matches on `ContributionCheckOutcome`.
    - Verified no other classification gaps: admission's collapse of
      per-node certificate/decrypt-share failures into a single
      `PetError::Mismatch` (rather than the old code's per-node
      `queue_pet_admission_report`) was checked against the "could this
      ever fire for a reason other than coordinator tampering or staleness"
      question — by construction, every entry admission re-checks already
      passed the *original* live collector's own per-node verification, so
      a mismatch during admission is always attributable to whoever
      forwarded the evidence (the relay, via the existing
      `report_relay_if_bound` path at the PRE handler call site), never to
      an individual committee member who behaved honestly. This is a
      deliberate difference from the old protocol, not an oversight.
    - Both backends: `clippy --all-targets -D warnings`/`cargo fmt --check`
      clean; `pet::v0` (17, unchanged pass count), `reporting::v0::observation`
      (3, extended) all pass.
  - Stage 9 (done, staged, 2026-09-28): ported the old single-round
    protocol's ~25-test exhaustive suite (`verification.rs`'s old `mod
    tests`, ~1230 lines) to the new 3-round shape — not test-for-test (the
    protocol shape changed too much for a mechanical port), but matching
    its breadth: every category the old suite covered (request/object_id
    binding, audit-authorization rejection/acceptance, live handler
    wiring, admission rejection for every evidence defect, and the
    slot-preemption acceptance-ordering guarantees) has a new-protocol
    equivalent, plus new coverage the old protocol had no concept of
    (independent certificate re-validation at admission, a duplicate-node-id
    rejection, decrypt-phase ordering). 27 tests total (up from the 6
    certificate-only tests Stage 6 landed with), reusing the old suite's
    exact fixture pattern (a degree-0 "identical shares" polynomial, so
    genuinely DLEQ-verifiable contributions and decrypt shares need no real
    DKG ceremony) extended with per-signer `NodeInfo` registration (needed
    now that every phase's handler independently resolves the authenticated
    coordinator's identity, unlike the old protocol). Both backends:
    `clippy --all-targets -D warnings`/`cargo fmt --check` clean; all 27
    pass on both. Pre-existing `pet::v0` (38), `pre::v0` (36),
    `reporting::v0` (110), and `cargo check --workspace` (both feature
    sets) all still pass.
  - `bin/orbis-node/src/tests/integration.rs`'s Docker test
    (`test_cli_calls_dkg_for_pet_ring`) confirmed passing against the new
    3-round flow over real network timing, 2026-09-28 (see the "Stages 3-8"
    entry above) — the one thing this unit-test port still doesn't exercise
    is `pending_blind`'s TTL under real (not simulated) timing, since no
    test currently forces a commit-to-reveal gap long enough to trip
    `PET_BLIND_PENDING_TTL` (45s).
  - **On-chain target-leak gap — fixed, 2026-09-28** (was: "known,
    deliberately unaddressed gap"). Reveal/decrypt-phase
    `invalid_crypto_response` reports previously carried `PetBlindContext`
    (including plaintext `audit_target_object_id`) inside
    `InvalidCryptoResponse::PetBlindReveal`/`PetBlindDecrypt` itself — the
    threshold-signed, on-chain-published payload — so anyone reading the
    chain could recover the audit target of any PET misconduct report, even
    though the chain's only real crypto gate is the ring threshold
    signature over the envelope (confirmed via the Vera/Go source:
    `validateSubmittedReport` only cross-checks binding fields against the
    envelope, never re-verifies evidence content). This matched
    `pet-implementation-plan.md`'s decision inventory item **D7 — "Public
    reporting/evidence privacy, audit-target handling"**.
    - **Fix:** `PetBlindContext` no longer travels inside
      `InvalidCryptoResponse` at all — `PetBlindReveal`/`PetBlindDecrypt`
      now hold only `{ statement, response_signature }`, exactly like
      `Pre`/`Sign`. The context instead rides the same off-chain,
      committee-internal side-channel that already existed for exactly this
      class of problem: `ReportedDocumentEvidence`/`inline_document`. A new
      `pet_blind_context: Option<PetBlindContext>` field was added
      alongside `inline_document` on `InvalidCryptoResponseObservation`,
      `PreparedReport`, `ReportSigningContext`, and
      `ReportValidationContext` (`reporting/v0/observation.rs`,
      `reporting/v0/registry/mod.rs`, `reporting/v0/types/envelope.rs`),
      populated only for PET evidence and `None` everywhere else. A new
      `require_pet_blind_context` helper (`reporting/v0/registry/common.rs`,
      mirroring `require_inline_document_evidence`) fetches it during
      validation; the registry's PET dispatch
      (`registry/invalid_crypto/mod.rs`) now resolves `blind_context` from
      `ReportValidationContext` instead of destructuring it out of the
      decoded evidence. `pet/v0/attestation.rs`'s two observation builders
      set the new field instead of embedding `context` in `evidence`.
    - **Collateral cleanup:** `PetBlindContext::from_canonical_bytes` (and
      its sole helper, `Decoder::read_optional_string`) became genuinely
      dead once nothing decodes a `PetBlindContext` off a canonical byte
      blob anymore — `PetBlindContext` now travels only via serde, exactly
      like `ReportedDocumentEvidence` always has. Both were removed rather
      than suppressed; `canonical_bytes()`/`context_digest()` (still
      load-bearing — every reveal/decrypt statement binds `context_digest`)
      are untouched, and their existing "every field changes the digest"
      test coverage (`pet_blind.rs`) already didn't depend on the round
      trip, so only the now-meaningless `context_round_trips` test was
      dropped.
    - Every other construction site across the codebase (DKG's 7 evidence
      builders, PRE's and Sign's `InvalidCryptoResponseObservation`
      builders, `pipeline.rs`'s three context-assembly sites, and every
      test fixture) picked up `pet_blind_context: None` (or, for the three
      pipeline sites, a genuine pass-through) — found exhaustively by
      letting `cargo check` fail on every incomplete struct literal rather
      than by grep alone, since Rust struct literals have no field
      defaults. Both backends: `clippy --all-targets -D warnings`/`cargo
      fmt` clean; `cargo check` clean with zero new warnings.
  - **Chain-side (Vera/Go) PET evidence handling — added, 2026-09-28.**
    `report.go`'s `evidenceKind` switch had no `pet` case at all before this
    (neither old nor new shape) — a report would still submit (the chain's
    only crypto gate is the ring threshold signature over the envelope),
    but nothing chain-side understood PET evidence's own binding fields the
    way it does for every other kind. Closing this required a small Rust
    wire-format addition first: unlike `PreReencryptResponseStatement`/
    `SignResponseStatement`, `PetBlindRevealStatement`/
    `PetBlindDecryptStatement` didn't carry `chain_id`/`ring_id`/`ring_pk`/
    `ring_state_sha256`/`protocol_version` directly — those lived only in
    `PetBlindContext`, which (per the fix above) never travels on chain
    anymore. Without them, the chain has no way to bind PET evidence to its
    envelope at all (unlike the off-chain Rust validator, which still gets
    the full `PetBlindContext` out-of-band). Added all five as plain fields
    to both statements (user's explicit call after weighing a
    single-hash-digest alternative — these four aren't sensitive, since
    they're already plaintext top-level `ReportEnvelope` fields on the same
    submission, so a hash buys no privacy, only a bigger diff to Vera's
    shared `validateInvalidCryptoResponseStatement`), populated at both
    production sites (`pet/v0/coordinator/handlers.rs`) and both
    reconstruction sites (`pet/v0/coordinator/verification.rs`) from the
    same `blind_context` already in scope there. Go side: new
    `decodePetBlindRevealStatement`/`decodePetBlindDecryptStatement`
    (mirroring `decodePreReencryptResponseStatement`'s shape), a new
    `readFixed32` decoder primitive (PET's `context_digest`/
    `selection_digest`/`certificate_digest`/`commit_salt` are fixed
    32-byte fields with no length prefix — a wire shape nothing else in
    `report.go` used before), `originProtocol` hardcoded per evidence kind
    (`"pet_blind_reveal"`/`"pet_blind_decrypt"`, not a wire field — nothing
    else in this design varies it), committee scope hardcoded to current
    (matching `Pre`, since PET has no refresh/reshare). No changes to the
    shared `validateInvalidCryptoResponseStatement`/`isValidInvalidCrypto*`
    functions. New cross-language golden-vector tests both ways
    (`invalid_crypto_response_pet_blind_{reveal,decrypt}_payload_matches_golden_vector`
    in `reporting/v0/types/tests.rs`; `TestReportPetBlindEvidenceDecodingMatchesRustGoldenVectors`
    in Vera's `report_test.go`) prove the two decoders agree field-for-field
    on real Rust-produced bytes, not just that each side round-trips against
    itself — this evidence kind's first real cross-language check. Both
    orbis-rs backends: `clippy --all-targets -D warnings`/`cargo fmt`/
    `cargo check --workspace` clean; `pet::v0` (61)/`reporting::v0` (113,
    bls12-381) or (110, decaf377) pass. Vera: `go build`/`go vet`/`gofmt`
    clean; `go test ./x/orbis/keeper/...` passes. Pushed to Vera's
    `pet-impl` branch (commit `f0fc130`, "add PET reporting") and
    `docker/VERA_REF` bumped to it, so the Docker chain image actually
    includes this — see the e2e entry below, which is what proved it.
  - **Docker e2e report test — added, found + fixed 2 more real bugs,
    2026-09-29.** `test_pet_invalid_decrypt_share_triggers_on_chain_report`
    (`bin/orbis-node/src/tests/reporting.rs`) mirrors
    `test_invalid_crypto_response_triggers_on_chain_report`'s PRE-share
    corruption pattern and `tests::integration::test_cli_calls_dkg_for_pet_ring`'s
    PET-gated ring/tag setup: corrupts node3's stored PET checking-key
    share (a distinct storage namespace from the main ring key — required
    a new `LOCAL_STORAGE_KEY_TYPE_PET_RING_KEY` unsafe-testing RPC key
    type, `crates/proto/.../unsafe_testing_service.proto` +
    `unsafe_testing/service.rs`), then runs PET-gated PRE and waits for the
    on-chain `invalid_crypto_response` event. Scoped to decrypt-phase only
    — reveal only touches a fresh per-attempt ephemeral scalar that's
    never stored, so it can't be corrupted this way (and is already
    covered at the unit level); commit has nothing to misreport (no proof
    yet). Runs on both backends (decrypt's over-ask doesn't depend on the
    Sign backend the way FROST-vs-BLS does), unlike the PRE/Sign tests
    above.
    - This is PET's first real exercise of the full
      observation → queue_report → prepare → sign → submit → chain-decode
      pipeline — every prior PET test (unit or the happy-path Docker test)
      stopped short of it. It surfaced three real, previously-undetected
      gaps, in order:
      1. **Decrypt-phase late-arrival gap.** Decrypt over-asks the whole
         committee and breaks out of collection as soon as `threshold`
         genuine shares arrive; a still-in-flight task that later resolves
         *successfully* (not just erroring) was silently discarded by the
         plain error-only drain (`spawn_error_drain`'s `Ok((_, Ok(_))) => {}`),
         letting a misbehaving node dodge attribution purely by resolving
         after enough honest shares already arrived. Fixed: a new
         decrypt-specific `spawn_pet_decrypt_drain` (`pet/v0/coordinator/initiator.rs`)
         that re-runs `verify_decrypt_response` on late-but-successful
         responses too. Reveal has no equivalent gap (exact-sized ask, no
         "extra" to race past); commit has nothing to misreport.
      2. **Empty `accused_peer_id`.** `verify_reveal_response`/
         `verify_decrypt_response` built their `InvalidCryptoResponseObservation`
         with `accused_peer_id: String::new()` — a placeholder that was
         never actually wired up — but `ReportEnvelope` requires it
         non-empty, so every PET reveal/decrypt invalid-proof report failed
         `validate_report_envelope_shape` and was silently swallowed by
         `let _ = queue_report(...).await;`. Fixed by threading the real
         peer id (already in scope at every caller — `local_peer_id` for
         each phase's own local contribution, `peer_id` for a remote
         response) through both functions as a new parameter.
      3. **Chain build/deploy gap, not a code bug.** `docker/VERA_REF` was
         still pinned to a commit predating all of this session's Go-side
         work, so the Docker-built chain genuinely didn't understand
         `pet_blind_reveal`/`pet_blind_decrypt` yet
         (`unsupported invalid crypto evidence kind`). Resolved once the
         user pushed Vera and bumped `VERA_REF` (see the entry above).
    - Diagnosed via `docker logs -f <container>` run in parallel with the
      test (started immediately after the container appears, so it
      captures the full run rather than `IntegrationTestNetwork`'s own
      last-200-lines-per-container failure dump) — the last-200-line cap
      hid every relevant line for a ~10-minute run dominated by debug-level
      networking noise; see `feedback_docker_compose_log_truncation.md`.
    - Passes clean end-to-end (single attempt, no retry needed) on both
      backends after all three fixes; `pet::v0` (38)/`reporting::v0`
      (113 bls12-381 / 110 decaf377) unit suites, `clippy --all-targets -D
      warnings`/`cargo fmt` both clean on both backends throughout.
  - **PSS extended to the PET checking key — Stage 1 (`RefreshPet`), added
    2026-09-29.** The PET checking key had a `Fresh` ceremony
    (`SessionKind::FreshPet`, auto-chained after the main ring's `Fresh` DKG)
    but no PSS refresh/reshare of its own — its shares never aged out and,
    critically, never moved to a new committee on reshare. This stage closes
    the refresh half only, staged via the plan in
    `docs/plans/lazy-gliding-gosling.md` (still on disk; Stage 2 reshare
    mechanics and Stage 3's reshare-atomicity gate are not started). Two
    product decisions (user, 2026-09-29) shape the design: PET refresh is
    **fully independent** of the main key's own refresh — its own `last_pss`
    on the PET `RingShareBundle` (`RingShareBundle::save_by_pet_ring_key`/
    `load_by_pet_ring_key`), scheduled and triggered on its own clock, never
    chained either direction — and there is **no health-check gate**
    (unlike main-key refresh's live threshold-signing dry-run): PET has no
    live signing op to dry-run against; a "prove success" mechanism is an
    explicitly deferred future brainstorm, out of scope here.
    - New `SessionKind::RefreshPet { ring_id }` (`dkg/v0/messages.rs`),
      mirroring `FreshPet`'s ring_id-keyed shape; a new domain-separated
      `derive_refresh_pet_session_id` (`helpers/session_ids.rs`); a new
      `validate_refresh_pet_session_init_for_version` (`helpers/validation.rs`)
      resolving the ring directly by `ring_id` (matching `FreshPet`'s own
      resolution shape, not `Refresh`'s `RingIndex`/`ring_pk_hex` lookup) and
      checking the PET bundle's own `last_pss` against `pss_interval`.
    - Full ceremony-start plumbing mirroring `Refresh` exactly, one level
      down: `validate_refresh_pet_start_sender`/`coordinate_refresh_pet`/
      `coordinate_refresh_pet_as_claimed_leader`/`start_refresh_pet`
      (`network/ceremony_start.rs`), new `DkgControlMessage::StartRefreshPet`/
      `RefreshPetStartAccepted`/`RefreshPetNotDue` (`transport/types.rs`),
      dispatch wiring in `control_client.rs`/`control_handler.rs`.
    - `phases/phase4.rs` gained a dedicated `RefreshPet` branch (not grouped
      with `Refresh`'s staging/health-check path, since PET skips staging
      entirely): loads the old PET bundle, builds the combined bundle via a
      new `build_refresh_pet_ring_bundle` (`helpers/ring_bundle.rs`), and —
      a real gap identified and closed proactively, not requested — verifies
      the combined PET public key still matches the ring's existing PET key
      before persisting (mirroring `Refresh`'s own
      `public_key_matches_storage_key` drift check, which PET has no
      equivalent of purely because it skips the health-check staging step
      that check normally rides along with). Direct write via
      `save_by_pet_ring_key` on success, no staging.
    - `pss/v0/mod.rs`'s `pss_ring` now runs a second, fully independent
      check every tick: `check_and_trigger_refresh_pet`/`trigger_refresh_pet`,
      combined with the main key's own outcome via
      `main_result.and(pet_result)` — both always attempted regardless of
      the other's result, never gated behind one another.
    - Remaining ~15 mechanical `SessionKind::Refresh`-matching sites (evidence/
      reporting emission, commitment-audit's identity-rejection exclusion,
      public batch/repair phase sets, prepare/prepare_participant DKG-mode
      selection, session_state ceremony-kind/polynomial-mode) extended the
      same way `FreshPet` was added alongside `Fresh` — grouped with
      `Refresh` wherever refresh-shaped handling applies, given its own arm
      only where health-check-skip or storage-key-shape genuinely differs
      (`public_contribution.rs`, `public_repair.rs`, `phase4.rs`'s
      persistence branch).
    - New tests: 4 unit tests directly on `check_and_trigger_refresh_pet`
      (skips when not `requires_pet`, skips when `pet_pk` unfinalized, skips
      before its own interval elapses, triggers when due) plus one
      `pss_ring`-level test proving the PET check fires even when the main
      key's own refresh is not due (`pss/v0/tests.rs`); 6 session-init-level
      tests mirroring `Refresh`'s own suite — accepts an external sender
      when the local node is in the PET ring, rejects when it isn't, rejects
      too-soon, rejects already-in-progress, plus the `ring_id`-mismatch
      pair `FreshPet` already has in `dkg.rs` (`dkg/v0/tests/refresh.rs`).
      `dkg::v0` (294)/`pss::v0` (44) lib suites pass on both backends;
      `clippy --all-targets -D warnings`/`cargo fmt` clean both backends.
      Staged not committed. No Docker e2e test yet (Stage 5 of the plan) —
      reshare's atomicity gate (Stage 3) needs to land first for a
      meaningful end-to-end committee-rotation test.
  - **PSS extended to the PET checking key — Stage 2 (`ResharePet`), added
    2026-09-29.** Mirrors `Reshare`'s own ceremony mechanics (old/new
    committee resolution, Dealer/Receiver/DealerReceiver role assignment,
    share redistribution) for the PET checking key — built as a **standalone
    ceremony** per the plan: reachable directly (as its own tests do), not
    yet chained to or gated by the main ring's own `Reshare` completion.
    Reshare is inherently riskier to redistribute than refresh (a Dealer
    holds material a departed committee shouldn't still have), so unlike
    Stage 1's direct-write `RefreshPet`, `ResharePet` stages its result the
    same way main `Reshare` does — new `PendingReshareBundle::save_pet/
    load_pet/clear_pet` (`ring_state.rs`) under a new
    `LocalStorageKeys::PendingResharePetBundle` variant, keyed by `ring_id`
    (a distinct namespace from the main key's `PendingReshareBundle`, same
    reasoning as `PetRingKey` vs `RingKey`) — with **no promotion path yet**
    (Stage 3 adds the confirmation-driven promotion, once it defines what
    "confirmed" means when gating the main ring's own bulletin post).
    - New `SessionKind::ResharePet { ring_id, new_peer_node_keys, new_threshold }`
      — no separate `bulletin_post_id` field like main `Reshare` has:
      `ring_id` alone is PET's identity anchor (matches `FreshPet`/
      `RefreshPet`), so it already resolves the bulletin post directly.
      New `derive_reshare_pet_session_id` (`"reshare-pet"` domain), new
      `validate_reshare_pet_session_init_for_version`/`validate_reshare_pet_init`
      resolving by `ring_id` directly (no `RingIndex` lookup), new
      `build_reshare_pet_params` (mirrors `build_reshare_params`, loads the
      old share via `RingShareBundle::load_by_pet_ring_key`), new
      `validate_reshare_pet_start_sender`/`coordinate_reshare_pet`/
      `start_reshare_pet` (`network/ceremony_start.rs`, mirroring the
      `Reshare` trio exactly), new `DkgControlMessage::StartResharePet`/
      `ResharePetStartAccepted` (no "not due" variant — reshare is always
      due once announced, matching `Reshare`'s own shape).
    - `phase4.rs` gained a dedicated, fully self-contained
      `complete_reshare_pet_phase4` — handled *before* the generic Dealer
      early-return (a departing PET Dealer's cleanup must not touch the
      main-ring storage/index machinery `ring_storage::cleanup_departing_dealer`
      assumes): a Dealer completes with no crypto and its old PET share left
      in place untouched (Stage 3 decides when it's safe to remove); a
      Receiver/DealerReceiver computes its new share, rejects an identity
      result, verifies the redistributed checking key still equals the
      ring's known `pet_pk` (fetched fresh off the bulletin — PET has no
      wire-known identity string the way `ring_pk_hex` is for main `Reshare`,
      so this mirrors `FreshPet`'s own precedent of a direct bulletin read
      at completion time), then stages via `PendingReshareBundle::save_pet`.
    - **A real, latent class of bug found and fixed by this stage's own
      "full rotation" test (disjoint old/new committees — every old member a
      pure Dealer, every new member a pure Receiver)**: several
      `SessionKind::Reshare`-gated `bool` flags across the DKG subsystem
      don't participate in Rust's match-exhaustiveness checking (they're
      plain `matches!()` calls, not exhaustive `match` arms on `SessionKind`
      itself), so adding `ResharePet` compiled clean while silently taking
      the *wrong* branch at several of them — the mechanical sweep for
      Stage 1 and this stage's own initial pass both missed these because
      `cargo check` cannot catch a non-exhaustive boolean condition the way
      it catches a non-exhaustive `match`. Found by running the ceremony
      end-to-end rather than by further static review, then fixed one at a
      time by tracing each resulting failure back to its exact flag:
      - `phase2.rs`'s own `is_reshare` (distinct from `phase1.rs`'s,
        already-fixed one) drives which peer-route map resolves a share's
        recipient (`reshare_new_node_id_to_peer_id` vs
        `current_node_id_to_peer_id`). Wrong for `ResharePet` meant a
        Dealer's shares for new-committee members resolved through the
        *old* committee's peer map instead — since both committees use
        small 1-based indices, this silently misrouted shares to old
        committee peers by coincidental index overlap rather than failing
        loudly, surfacing as "share received but this node is a pure Dealer"
        on the misrouted recipient.
      - `SessionSnapshot::is_reshare()` (`state_machine.rs`) — a single
        method backing five state-machine decisions (expected commitment
        counts, share-ack gating, Phase 4 completion gating). Fixing the one
        method fixed all five call sites at once.
      - `reshare/selection.rs`'s three `Reshare`-only gates: valid-share
        recording/acking silently no-opped for `ResharePet` (dealer
        selection would never converge, hanging Phase 4 forever for a
        receiver — not yet observed as a symptom only because the routing
        bug above was hit first), the `still_needed` poll for the ack-retry
        loop, and `ReshareParticipantSet` message validation (outright
        rejected as "non-reshare session").
      - `network/public_publish.rs`'s own `is_reshare` — decides whether a
        `CommitmentAudit` publish uses the next-committee identity; wrong
        for `ResharePet` would have mismatched the receiving side's
        already-fixed `expected_public_origins` (Stage 2's own earlier
        mechanical-sweep fix).
      - `ceremony_start.rs`'s `validate_reshare_transport_routes` — a
        security-relevant check (the new committee's transport routes in a
        `Prepare` must match Vera's authoritative NodeInfo) that a `let
        SessionKind::Reshare {..} = &prepare.kind else { return Ok(()) }`
        silently skipped entirely for `ResharePet`, restructured into a
        `match` since `Reshare`/`ResharePet` don't share every field name.
      - `session_state/lifecycle.rs`'s stalled-pure-Receiver classification
        (for `node_offline` stall attribution) extended for consistency —
        a reporting-coverage gap, not a correctness one.
      - Deliberately **not** extended: `pss_offline.rs`'s
        `validate_offline_relay_transition` (rejects non-`Reshare` outright)
        and `reporting.rs`'s `is_pure_next` that feeds it — both belong to
        the multi-hop offline-observation *relay* path (forwarding a
        `StartResharePet` to an unreachable leader, from a third node),
        which only matters for that specific fault-tolerance corner case,
        not the ceremony's core correctness; left for Stage 4's own
        reporting-attribution pass alongside PET's other reporting gaps.
    - **A real, independent bug found and fixed in the test double itself**:
      `DummyBulletin::post_finalized_ring` (`crates/bulletin/src/dummy/mod.rs`)
      never copied `RingFinalizationPayload.pet_pk` into the stored
      `RingPayload` — every confirmation-counting/conflict check tracked
      `ring_pk` only. Harmless for every *other* existing test (none needed
      a `DummyBulletin`-backed multi-node PET finalize to actually read
      `pet_pk` back afterward), but blocked this stage's own ceremony tests
      immediately (`ring_pk` finalized correctly; `pet_pk` silently stayed
      `None` forever). Fixed by tracking `(ring_pk, pet_pk)` together through
      the existing pending/conflict-check machinery.
    - Two full 3-node ceremony tests exercising the actual redistribution
      math end-to-end (`dkg/v0/tests/reshare.rs`): full rotation
      ({A,B,C}→{D,E,F}, pure Dealers/Receivers, found the routing bugs
      above) and same-committee threshold change ({A,B,C}→{A,B,C}, t=2→1,
      all DealerReceivers — proves the redistributed share value actually
      changes while the checking key itself doesn't). Both assert the old
      dealers' live PET bundles are byte-for-byte untouched and the new
      committee's staged bundles recover the original checking key via
      `PubPoly::eval(0)`. Plus 3 session-init rejection tests (ring not
      PET-enabled, mismatched announced committee, no bulletin
      announcement).
    - `dkg::v0` (305)/`pss::v0` (44) lib suites pass on both backends;
      `bulletin` crate's own suite (13, including the fixed
      `post_finalized_ring` coverage) passes; `clippy --all-targets -D
      warnings`/`cargo fmt` clean both backends. Staged not committed.
      Stage 3 (the atomicity gate deferring the main ring's bulletin post
      until `ResharePet` also completes, plus the confirmation-driven
      promotion this stage's staging sets up for) is next.
    - **Follow-up cleanup, same day**: the main-ring and PET validators
      (`validate_reshare_session_init_for_version`/
      `validate_reshare_pet_session_init_for_version` in `validation.rs`;
      `validate_reshare_init`/`validate_reshare_pet_init` in
      `session_init.rs`) had near-verbatim duplicated boilerplate wherever
      the logic didn't actually depend on ring identity or resolution
      strategy. Extracted into four shared helpers that both callers pass
      their own already-resolved `RingPayload`/identifiers into —
      `validate_reshare_committee_shape`/
      `validate_reshare_ring_payload_matches_proposal` (structural and
      authoritative-committee checks) and
      `authorize_new_committee_membership`/`resolve_reshare_transport_routes`
      (new-committee membership authorization and old/new route resolution
      + leader check). Deliberately left un-merged: the two functions' own
      *ring resolution* step (`RingIndex` lookup + wire fallback for the
      main key vs a direct `ring_id` read for PET) — that's the one place
      the two are genuinely different, and after this same stage's own
      `is_reshare`-flag bugs, a kind-conditional branch inside a shared
      resolution function is exactly the shape of risk worth avoiding
      rather than reintroducing in the validation layer. Confirmed
      behavior-preserving: `dkg::v0` (305) unchanged on both backends,
      `clippy --all-targets -D warnings`/`cargo fmt` clean both backends.

**Problem.** Contributions are still raw `S_i = x_i R`. A threshold of them
combines into `xR`, so the collector can compute `F(owner) = T - xR`. This reveals
the complete deterministic fingerprint even on a mismatch. The collector can
link recovered fingerprints and test known/candidate identities offline.
Recovering the private key or solving a discrete logarithm is unnecessary.

**Required fix.** Use a reviewed, target-bound PET construction that blinds the
encrypted difference before threshold decryption and proves correct processing.
Its blinding must be fresh, nonzero, and remain unknown to the permitted
adversarial coalition. Do not expose raw tag-decryption contributions as a
shortcut or fallback. This checklist deliberately does not prescribe a new
cryptographic protocol; agree and review that protocol before implementing it.

**Done when.** The transcript of a mismatching check does not expose the original
fingerprint or an offline identity-testing/linking handle beyond the intended
equality result. Proofs of contribution correctness alone do not achieve this.

**Code:** [PET trait](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/trait/pet.rs),
[BLS PET](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/bls12_381/pet.rs),
[Decaf PET](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/decaf377/pet.rs),
[PET coordinator](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/initiator.rs).

### 3. Authorize the audit request at every PET responder

- [x] Fixed 2026-09-26. `PetCheckContext` (`pet/v0/messages.rs`) gained three
  fields mirroring `PreRequestContext`'s existing shape: `token_string`
  (raw JWT), `audit_target_object_id` (plain field — protected by ACP
  itself, not by JWT binding, same reasoning as `PreRequestContext`'s
  identical field), and `valid_window`. A new function,
  `verify_pet_audit_authorization` (`pet/v0/coordinator/verification.rs`),
  independently re-verifies the JWT the same way PRE's own responders
  re-verify `PreRequestContext::token_string` (`resolve_jwt_did` with the
  same shared constants), binds it to the request's `object_id`/`salt`
  (closing token-for-a-different-document replay), derives `actor_id` via
  the existing `request_actor` helper, and runs the existing
  `check_pet_permission` gate. Wired into exactly one place —
  `handle_check_request` (`pet/v0/coordinator/handlers.rs`), right after
  `verify_pet_check_request` returns and before the secret share is ever
  touched — since that is the only entry point reachable from a raw wire
  message with no other upstream authentication; `verify_pet_check_request`
  itself, `initiate_pet_check`'s own local path, and `verify_pet_admission`
  are all reached only through already-authenticated call chains (PRE's own
  ingress re-verifies the same JWT before ever calling them) and were left
  untouched, keeping the fix minimal. `initiate_pet_check` gained a new
  `token_string` parameter, threaded from `check_pet_if_required`
  (`pre/v0/service/stages.rs`) via `authorized.token_str.clone()`.
  `verify_pet_admission`'s own `PetCheckContext` construction populates the
  three new fields with real, correct values (`audit_target_object_id`,
  `valid_window`) or an explicitly-commented placeholder (`token_string`,
  since that path never reads it — it already ran its own equivalent
  `check_pet_permission` check beforehand). New tests: four covering
  `verify_pet_audit_authorization` directly (garbage token, wrong
  object_id, wrong salt, genuine acceptance) plus two end-to-end wiring
  tests through `handle_message`/`handle_check_request` (rejects with no
  valid authorization; accepts with a valid, correctly-bound one) — total
  25 `pet::v0` tests (was 19), all green both backends. `pre::v0` (36),
  `reporting::v0` (97) unaffected. `cargo check`/clippy(`-D
  warnings`)/fmt clean both backends. Docker integration test
  (`test_cli_calls_dkg_for_pet_ring`, the only test exercising the real
  end-to-end JWT-authorized flow) re-run to confirm the legitimate path
  still works. Staged not committed.

**Problem.** The direct peer request supplies a document/tag, but the responder
does not independently authenticate an auditor and authorize the exact audit
target before using its share. A copied valid tag-knowledge proof is transferable;
presenting it does not establish permission to audit. The normal initiator's ACP
check does not constrain a malicious initiator or direct peer request.

**Required fix.** Carry an authenticated, request-bound audit context to each
participant. Each responder must verify the actor, target, document selection,
ring/policy context, validity/replay rules, and required ACP permission before
contributing. Derive the fingerprint target from that same authorized identity.
Preserve the existing document ACP requirement unless a separate design decision
explicitly changes it. Peer identity alone is not auditor authorization.

**Done when.** Direct peer requests cannot obtain contributions or an equality
oracle by bypassing the normal PRE entry point. Altering the authorized target
or document context fails before a secret share is used.

**Code:** [PET messages](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/messages.rs),
[PET responder](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/handlers.rs),
[PET verification](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/verification.rs).

### 4. Bind FreshPet storage to the authorized ring

- [x] Fixed 2026-09-26, in two parts:
  1. **Reject the mismatch at admission.** `handle_session_init`'s
     `FreshPet` arm (`dkg/v0/coordinator/message_handlers/session_init.rs`)
     now binds `kind.ring_id` and requires it equals the outer,
     already-authorized `ring_id` *before* calling `validate_fresh_pet_init`
     — closing the confused-deputy gap where authorization checked one
     field (the outer `ring_id`) while finalization used a different,
     unvalidated one (`kind`'s own inner `ring_id`).
  2. **Separate storage namespaces (defense in depth).** Added
     `LocalStorageKeys::PetRingKey(String)` (`local-storage/src/trait.rs`),
     distinct from `RingKey(String)` (main-key storage) even though both
     previously wrapped a plain string with no structural collision
     guarantee. Added `RingShareBundle::{save,load}_by_pet_ring_key`
     (`ring_state.rs`) — deliberately without `save_by_ring_key`'s
     polynomial-history stashing, since PET has no refresh/reshare yet and
     so no "previous generation" to retire. Repointed every PET-specific
     call site to the new methods: the `FreshPet` write in
     `persist_ring_bundle` (`dkg/v0/helpers/ring_bundle.rs`), the three PET
     bundle reads in `pet/v0/coordinator/{handlers,verification,initiator}.rs`,
     and the report-verification read in
     `reporting/v0/registry/invalid_crypto/pet.rs`. Every other
     `RingKey`/`save_by_ring_key`/`load_by_ring_key` call site (Refresh,
     Reshare, refresh-health-check, PSS refresh) is genuinely keyed by
     `ring_pk_hex` and was left untouched. New tests:
     `test_dkg_session_init_rejects_fresh_pet_ring_id_mismatch` (mismatch →
     `Unauthorized`, fires before any bulletin read — no ring is even
     seeded in this test) and
     `test_dkg_session_init_fresh_pet_matching_ring_id_passes_the_mismatch_check`
     (confirms the rejection above isn't vacuous — a matching `ring_id`
     passes this specific check) in `dkg/v0/tests/dkg.rs`; and
     `pet_ring_key_and_ring_key_are_separate_namespaces` in `ring_state.rs`
     — writes a main bundle and a PET bundle under the *same* string key
     against a real `RedbStorage` and confirms neither clobbers the other.
     `cargo check`/clippy(`-D warnings`)/fmt clean both backends; full
     `dkg::v0` suite (294), `pet::v0` (19), `reporting::v0` (97),
     `ring_state` (5) green on bls12-381; `pet::v0` (19), the two new
     session_init tests, and the namespace test re-confirmed green on
     decaf377 too (storage-layer code is backend-independent). Staged not
     committed.

**Problem.** A DKG prepare request contains an outer `ring_id`, used for
authorization, and an inner `FreshPet { ring_id }`, used for persistence.
Admission does not require equality. A malicious canonical leader authorized
for pending ring A can name an existing ring B internally, causing overlapping
participants to overwrite B's stored bundle. The shared storage namespace also
allows targeting the representation used for a main PRE/signing bundle.

**Impact.** Persistent cross-ring availability damage. The review did not establish
extraction of the previous secret. Persistence happens before finalization, so
later chain rejection does not protect the overwritten material.

**Required fix.** Reject mismatched identifiers before session creation; derive
the storage destination from the validated ring identity. Separate PET and main
key storage namespaces, and ensure a fresh ceremony cannot overwrite an unrelated
existing bundle.

**Done when.** An A-authorized ceremony cannot select B's PET or main-key storage
entry, including when B is idle and later finalization would fail.

**Code:** [DKG admission](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/dkg/v0/coordinator/message_handlers/session_init.rs),
[bundle persistence](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/dkg/v0/helpers/ring_bundle.rs),
[DKG phase 4](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/dkg/v0/coordinator/phases/phase4.rs).

### 5. Bind the original payload encryption to its ownership tag

- [x] Fixed 2026-09-26. Added `crypto::context::PetTagBinding` (ring_id,
  pet_pk, ephemeral_point, masked_fingerprint) as a new `Option` field on
  `CiphertextContext` (`crates/crypto/src/context.rs`) — folded into
  `canonical_encode`/`context_digest`, so it's part of both the AES-GCM AAD
  and the payload's own Schnorr proof's Fiat-Shamir challenge. Zero code
  changes needed in `encrypt_secret`/`verify_encryption` in either backend —
  they only ever call the generic `context::` helpers.
  `cli-tool/commands/crypto.rs`'s `prepare_pet_tag` split into
  `generate_pet_tag` (tag ciphertext only, no proof — step 1) and
  `prove_pet_tag_knowledge` (proof over an already-encrypted payload —
  step 3), with `prepare_secret` gaining a new `pet_tag_binding` parameter
  (step 2) folded straight into the context it builds — enforcing the
  required noncircular order end to end. `pre::v0::helpers::build_ciphertext_context`
  and the private duplicate in `pet::v0::coordinator::verification.rs` both
  gained a new `pet_pk_hex: Option<&str>` parameter and a shared
  `pre::v0::helpers::build_pet_tag_binding` helper (mirroring how
  `check_document_id_binding` is already reused across both modules) that
  rebuilds the binding from the document's own `pet_tag` field, erroring on
  an inconsistent ring/document state rather than silently treating it as
  untagged. Every real call site already had `ring_payload`/`document` in
  scope, so no new data-fetching was needed. ~30 other direct
  `CiphertextContext` literals (PRE's own crypto-primitive tests/benches,
  `store_secret`/`reporting` fixtures) and ~25 `prepare_secret` call sites
  (the real CLI command, Docker/fault-injection/scale-testing suites, all
  three `orbis-bench` runners) needed only a mechanical `pet_tag: None`/
  `None` — none of them exercise PET. New tests: `context.rs` gained a
  presence/content encoding test plus extended
  `test_context_individual_field_tampering_fails` (shared generic PRE test
  suite, both backends) with tampered/stripped-tag cases proving
  `verify_encryption` fails exactly like any other tampered field;
  `cli-tool/commands/crypto.rs` gained
  `reattaching_a_different_tag_fails_the_original_payload_proof` — the
  direct "Done when" proof: Charlie's original payload proof fails against
  Alice's freshly generated, independently-valid, reattached tag, while the
  untouched original context still verifies. `cargo check`/clippy(`-D
  warnings`)/fmt clean across `crypto`, `cli-tool`, `orbis-node`,
  `orbis-bench`, both backends. `crypto` (53/47), `cli-tool` (22/22),
  `pet::v0` (25), `pre::v0` (36), `reporting::v0` (97), `store_secret` (10)
  all green; Docker integration test
  (`test_cli_calls_dkg_for_pet_ring`) re-run to confirm the legitimate
  end-to-end flow still encrypts/decrypts correctly under the new
  construction order. Staged not committed.

**Problem.** The tag proof commits to the payload, but the payload's original
encryption proof/AAD does not commit to the tag. Someone with the public envelope
and necessary context/salt can copy Charlie's ciphertext and proof, generate a
fresh Alice tag using their own randomness, and produce a valid tag proof over
the copied payload. Both proofs verify, and an honest PET matches Alice.

**Impact boundary.** The association failure is real, but replacing the attachment
changes the document ID. Actual PRE disclosure also requires authorization for
that new document ID, Alice-target ACP, and the existing reader/capability checks.
This is not an unconditional bypass of the original document's ACP.

**Required fix.** Use the noncircular construction order:

1. Generate the tag ciphertext.
2. Bind the canonical tag, authoritative PET key, and ring/suite identity into
   payload encryption AAD and its proof context.
3. Generate the tag-randomness proof over the completed payload and payload proof.
4. Compute the final document ID.

Do not include the later tag proof or final document ID in the earlier payload
binding. This fixes reattachment; it does not replace Bankd's separate proof of
truthful transaction ownership.

**Done when.** Replacing a copied payload's tag causes its original payload proof
to fail, even if the replacement tag has a valid proof of its own.

**Code:** [payload context](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/context.rs),
[tag proof context](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/pet_context.rs),
[tag preparation](/Users/jesse/Desktop/source/orbis-rs/bin/cli-tool/src/commands/crypto.rs).

### 6. Prevent invalid responses from consuming honest-node slots

- [x] Addressed by the reviewed collector ordering.

**Problem.** Previously the collector inserted an untrusted `from_node_id` into
`seen_node_ids` before checking its signature. A bad response claiming an honest
node's ID poisoned that slot, so the later honest response was discarded.

**Reviewed fix.** The acceptance order is now committee resolution → signature
verification → canonical decoding → DLEQ verification → deduplication insertion
→ counting. Rejected responses do not mutate the accepted-ID set. The transport
response manager consumes the authenticated sender's slot, not the claimed ID.

**Keep invariant.** Invalid or spoofed responses cannot prevent later valid
contributions from those claimed IDs being accepted; valid duplicates count only
once. Collection continues toward a threshold of distinct valid shares. PRE
admission independently rejects invalid forwarded evidence.

**Code:** [response verification](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/verification.rs),
[collector](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/initiator.rs).

## New findings from the proof/reporting review

### 7. Prevent document-ID substitution from framing an honest responder

- [x] Fixed 2026-09-26. Verified: `verify_pet_admission` and the initiator's
  own local-share path were already safe (both resolve `document`/`object_id`
  together via `resolve_document_and_ring_payloads`, which already calls
  `check_document_id_binding`, before PET ever sees them) — the only actually
  vulnerable caller was `handle_check_request`, the standalone PET P2P
  responder. Fix: `check_document_id_binding` (`pre::v0::helpers`) widened to
  `pub(crate)`; `verify_pet_check_request` — the one shared verification
  point all three callers go through — now calls it on `ctx.object_id`/
  `ctx.document` before doing anything else with either, closing the gap for
  all three callers uniformly (the two already-safe ones pay a redundant but
  harmless recheck). New regression test
  `verify_pet_check_request_rejects_a_document_object_id_mismatch` (pairs a
  genuine document with a different document's id, same ring) proves the
  exact attack shape is rejected before any proof is computed or signed.
  `cargo check`/clippy(`-D warnings`)/fmt clean both backends; `pet::v0` (17,
  incl. the new test) and `pre::v0` (36) green. Staged not committed.

**Problem.** The responder computes its contribution from `ctx.document`, but
signs the independently supplied `ctx.object_id` without confirming the two
match. The signed response no longer directly binds the tag-proof digest.

**Attack.** A malicious coordinator supplies valid document A with document B's
ID, both in the same ring. The honest responder signs a correct proof for A's
input point while naming B. Report validators load B by that signed ID, verify
against B's different input point, and can approve a false invalid-crypto
accusation against the honest responder.

**Required fix.** Recompute and validate the document content ID before producing
any signed PET response, for both inline and stored-document requests. Reuse or
factor the equivalent PRE document-ID validation. Ensure the signed evidence
identifies exactly the proof input actually processed; directly binding the input
point/digest can provide additional protection but does not replace consistent
document selection.

**Done when.** `document = A, object_id = id(B)` fails before signing. A correct
response for A cannot be accepted as evidence of an invalid response for B.

**Code:** [PET responder](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/handlers.rs),
[PET request verification](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/verification.rs),
[report validation](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/reporting/v0/registry/invalid_crypto/pet.rs),
[existing PRE ID check](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pre/v0/helpers.rs).

### 8. Preserve the timestamp needed to report inline documents

- [x] Fixed 2026-09-26. `PetCheckResponseStatement` gained `timestamp: Option<u64>`
  (mirrors `PreReencryptResponseStatement::timestamp` exactly, using the
  existing `write_optional_u64`/`read_optional_u64` codec primitives — no new
  codec work needed). `PetCheckStatementContext` gained the same field,
  threaded from `document.timestamp`/`ctx.document.timestamp` at all three
  construction sites (`handlers.rs`, `initiator.rs`,
  `verification.rs::verify_pet_admission`). `resolve_pet_tag`
  (`registry/invalid_crypto/pet.rs`) now passes `statement.timestamp` instead
  of a hardcoded `None`. New round-trip tests
  (`pet_response_statement_with_no_timestamp_round_trips`, and the updated
  `pet_statement()` fixture now has `Some(timestamp)` by default) prove the
  field survives serialization and that a timestamped statement's bytes
  differ from an untimestamped one's. Did not add a full end-to-end
  registry-level report-validation test for a timestamped inline PET
  document — the underlying `require_inline_document_evidence`/
  `generate_document_id` mechanism is already covered for timestamped
  documents via PRE's existing `pre_proof_refutation_accepts_matching_inline_document`,
  so the remaining risk was purely "is the right value threaded through,"
  which the round-trip tests plus the code change directly address.
  `cargo check`/clippy(`-D warnings`)/fmt clean both backends; `pet::v0` (17),
  `reporting::v0` (97, incl. 2 new), `pre::v0` (36) green. Staged not
  committed.

**Problem.** PET report validation reconstructs an inline document's content ID
with `timestamp = None`. The original document may have `Some(timestamp)`, which
is part of its content ID. Neither the PET statement nor its inline evidence
currently preserves that timestamp, so otherwise valid reports for timestamped
inline documents fail ID reconstruction.

**Required fix.** Preserve the original document timestamp in the signed statement
or content-hash-validated inline evidence, carry it through report construction,
and pass it to the document-ID reconstruction helper. Do not confuse the document
timestamp with the responder's `signed_at`.

**Done when.** Both timestamped and untimestamped inline documents reconstruct
their original IDs; changing the timestamp cannot validate against the same ID.

**Code:** [PET report tag resolution](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/reporting/v0/registry/invalid_crypto/pet.rs),
[inline evidence validation](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/reporting/v0/registry/common.rs),
[PET statement](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/reporting/v0/types/pet.rs),
[inline evidence type](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/reporting/v0/types/envelope.rs).

### 9. Report authenticated malformed contribution/proof encodings

- [x] Fixed 2026-09-26. Both attributable-failure points now report a signed
  but undecodable response the same way they already reported a decodable-
  but-cryptographically-invalid one — a malicious node can no longer dodge
  reporting just by signing garbage bytes instead of a well-formed wrong
  proof. In `verify_check_response` (the live collector, `verification.rs`),
  step 4's decode-failure branch now builds the same
  `InvalidCryptoResponseObservation` the step-5 DLEQ-failure branch already
  built, and returns `PetCheckResponseVerification::InvalidProof` instead of
  `Rejected` — the caller in `initiator.rs` already handles `InvalidProof`
  generically (queue the report, never insert into `seen_node_ids`), so no
  change was needed there. In `verify_pet_admission` (the PRE-peer admission
  re-check), the decode step and the DLEQ-failure step both now go through a
  new shared helper, `queue_pet_admission_report` (bulletin `NodeInfo`
  lookup → build observation → `queue_report`), extracted so the two
  attributable-failure branches don't duplicate that lookup — the decode
  branch previously used a bare `.map_err(...)?` with no reporting at all.
  Kept the exclusions the finding calls out: a *signature* failure (step 3)
  is still never attributed to the claimed id, and nothing upstream of these
  two branches (missing local state, a wrong verification polynomial, a
  malformed *request*) is misclassified as bad responder output — those
  stay hard errors with no report. New tests:
  `malformed_response_is_reported_and_does_not_consume_the_slot` (pure
  `verify_check_response`, mirrors the existing #6 regression tests exactly
  — asserts `InvalidProof`, confirms the slot stays free, confirms the same
  node's later genuine response still gets accepted) and
  `verify_pet_admission_rejects_and_reports_a_malformed_attestation` (full
  async coordinator, confirms admission still rejects on a genuinely
  undecodable but validly-signed attestation now that the report-queueing
  call sits in that path). `cargo check`/clippy(`-D warnings`)/fmt clean
  both backends; `pet::v0` (19, incl. 2 new), `reporting::v0` (97),
  `pre::v0` (36) green on bls12-381; `pet::v0` (19) green on decaf377.
  Staged not committed.

**Problem.** The collector verifies the node signature, then silently rejects
malformed partial/challenge/proof bytes. PRE admission similarly exits on decoding
errors before reporting. A malicious node can avoid automatic accountability by
signing malformed bytes instead of a well-encoded but invalid proof. The registry
already treats signed malformed outputs as attributable failures.

**Required fix.** After authenticating the exact signed response and its context,
route output-decoding failures through the invalid-crypto reporting path as well.
Preserve the signed raw bytes as evidence. Do not report signature failures as
misconduct by the claimed participant, and do not classify malformed requests,
missing local state, or a wrong verification polynomial as bad responder output.

**Done when.** Signed malformed outputs queue a report in both collection and
admission paths, never count toward threshold, and never consume an acceptance
slot. Unsigned/forged responses are rejected without falsely accusing a node.
Reporting failure remains independent of rejection and PRE release.

**Code:** [PET verification](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/pet/v0/coordinator/verification.rs),
[PET report verification](/Users/jesse/Desktop/source/orbis-rs/bin/orbis-node/src/reporting/v0/registry/invalid_crypto/pet.rs).

### 10. Restore constant-time multiplication for secret tag randomness

- [x] Fixed 2026-09-26. Added `crypto::helpers::mul_point_secret` alongside
  the existing (now explicitly documented as variable-time,
  public-scalars-only) `mul_point` — bls12-381 routes it through the
  existing `bls12_381::ct::ct_mul_g1` (the same constant-time path
  `Pet::prove_tag_knowledge` and the per-share DLEQ proof already use for
  every other secret-scalar multiplication in this protocol); decaf377
  keeps the same plain operator, with the same documented, tracked gap
  `prove_tag_knowledge`'s decaf377 twin already carries (no constant-time
  path exists yet for that backend). `prepare_pet_tag`
  (`cli-tool/src/commands/crypto.rs`) now calls `mul_point_secret` for
  `r_tag*pet_pk` instead of `mul_point`. New test
  `mul_point_secret_matches_mul_point` (`crypto::helpers`) proves the
  constant-time path computes the exact same group element as the
  variable-time one for 20 random inputs, satisfying "Done when" directly
  — `ct_mul_g1_matches_naive_mul` already covers the same equivalence one
  layer down. Did not touch `generate_keypair`'s own BLS multiplication —
  out of scope per this item's own scope boundary. `cargo test` green for
  `crypto` (52 bls12-381, 46 decaf377) and `cli-tool` (21, both backends);
  clippy(`-D warnings`)/fmt clean both backends. Staged not committed.

**Problem.** The new BLS `helpers::mul_point` uses variable-time arkworks
multiplication. The refactored tag helper passes secret `r_tag` into it, replacing
a previously constant-time `r_tag * pet_pk` operation. A public base point does
not make the scalar public. Recovering this randomness would reveal
`F(owner) = T - r_tag * pet_pk`.

**Required fix.** Route the BLS helper through `ct_mul_g1` when used with secret
scalars, or expose an explicitly secret-safe helper and use it here. Document
the scalar's secrecy correctly.

**Scope boundary.** This restores the protection removed by this refactor. It
does not establish that all existing tag generation is constant-time:
`generate_keypair` has a separate preexisting BLS multiplication to review.
The currently inspected tag producer is a CLI/library stand-in for Bankd.

**Done when.** This tag-masking operation uses the constant-time path without
changing the resulting group element or wire format.

**Code:** [crypto helpers](/Users/jesse/Desktop/source/orbis-rs/crates/crypto/src/helpers.rs),
[tag preparation](/Users/jesse/Desktop/source/orbis-rs/bin/cli-tool/src/commands/crypto.rs).

### 11. Reject an identity PET checking key when preparing a tag

- [x] Fixed 2026-09-26. `prepare_pet_tag` now rejects an identity `pet_pk`
  immediately after decoding it, via the existing, already-tested
  `Dkg::public_key_is_identity` trait method (implemented for both
  backends — `*public_key == G1Affine::identity()` for bls12-381,
  `*public_key == Element::default()` for decaf377 — already used
  elsewhere to reject an identity DKG public key). Reused this rather than
  writing a new ad hoc identity check in cli-tool, since it's
  backend-generic and already proven correct; canonical decoding and
  subgroup validation are untouched (`G1Affine::from_bytes` still does
  both, unchanged). New tests
  `prepare_pet_tag_rejects_an_identity_checking_key` (identity `pet_pk` →
  `Err`) and `prepare_pet_tag_accepts_a_genuine_checking_key` (a real,
  independently generated key still produces a tag — proves the rejection
  above isn't vacuous), both green on bls12-381 and decaf377. `cargo
  test`/clippy(`-D warnings`)/fmt clean both backends. Staged not
  committed.

**Problem.** Canonical point decoding allows the identity point. The old
staging-tag path rejected it; the refactored helper no longer does. With an
identity checking key, `r_tag * pet_pk = identity`, so tag creation succeeds with
`T = F(owner)` and the owner fingerprint is publicly exposed.

**Required fix.** Explicitly reject an identity checking key before producing a
tag. Preserve canonical decoding and prime-order group/subgroup validation.

**Done when.** An identity checking key returns an error rather than a tag;
valid independently generated checking keys retain the normal behavior.

**Scope boundary.** This is an input-validation regression in the CLI/tag helper,
not a demonstrated attack against a valid DKG-generated checking key.

**Code:** [tag preparation](/Users/jesse/Desktop/source/orbis-rs/bin/cli-tool/src/commands/crypto.rs).

## Handoff rules

- Name the checklist IDs a change addresses. Do not mark an unrelated finding
  fixed merely because it touches the same file or uses the same proof.
- Preserve rejection on all invalid-input/proof paths. Reporting must remain a
  separate best-effort side effect, never a substitute for verification.
- Record the reviewed revision and evidence when changing a status. A successful
  happy path alone does not establish that the corresponding attack is blocked.
- The user requested no test runs during these reviews. The completion conditions
  above describe required behavior, not authorization to run tests or benchmarks.
- This document is a fix backlog, not authorization to implement all items at once.
