# PET Developer Guide

This module implements the node-local threshold ownership-tag (PET) check that
gates PRE release on a `requires_pet` ring. It has no public-facing service —
unlike PRE and Sign, there is no client-facing gRPC entrypoint here. The only
caller is PRE's own `start_pre` pipeline (`pre::v0::service::stages`), which
runs the check as one internal stage, immediately after ACP authorization and
before setting up the reencryption round, when the ring requires it.

The mental model is:

```text
pre::v0::service::stages (a new stage, gated on ring_payload.requires_pet)
    -> PetCoordinator::initiate_pet_check
    -> check_pet_permission: does the requester hold document.permission
       on the audit target? (ACP, additive — checked before anything below
       reveals whether the tag itself would have matched)
    -> this node's own independent tag-knowledge verification
    -> threshold check-share round (peer-to-peer, mirrors PRE's reencrypt round)
    -> combine shares -> pet_sk * R
    -> F(audit_target_object_id) — the plaintext owner identity itself,
       not resolved via ACP; see the invariant below
    -> verify T == F(target) + pet_sk*R
    -> Ok(signed attestations) or PetError, folded into PreError by `start_pre`

network message (PET's own check-share round)
    -> protocol_handler.rs
    -> PetCoordinator::handle_message
    -> handlers.rs: verify request, load local PET share, reply with a
       signed partial (PetShareAttestation)

pre::v0::coordinator::handlers::handle_reencrypt_request (every PRE peer,
gated on ring_payload.requires_pet, using the attestations forwarded in
PreRequestContext rather than re-running the threshold round above)
    -> PetCoordinator::verify_pet_admission
    -> same check_pet_permission gate, independently re-checked
    -> independently re-verifies the tag-knowledge proof
    -> verifies each attestation's signature, recombines, does its own
       final match against F(audit_target_object_id)
    -> only then releases its reencryption share
```

Like PRE, this is a bounded one-round request/response protocol — no
long-lived state machine, no leader election. Whichever node received the
external `StartPreRequest` drives the check directly against the whole ring
committee, exactly like PRE's own reencryption round.

## Directory Map

```text
pet/
  README.md
  v0/
    error.rs                PetError (no public service, so no GrpcServiceError —
                             surfaces via `From<PetError> for PreError`)
    messages.rs              wire messages and PetCheckContext
    protocol_handler.rs       network protocol adapter (MessageCoordinator impl)
    response_state.rs        response collection (thin wrapper over the shared
                             ResponseManager, mirrors PreResponseManager)
    coordinator/
      mod.rs                  PetCoordinator facade
      initiator.rs            fan-out, combine, final verify against the target
      network.rs               per-peer send and same-stream response receive
      handlers.rs             inbound CheckRequest handler (responder side)
      verification.rs        shared tag-knowledge-proof verification, reused
                              by both the initiator's own contribution and
                              every incoming request
```

## Threshold check, precisely

A PET tag is `(R = r_tag*G, T = F(owner_id) + r_tag*pet_pk)`, produced
off-chain by Bankd. The check recovers `r_tag*pet_pk` via a **threshold
decryption** shape (the same "apply my secret share to a public group
element" structure as `ThresholdDealer::reencrypt`, just against a single
point instead of a sum):

- Each committee member holds a Shamir share `pet_sk_i` of the ring's PET
  secret key (from its own fresh-DKG ceremony — see `docs/plans/pet-integration.md`'s
  "Checking-key lifecycle").
- Each contributes `pet_sk_i * R` (`Pet::partial_pet_check`).
- The initiator Lagrange-combines `threshold`-many contributions into
  `pet_sk * R = pet_sk*(r_tag*G) = r_tag*pet_pk` (`Pet::combine_pet_check_shares`).
- The check passes iff `T == F(target) + pet_sk*R` (`Pet::verify_pet_match`),
  where `target` is `audit_target_object_id` itself — the plaintext owner
  identity, recomputed locally, never taken from the wire (the request
  supplies the *identifier*, not a precomputed fingerprint).

## Key invariants

- **Every participant, including the initiator, independently verifies the
  tag-knowledge proof** (`verification.rs`) before touching its secret share
  with an untrusted `R` — an unverified ephemeral point could otherwise be
  used to probe the checking key. This mirrors PRE's own "every peer
  independently re-does `check_policy_access`" pattern.
- **Responders never resolve or need the audit target.** Computing
  `share_i * R` reveals nothing about which owner it will be checked
  against — only the initiator needs the target, for the one final
  comparison after combining. This is why `PetCheckContext` (the wire
  payload) carries the full `DocumentPayload` but not `audit_target_object_id`.
- **`audit_target_object_id` is the plaintext owner identity itself — there
  is deliberately no ACP identity-resolution step.** Earlier drafts of this
  feature resolved a `"creator"` relation via ACP to find "the real owner";
  that indirection was removed because it added no protection a caller
  can't already get around by naming any object it likes — nothing stops
  that, and it doesn't need to. What actually gates the check is the
  cryptographic match below (a wrong identity fails it outright — nobody
  can guess or forge a matching tag) and `check_pet_permission` (below).
  `audit_target_object_id` still names an ACP object *under the document's
  own resource type* (`document.resource` — not a separate resource; a
  document and its audit target sharing a resource type risks nothing in
  practice, since `object_id` is always a content hash and
  `audit_target_object_id` a chosen identifier).
- **A second, independent ACP gate: `check_pet_permission`.** Does the
  requesting actor hold `document.permission` (reused as-is — already bound
  into the tag digest via `ciphertext_context`, so no dedicated field exists
  for this) on `(document.resource, audit_target_object_id)`? This is
  additive to the cryptographic tag-match above, not a replacement — a
  genuinely matching tag still proves the tag is real; this proves the
  requester is allowed to invoke/learn that fact. Checked *first*, in both
  `initiate_pet_check` and `verify_pet_admission` — an unauthorized caller
  learns nothing about whether the tag would have matched. Reuses
  `PetError::Mismatch` on denial rather than a distinct variant, so "wrong
  tag" and "not authorized" stay indistinguishable to the caller. This is
  what lets the real owner delegate `reader` on the audit target to other
  actors, exactly like decrypting the document itself.
- **No refresh/reshare support yet.** The PET checking key's `RingShareBundle`
  is write-once (only fresh-DKG writes it via `save_by_ring_key`, keyed by
  `ring_id` rather than by public key) — the PSS-generation TOCTOU handling
  PRE's own initiator has isn't needed here yet, since there is no PET-key
  refresh ceremony to race against. Revisit this once that lands.
- **Relay attribution, not PET-specific evidence.** A relayed request whose
  PET admission fails is reported exactly like one that fails ACP: PRE's
  `handle_reencrypt_request` shares one `RelayRequestBinding` between both
  checks and calls the same `report_relay_if_bound` helper from whichever
  branch rejects with `PreError::Unauthorized`, provided the relayer signed
  a `relay_statement` for this exact request. It still resolves to the
  same generic `unauthorized_request` on-chain report type as an ACP
  failure — there is no PET-specific report kind or evidence payload, and
  nothing distinguishes "PET failed" from "ACP failed" in the resulting
  report. A JWT-validation failure (`resolve_jwt_did`) still isn't reported
  at all — that gap predates PET, applies identically to Sign, and is a
  known, deliberately deferred issue, not something this covers.
