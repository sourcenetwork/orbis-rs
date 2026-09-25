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
    -> this node's own independent tag-knowledge verification
    -> threshold check-share round (peer-to-peer, mirrors PRE's reencrypt round)
    -> combine shares -> pet_sk * R
    -> resolve the audit target's real owner via ACP
    -> verify T == F(target) + pet_sk*R
    -> Ok(()) or PetError::Mismatch, folded into PreError by `start_pre`

network message
    -> protocol_handler.rs
    -> PetCoordinator::handle_message
    -> handlers.rs: verify request, load local PET share, reply with partial
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
      initiator.rs            fan-out, combine, resolve target, final verify
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
  where `F(target)` is recomputed locally from the ACP-resolved audit target
  — never taken from the wire.

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
- **The audit target is always resolved via ACP, never trusted from the
  caller.** `audit_target_object_id` names an ACP object; `Authz::resolve_relation_subject`
  reads who actually holds the `"owner"` relation on it. See
  `coordinator::verification::PET_OWNER_RESOURCE`/`PET_OWNER_RELATION` for the
  exact contract external callers (Bankd) must follow when registering that
  relationship.
- **No refresh/reshare support yet.** The PET checking key's `RingShareBundle`
  is write-once (only fresh-DKG writes it via `save_by_ring_key`, keyed by
  `ring_id` rather than by public key) — the PSS-generation TOCTOU handling
  PRE's own initiator has isn't needed here yet, since there is no PET-key
  refresh ceremony to race against. Revisit this once that lands.
- **No reporting/evidence integration yet.** A PET-check failure surfaces as
  a clean `PreError::Unauthorized` rejection — no on-chain report, no
  evidence capture. Deferred to Task 7 in the PET feature's task breakdown.
