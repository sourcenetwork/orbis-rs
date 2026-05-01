# Sign Developer Guide

This module implements node-local threshold signing. There is no central
coordinator in the protocol. Each node has a `SignCoordinator` that can initiate
a signing request, respond to requests from peers, and collect enough verified
shares to recover one final signature.

The important mental model is:

```text
service.rs or internal caller
    -> SignCoordinator::initiate_signing
    -> optional FROST nonce round
    -> signing share round
    -> verify shares
    -> recover and verify final signature

network message
    -> protocol_handler.rs
    -> SignCoordinator::handle_message
    -> responder handler
```

Do not model this like DKG. DKG is a long-lived multi-phase ceremony with
durable session state. Sign is a bounded request/response protocol. For FROST it
has two rounds; for non-interactive signing it has one.

## Directory Map

```text
sign/
  service.rs                         gRPC StartSign entrypoint for policy signing
  protocol_handler.rs                network protocol adapter
  messages.rs                        wire messages and SignContext
  helpers.rs                         auth, bulletin, serialization, reshare validation helpers
  response_state.rs                  response collection plus FROST nonce state
  error.rs                           SignError
  coordinator/
    mod.rs                           SignCoordinator facade and SignResponse
    handlers.rs                      inbound NonceRequest and SignRequest handlers
    network.rs                       per-peer send and same-stream response receive
    verification.rs                  nonce response parsing and signature share verification
    rounds/
      nonce.rs                       FROST round 1 nonce collection
      signing.rs                     signing orchestration, recovery, final verification
```

## Entry Points

### Policy Signing From gRPC

`service.rs::start_sign` handles the public gRPC request:

1. Validate message size before crypto work.
2. Extract and validate the JWT.
3. Validate JWT claims against namespace, derivation ID, and message.
4. Fetch key derivation and ring payloads from the bulletin.
5. Check policy access through authz.
6. Build `RingConfig` from the bulletin and local ring polynomial state.
7. Call `SignCoordinator::initiate_signing` with `SignContext::Policy`.

The service does the first auth pass for the local caller. Peer nodes still
revalidate independently when they receive protocol messages.

### Internal Signing Callers

Other modules can call `SignCoordinator::initiate_signing` directly. Current
contexts are:

| Context | Meaning |
| --- | --- |
| `Bulletin` | Message is a serialized bulletin post. Authorization is bulletin existence. Signs with the root key. |
| `Policy` | JWT and policy-authorized derivation signing. Derivation and metadata come from bulletin data. |
| `RingReshareUpdate` | New committee signs a canonical ring bulletin update after reshare. |

### Inbound Network Messages

`protocol_handler.rs` plugs sign into the generic network handler.

Responses (`NonceResponse` and `SignResponse`) are stored for the initiator in
`response_state.rs`. Requests (`NonceRequest` and `SignRequest`) are routed to
`SignCoordinator::handle_message`.

The authenticated network `PeerId` is the trust anchor for stored responses. The
claimed `from_node_id` is still used by the cryptographic protocol, but it is
not trusted for response allowlisting.

## Initiator Flow

`coordinator/rounds/signing.rs::initiate_signing` is the public initiator path.
It determines whether this node is in the ring, initializes response state, and
guarantees cleanup on both success and failure.

`initiate_signing_inner` owns the protocol body:

1. Load the public polynomial and optional local share from one
   `RingShareBundle` snapshot.
2. Check that enough possible participants exist for the threshold.
3. Resolve derivation and metadata from the selected `SignContext`.
4. If the signer is interactive, call `collect_nonces`.
5. Select the exact FROST signing set and serialize those commitments.
6. Locally sign if this node is selected.
7. Send `SignRequest` to selected peers and verify returned shares.
8. Drain any already stored responses and verify uncounted shares.
9. If threshold is not met during an active reshare, return
   `ReshareInProgress`; otherwise return `InsufficientShares`.
10. Recover the signature.
11. Verify the recovered signature before returning it.

Final verification is part of the protocol contract. Do not remove it just
because individual shares were verified.

## FROST Nonce Round

`coordinator/rounds/nonce.rs::collect_nonces` runs only when
`S::INTERACTIVE` is true.

The initiator:

1. Generates a local nonce if this node is in the ring.
2. Initializes response state for `nonce-{request_id}`.
3. Sends `NonceRequest` to peers.
4. Parses deserializable nonce commitments and deduplicates by node ID.
5. Sorts commitments by participant ID for deterministic selection.

The signing round must use the exact selected commitment set. FROST signature
shares are bound to the participant list, so changing the set between request,
share verification, and recovery is a correctness bug.

## Responder Flow

Responder logic lives in `coordinator/handlers.rs`.

### NonceRequest

`handle_nonce_request` is FROST round 1:

1. Validate auth before generating a nonce.
2. Decode the ring public key and load the local distributed key share.
3. Generate nonce commitment and signing state.
4. Store signing state in `SignResponseManager`, bound to a context key.
5. Return `NonceResponse`.

The auth-before-nonce ordering matters. A malicious relayer should not be able
to make a node burn FROST nonces for unauthorized contexts.

### SignRequest

`handle_sign_request` is the signing share responder:

1. Reject oversized messages.
2. Resolve ring, derivation, and metadata from the context.
3. Load local share and public polynomial from one `RingShareBundle` snapshot.
4. Deserialize the commitment set.
5. For FROST, consume the stored nonce only if the context key matches.
6. Produce a signature share.
7. Return `SignResponse`.

FROST nonce state is consumed once. If there is no nonce state, or if the
context changed between round 1 and round 2, signing fails.

## State And Trust Boundaries

`response_state.rs` has two jobs:

1. Track expected responders and store responses by authenticated peer identity.
2. Hold FROST nonce signing state between round 1 and round 2.

Keep these invariants intact:

| Invariant | Why It Matters |
| --- | --- |
| Auth is checked before generating FROST nonces. | Prevents unauthorized nonce burn. |
| Nonce state is bound to the exact context and consumed once. | Prevents cross-context nonce reuse. |
| FROST commitment selection is fixed for the signing set. | Shares and recovery must agree on participants. |
| Responses are keyed by authenticated peer identity. | Prevents spoofing with `from_node_id`. |
| Share and public polynomial come from one bundle snapshot. | Avoids PSS reshare races. |
| Final recovered signature is verified. | Catches aggregation or derivation mistakes. |
| Response state is cleaned up on success and failure. | Prevents stale in-flight requests. |

## Common Places To Start

| Task | Start Here |
| --- | --- |
| Add or change a signing pathway | `messages.rs::SignContext`, then `coordinator/handlers.rs` and `rounds/signing.rs` |
| Debug peer response collection | `coordinator/network.rs`, `protocol_handler.rs`, `response_state.rs` |
| Debug FROST nonce issues | `rounds/nonce.rs`, `handle_nonce_request`, nonce methods in `response_state.rs` |
| Debug signature verification | `coordinator/verification.rs`, final verification in `rounds/signing.rs` |
| Debug policy auth | `service.rs`, `helpers.rs`, `handle_sign_request` |
| Debug reshare update signing | `helpers.rs` ring reshare validation and `SignContext::RingReshareUpdate` |

## Tests

Useful focused checks while changing this module:

```bash
cargo test -p orbis-node sign::
cargo test -p orbis-node dkg::coordinator
git diff --check
```

Run the DKG coordinator tests when touching reshare update signing because DKG
uses sign to finalize reshare bulletin updates.
