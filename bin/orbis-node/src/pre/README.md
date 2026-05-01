# PRE Developer Guide

This module implements node-local threshold proxy re-encryption (PRE). There is
no central coordinator in the protocol. Each node has a `PreCoordinator` that
can initiate a reencryption request, respond to requests from peers, and collect
enough verified shares to recover the reencrypted commitment.

The important mental model is:

```text
service.rs
    -> PreCoordinator::initiate_reencryption
    -> reencryption share round
    -> verify shares
    -> recover xnc_cmt

network message
    -> protocol_handler.rs
    -> PreCoordinator::handle_message
    -> responder handler
```

PRE is a bounded one-round request/response protocol. It should stay simpler
than DKG: split by responsibility, not by a long-lived state machine.

## Directory Map

```text
pre/
  service.rs                         gRPC StartPre entrypoint
  protocol_handler.rs                network protocol adapter
  messages.rs                        wire messages and PreRequestContext
  helpers.rs                         auth, bulletin, proof, serialization helpers
  response_state.rs                  response collection and expected-peer checks
  error.rs                           PreError
  coordinator/
    mod.rs                           PreCoordinator facade and PreResponse
    handlers.rs                      inbound ReencryptRequest handler
    network.rs                       per-peer send and same-stream response receive
    verification.rs                  peer response deserialization and proof verification
    initiator.rs                     request orchestration, collection, recovery
```

## Entry Points

### PRE From gRPC

`service.rs::start_pre` handles the public gRPC request:

1. Extract and validate the JWT.
2. Fetch document and ring payloads from the bulletin.
3. Check policy access through authz.
4. Validate JWT claims against reader key, object, namespace, derivation, and salt.
5. Verify the document encryption binding before any reencryption work.
6. Build `RingConfig` from the bulletin and local ring polynomial state.
7. Build `PreRequestContext`.
8. Call `PreCoordinator::initiate_reencryption`.

The service performs an auth and proof pass for the local caller. Peer nodes
still revalidate independently when they receive `ReencryptRequest`.

### Inbound Network Messages

`protocol_handler.rs` plugs PRE into the generic network handler.

`ReencryptResponse` messages are stored for the initiating coordinator in
`response_state.rs`. `ReencryptRequest` messages are routed to
`PreCoordinator::handle_message`.

Stored responses are allowlisted by authenticated network `PeerId`, not by the
claimed `from_node_id`.

## Initiator Flow

`coordinator/initiator.rs::initiate_reencryption` is the public initiator path.
It determines whether this node is in the ring, initializes response state, and
guarantees cleanup on both success and failure.

`initiate_reencryption_inner` owns the protocol body:

1. Load the public polynomial and optional local share from one
   `RingShareBundle` snapshot.
2. Check that enough possible participants exist for the threshold.
3. Deserialize the reader public key.
4. Deserialize the secret and encrypted commitment.
5. Locally reencrypt if this node is in the ring.
6. Send `ReencryptRequest` to peers and verify returned shares.
7. Drain any already stored responses and verify uncounted shares.
8. If threshold is not met during an active reshare, return
   `ReshareInProgress`; otherwise return `InsufficientShares`.
9. Recover `xnc_cmt`.
10. Return `PreResponse`, which contains recovered `xnc_cmt` plus the original
    secret payload for the reader.

Threshold collection is best-effort. The initiator can succeed without every
peer responding as long as enough verified shares are recovered.

## Responder Flow

Responder logic lives in `coordinator/handlers.rs`.

`handle_reencrypt_request` does the peer-side work:

1. Validate the JWT.
2. Validate JWT claims against the request context.
3. Fetch document and ring payloads from the bulletin.
4. Build policy metadata.
5. Check policy access through authz.
6. Deserialize the secret and reader public key.
7. Decode the ring public key and load the local `RingShareBundle`.
8. Deserialize the local private share.
9. Verify the encryption binding before reencryption.
10. Produce a reencryption reply and return `ReencryptResponse`.

The proof and policy checks must remain before reencryption. A responder should
not transform ciphertext material for an unauthorized or tampered request.

## Verification

`coordinator/verification.rs::verify_peer_response` is used by the initiator
for every peer response, both from live join tasks and from already stored
responses.

It:

1. Ignores non-response messages.
2. Deduplicates by claimed node ID after the authenticated peer check has
   already happened in response storage.
3. Deserializes share, challenge, and proof.
4. Reconstructs `ReencryptReply`.
5. Calls `dealer.verify`.
6. Returns only verified shares to the recovery path.

Never count a peer response toward threshold before this verifier accepts it.

## State And Trust Boundaries

`response_state.rs` tracks expected responders for each request. The generic
response manager stores at most one response per authenticated expected peer and
rejects unknown peers.

Keep these invariants intact:

| Invariant | Why It Matters |
| --- | --- |
| JWT claims and policy access are validated before reencryption. | Prevents unauthorized transforms. |
| Encryption binding/proof verification runs before reencryption. | Prevents tampered ciphertext metadata from being accepted. |
| Share and public polynomial come from one bundle snapshot. | Avoids PSS reshare races. |
| Responses are keyed by authenticated peer identity. | Prevents spoofing with `from_node_id`. |
| Peer responses are verified before threshold counting. | Prevents invalid shares from entering recovery. |
| Active reshare threshold failure returns `ReshareInProgress`. | Lets callers distinguish transient committee churn. |
| Response state is cleaned up on success and failure. | Prevents stale in-flight requests. |

## Common Places To Start

| Task | Start Here |
| --- | --- |
| Debug public PRE requests | `service.rs::start_pre` |
| Debug responder auth or proof failures | `coordinator/handlers.rs`, `helpers.rs` |
| Debug peer response collection | `coordinator/network.rs`, `protocol_handler.rs`, `response_state.rs` |
| Debug share verification | `coordinator/verification.rs` |
| Debug recovery or threshold behavior | `coordinator/initiator.rs` |
| Debug PSS/reshare races | the `RingShareBundle` load in `coordinator/initiator.rs` and `coordinator/handlers.rs` |

## Tests

Useful focused checks while changing this module:

```bash
cargo test -p orbis-node pre::
cargo test -p orbis-node dkg::coordinator
git diff --check
```

Run sign tests too if you change shared ring, bulletin, auth, or response-state
helpers that both protocols depend on.
