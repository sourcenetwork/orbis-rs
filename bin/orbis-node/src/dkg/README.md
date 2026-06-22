# DKG Developer Guide

This guide is the source of truth for the behavior implemented by the current
Rust node. [`new_dkg_flow.md`](new_dkg_flow.md) is a non-authoritative design
draft; do not treat draft behavior as implemented unless it is also described
here and covered by code/tests. The former `PROTOCOL_FLOW.md` was removed
because it duplicated this guide.

This module implements the node-local side of the DKG protocol. There is no
central coordinator in the protocol. Each node has a `DkgCoordinator` that
receives messages, validates them, records local facts, and advances its own
session state when the state machine says the protocol is ready.

The important split is:

```text
protocol_handler/service/scheduler
    -> DkgCoordinator::handle_message or local phase starter
    -> message_handlers/* record validated facts
    -> phases::drive_event(...)
    -> state_machine::transition(...)
    -> phases executes selected commands
```

## Directory Map

```text
dkg/
  service.rs                         fresh DKG gRPC entrypoint
  protocol_handler.rs                network protocol adapter
  messages.rs                        wire messages and SessionKind
  session_state.rs                   per-session mutable state and cleanup
  helpers.rs                         validation, session IDs, persistence helpers
  coordinator/
    mod.rs                           public coordinator API and inbound dispatch
    network.rs                       send path, stream caching, per-peer locks
    state_machine.rs                 pure transition function
    phases/
      mod.rs                         state-machine driver and command executor
      phase1.rs                      commitment generation/broadcast
      phase2.rs                      share generation/send
      phase4.rs                      durable completion/persistence/bulletin work
    message_handlers/
      session_init.rs                SessionInit validation and session creation
      commitment.rs                  commitment validation/storage
      share.rs                       share validation/storage
    reshare/
      selection.rs                   reshare ACKs and participant-set selection
      bulletin_update.rs             signed RingPayload update
      cleanup.rs                     reshare cleanup after bulletin finalization
```

## Entry Points

There are three ways a DKG session gets moving.

### Fresh DKG from gRPC

`service.rs::start_dkg` handles a user request:

1. Validate the JWT and requested peer set.
2. Allocate a random `session_id`.
3. Create a local session if this node is a participant.
4. Send `DkgMessage::SessionInit` to peers.
5. If this node participates, call `initiate_phase1_commitments`.

Remote participants receive that `SessionInit` through the network path below.

### Refresh/Reshare from PSS scheduler

`pss/mod.rs` periodically scans known rings.

For refresh, it derives a deterministic session ID from the current ring state,
claims the ring's active PSS slot, creates a session, sends `SessionInit`, and
starts Phase 1.

For reshare, it reads the bulletin's requested next committee/threshold, derives
a deterministic session ID, creates a role-specific session, sends `SessionInit`
to the old/new committee union, and old dealers begin distributing reshare
material.

### Inbound Network Messages

`protocol_handler.rs` plugs `DkgCoordinator` into the generic protocol loop.
Every decoded `DkgMessage` goes to `DkgCoordinator::handle_message`.

`handle_message` is the edge of the trust boundary:

1. Classify the message for metrics and dedup.
2. Handle `SessionInit` first, because it can create the session.
3. For other messages, wait for a bounded grace period for the session to appear.
4. Validate the authenticated peer against the claimed node ID.
5. Atomically claim the message as in-flight to suppress concurrent duplicates.
6. Dispatch to the per-message handler.
7. Mark the message processed only if the handler succeeds.

## State Machine Model

The state machine lives in `coordinator/state_machine.rs`. It is intentionally
pure: it does not hold locks, mutate state, send network messages, or touch
storage. It receives a `SessionSnapshot` plus a `DkgEvent`, and returns a
`Transition`.

```text
SessionSnapshot + DkgEvent -> Transition

Transition:
  next_phase: Option<DkgPhase>
  commands: Vec<DkgCommand>
```

The state-machine driver is `phases::drive_event`.

```text
drive_event
  1. lock session state
  2. build SessionSnapshot
  3. call state_machine::transition
  4. atomically claim transition.next_phase, if any
  5. release session state lock
  6. execute transition.commands outside the lock
```

The lock boundary matters. Decisions are claimed while holding the session-state
write lock, but slow work happens after the lock is released. Do not add network
sends, storage writes, bulletin calls, or signing calls inside the snapshot or
transition path.

## Events And Commands

Events describe facts that just became true locally.

| Event | Emitted When |
| --- | --- |
| `CommitmentRecorded` | A valid commitment was stored. |
| `ShareRecorded { from_node_id }` | A valid private share was stored. |
| `ReshareParticipantSetAccepted` | The selected old-dealer subset was frozen or accepted. |
| `Phase2SharesDistributed { local_node_id }` | This node finished sending Phase 2 shares. |
| `ReadinessChanged` | Something may have unblocked Phase 4, usually a late commitment. |

Commands describe side effects selected by the state machine.

| Command | Executed By |
| --- | --- |
| `InitiatePhase2Shares` | `phases::initiate_phase2_shares` |
| `AckValidReshareShare { dealer_id }` | `reshare::selection::record_and_ack_valid_reshare_share` |
| `CompletePhase4` | `phases::initiate_phase4_completion` |

The state machine should only decide that a command is needed. The command
runner owns how that command is performed.

## Phase Flow

### SessionInit

`message_handlers/session_init.rs` validates the session kind before creating
state.

Fresh DKG validates the JWT claims against threshold, peers, and PSS interval.
Refresh and reshare validate against the existing ring state and bulletin.

Node IDs are not trusted blindly from the wire. The handler recomputes the
canonical sorted peer mapping locally and rejects non-canonical assignments.

For reshare, roles are derived from committee membership:

| Role | Meaning |
| --- | --- |
| `Dealer` | Old committee only. Sends reshare shares, then leaves. |
| `Receiver` | New committee only. Receives old dealers' shares. |
| `DealerReceiver` | In both committees. Sends and receives. |

### Phase 1: Commitments

`phases/phase1.rs::initiate_phase1_commitments` generates the local polynomial
when needed and broadcasts the local commitment.

Incoming commitments are handled by `message_handlers/commitment.rs`:

1. Validate commitment length and coefficient count.
2. Deserialize commitment coefficients.
3. Store the commitment in the crypto node.
4. Increment commitment counters.
5. Emit `CommitmentRecorded`.
6. For reshare, also emit Phase 4 readiness when a late selected commitment may
   unblock completion.

For fresh/refresh sessions, enough commitments can cause:

```text
CommitmentRecorded -> InitiatePhase2Shares
```

Reshare dealers do not wait for every old dealer commitment before sending
shares to the new committee. They start sending after their own commitment path
is ready.

### Phase 2: Shares

`phases/phase2.rs::initiate_phase2_shares` generates private shares and sends
each one only to its intended recipient. For reshare, shares are routed by the
new committee ordering stored in `reshare_params`.

After sending shares, Phase 2 emits:

```text
Phase2SharesDistributed { local_node_id }
```

That lets the state machine handle special reshare roles:

| Role | After Phase 2 Distribution |
| --- | --- |
| `DealerReceiver` | ACK its own valid dealer share to the selector. |
| `Dealer` | Run Phase 4 cleanup; it does not receive shares. |

Incoming shares are handled by `message_handlers/share.rs`:

1. Validate the share is addressed to this node.
2. Deserialize the share value.
3. Call `receive_share`, which verifies against the sender commitment.
4. Increment share counters.
5. Emit `ShareRecorded { from_node_id }`.

For fresh/refresh, enough verified shares plus an aggregate public key can cause
Phase 4 completion. For reshare receivers, a valid share also triggers an
idempotent ACK to the selector.

### Reshare Selection

Reshare has an extra readiness step. A new-committee receiver ACKs each old
dealer whose share it verified. The selected node-1 receiver acts as selector.

The ACK path is intentionally retryable:

```text
ShareRecorded
  -> AckValidReshareShare { dealer_id }
  -> record dealer as locally valid
  -> deliver ReshareShareAck to selector until delivered or selection is done
```

The selector records ACKs by `(dealer_id, receiver_node_id)`. When all new
receivers have ACKed enough old dealers to meet the old threshold, the selector:

1. Freezes the first threshold-complete dealer set.
2. Stores that set in the crypto node.
3. Broadcasts `ReshareParticipantSet`.
4. Emits `ReshareParticipantSetAccepted`.

All new-committee receivers use the same selected old-dealer set for weighted
reshare aggregation.

### Phase 4: Durable Completion

The state machine never jumps directly to `Phase4Complete`. It first claims:

```text
Phase4Completing
```

This is the single-flight state for durable completion. It prevents concurrent
handlers from starting Phase 4 twice, but it is still eligible for timeout
cleanup if the completion task gets stuck.

Only after `initiate_phase4_completion` succeeds does the code mark:

```text
Phase4Complete
```

Phase 4 performs the durable work:

1. Compute final secret share.
2. Compute aggregate public key and public polynomial.
3. Persist the local ring bundle.
4. Update local ring index when needed.
5. For fresh DKG, post the initial `RingPayload`.
6. For reshare selector, collect a threshold signature and update the bulletin.
7. Remove the session, or for reshare wait until the bulletin update is visible
   before releasing the PSS claim.

Pure reshare dealers skip secret-share computation. Their Phase 4 command
deletes old local share material, removes the ring index entry, clears the PSS
claim, and removes the session.

## Network And Ordering

Outgoing session messages use `coordinator/network.rs`.

For `session_id = Some(_)`, each peer gets a cached QUIC stream plus a per-peer
send lock. This preserves local send order for that peer where possible, such as:

```text
SessionInit -> Commitment -> Share
```

If a cached stream fails, the send path evicts it and retries once with a fresh
stream while holding the same per-peer lock. Session-generation checks prevent a
stale sender from delivering messages into a newly recreated session with the
same external `session_id`.

Do not rely on this as a global delivery guarantee. Stream replacement,
cross-peer delivery, and locally staged state can still make valid inbound
messages arrive before their dependent local state is visible. Handlers should
queue and replay early-but-valid messages instead of sleeping inside the handler
until a timeout.

## Concurrency Rules

When changing this code, keep these invariants intact:

1. `state_machine::transition` must stay pure and deterministic.
2. Build snapshots and claim phase transitions under the session-state lock.
3. Execute network, storage, bulletin, and signing side effects after releasing
   the session-state lock.
4. Use `Phase4Completing` to claim durable completion, and mark
   `Phase4Complete` only after durable completion succeeds.
5. Do not trust wire-provided node assignments without canonical validation.
6. Let `handle_message` own inbound sender validation and message dedup claims.
7. If a command sends an important protocol message, make it idempotent or
   retryable.
8. If an inbound message is authenticated and well-formed but depends on local
   state that may arrive later, queue it and replay when that state is published.

## Adding A New Transition

When adding protocol behavior:

1. Add a `DkgEvent` for the local fact that changed.
2. Add a `DkgCommand` only if a side effect is needed.
3. Extend `SessionSnapshot` with the minimum state needed to decide.
4. Update `state_machine::transition`.
5. Execute the command from `phases/mod.rs`, outside the state lock.
6. Emit the event from the message handler or phase function that records the
   fact.
7. Add a unit test in `state_machine.rs` for the transition.
8. Add a coordinator/session test if the behavior depends on locking, retries,
   dedup, or cleanup.

## Useful Test Slices

```bash
cargo test -p orbis-node dkg::coordinator
cargo test -p orbis-node dkg::session_state
cargo test -p orbis-node dkg::tests
cargo test -p orbis-node dkg::tests::reshare
cargo test -p orbis-node pss::tests
```

Use the broader `dkg::tests` and `pss::tests` slices after touching reshare,
session cleanup, or Phase 4 completion. Those paths are where most state-machine
changes show up as real ceremony behavior.
