# Bulletin crate

A small async abstraction over typed Orbis bulletin objects: **read** rings by authoritative id, and **post** fresh ring finalizations, node info, encrypted document handles, and key-derivation records.

The default backend is Vera `x/orbis`; an in-memory **dummy** implementation ships for tests and local development.

## Native service client

The `native` feature exposes `native::NativeVeraClient` for signed
node registration/controller commands, fresh-ring creation, confirmation and
cancellation, and certified reads. Open it with an independently provisioned
deployment root and consensus key, a worker journal
directory, and the existing encrypted Orbis `RedbStorage`. The node signing key
must already exist. Worker keys use separate encrypted entries.

Call `prepare_node_registration` or `prepare_node_command` to persist a command,
`submit_pending` to send its exact bytes, then `confirm_pending` to verify execution. A missing
receipt or transport error leaves the command pending. On restart, use
`pending_id` and confirm or resubmit before preparing another command. Inspect the
receipt's success: rejected commands consume the worker sequence but leave the
node's command sequence unchanged. Controller commands use the next sequence
returned by `read` and an explicit expiry.

`read_node_info` produces the payload used by peer routing after verifying the
record against the configured consensus key and caller's minimum revision.
Callers remain responsible for their freshness requirement.

`prepare_ring_command` uses an actor's delegation to the client's `worker_did`.
`prepare_ring_participant_request` signs fresh-DKG confirmation or cancellation
with the node identity. Ring operations share the same durable pending slot and
receipt recovery. `read_ring_info` and `ring_finalization_status` adapt certified
state to existing Orbis DKG types. Cancelled/conflicting records map to not-found
for the DKG protocol; `read_ring` exposes the terminal record for inspection.

`prepare_ring_reshare` and `prepare_ring_report` persist aggregate authorizations
from the existing threshold signers. The report path uses shared canonical IDs,
snapshot hashes and bounded large-request delivery.

`prepare_document` and `prepare_key_derivation` use an actor's
`orbis:object:store` delegation to the worker. `read_object` verifies a document
or derivation at a minimum revision and returns the payload used by the existing
PRE/signing protocols. IDs preserve the current Rust consumer encoding, including
canonical ciphertext/proof fields and optional document tier/timestamp. Admission
registers the metadata; the threshold protocols must still validate encryption
proofs and the requesting actor's ACP permission before use.

`NativeBulletin::connect` implements the `Bulletin` trait over this client. Supply
an independent reader endpoint, a maximum evidence age and a request deadline.
Connection verifies the configured deployment root. Reads verify fresh,
monotonic revisions without waiting for the writer mutex. Writes recover the
existing journaled submission before allocating another sequence; errors or
cancellation retain unresolved bytes. Node registrations, confirmations,
cancellations and object posts recognize already-applied state. Node metadata
changes still require explicit controller commands. Object posts delegate from
the configured node identity to its worker.

Report and reshare calls keep their completed signed request in the journal until
the next distinct write. An exact retry reads its certified receipt, including
after restart, without advancing the worker sequence again. Reshare retries match
the originally signed ring sequence. A different write acknowledges the retained
request before preparing its own. This is a single retained completion, not an
unbounded history of previous calls. Use `NativeVeraClient`'s explicit
prepare/submit/confirm interface to retain receipt IDs when older outcomes must
remain addressable across subsequent writes.

The focused service fixture covers a failed submission followed by journal
recovery, controller allow-list enforcement, fresh-ring confirmation, document
and derivation posts, cancellation, duplicate calls and restart:

```bash
HUBD_BINARY=/path/to/hubd cargo test -p bulletin --features native --test native_service -- --ignored
```

Node startup can select this backend with `--vera-config`; see the node README.
The report/reshare recovery fixture uses supplied aggregate signatures and checks
lost-reply recovery, service restart and exact retries against certified state.
Distributed resharing, report co-signing, fault qualification and historical
authorization availability remain required before deployment.

## `Bulletin` trait

Defined in [`src/trait.rs`](src/trait.rs):

| Method | Role |
|--------|------|
| `post(kind, payload)` | Store a typed write object and return its authoritative id. Write kinds are `Finalize`, `Document`, `KeyDerivation`, and `NodeInfo`. |
| `read(id, kind)` | Load a `BulletinPost` (`id`, `payload`). |

Shared **value types** (JSON serde):

- **`BulletinPost`** — `id`, raw **`payload`** bytes.
- **`DocumentPayload`** — Encrypted document + encryption‑proof fields (Schnorr PoK of the encryption randomness) + policy binding (`ring_id`, `policy_id`, `resource`, `permission`, optional tier/timestamp).
- **`RingPayload`** — Ring metadata: `ring_pk`, `peer_node_keys`, `threshold`, optional `pss_interval`, optional **`new_peer_node_keys`** / **`new_threshold`** for reshare coordination, and **`block_number_nonce`** used as anti-replay input to the reshare finalization sign doc.
- **`RingFinalizationPayload`** — Fresh DKG finalization confirmation: `ring_id` and aggregate `ring_pk`.
- **`KeyDerivation`** — Bulletin entry for signing/PRE derivation: `ring_id`, `derivation`, policy fields.
- **`NodeInfo`** — Node registration: `peer_id`, `controller_key`, `whitelisted_policy_ids`, and `whitelisted_ring_ids`.

`TryFrom` helpers convert between posts and these structs (JSON in `payload`).

## Feature flags

| Feature | Default | `BulletinImpl` |
|---------|---------|----------------|
| `vera` | **yes** | [`VeraBulletin`](src/vera/mod.rs) |
| `dummy` | no | [`DummyBulletin`](src/dummy/mod.rs) |

**`vera` and `dummy` are mutually exclusive** (only one can be enabled). Default builds use Vera.

The **`dummy`** module is **always compiled** (in-memory store, useful in unit tests). The **`dummy`** *feature* only switches **`BulletinImpl`** to `DummyBulletin` and must not be combined with `vera`:

```bash
cargo build -p bulletin --no-default-features --features dummy
```

## Vera implementation

**`VeraBulletin`** wraps [`VeraClient`](../common) from the workspace `common` crate.

- **`post`** — routes to fresh `FinalizeRing`, `StoreDocument`, `StoreKeyDerivation`, or `CreateNodeInfo`, returning the chain id for the written object.
- **`read`** — routes to typed `x/orbis` queries by object id.
- Ring creation is intentionally outside this abstraction; callers receive a `ring_id` from Vera `CreateRing` and pass that id through DKG.

Construction:

- **`VeraBulletin::new(ChainConfigBuilder)`** — Read-focused client.
- **`VeraBulletin::with_signer(..., balance_check_amount)`** — Client with **`TxSigner`**; optionally waits (exponential backoff) until the account balance ≥ threshold, then performs a minimal **self-transfer** to register the account on-chain.

Diagnostics name: **`"bulletin/vera"`**.

Integration tests in [`src/vera/tests.rs`](src/vera/tests.rs) may require **Docker** (Vera stack), similar to other `common`-based tests.

## Dummy implementation

**`DummyBulletin`** keeps typed objects in a process-local **`HashMap`**, keyed by object id. Document and key-derivation writes return the same typed ids as Vera.

Extras for tests: **`set_post`**, **`set_ring`**, **`set_node_info`**, **`get_posts`**, and **`finalization_count`**. `DummyBulletin::post` rejects `NodeInfo` because the dummy backend has no signer to derive the node key.

Diagnostics name: **`"bulletin/dummy"`**.

## Errors

[`BulletinError`](src/error.rs): **`ChainError`**, **`ParseError`**, **`NotFound { id }`**.

## Dependencies (high level)

- **`async-trait`**, **`serde`** / **`serde_json`**
- **`sha2`**, **`hex`** — canonical ring hash helpers
- **`backoff`** — balance retries in `with_signer`
- **`common`** — Vera chain client

## Spec notes

The repo includes a short intent doc [`bulletin_spec.md`](bulletin_spec.md): first implementation is Vera; other bulletin backends can be added if they honor the same typed-object contract expectations and deterministic ids where applicable. Filling out the spec is a TODO.

## Tests

```bash
cargo test -p bulletin
```
