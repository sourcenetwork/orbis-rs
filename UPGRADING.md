# Protocol Version Upgrades

This guide explains how Orbis protocol version upgrades work and gives operators a step-by-step playbook for upgrading a live ring from one protocol version to the next.

## Browser CORS migration

`orbis-node` no longer enables cross-origin browser gRPC-Web access by default.
When upgrading a node used by a browser frontend, add one
`--cors-allow-origin <ORIGIN>` argument for every trusted frontend origin. To
preserve the previous fully permissive behavior, add `--cors-permissive`
explicitly. These settings are local to each node, are not persisted, and must
be supplied on every launch. Native gRPC clients require no changes.

## How It Works

Every ring on-chain carries an `UpgradeInfo` field with three values:

| Field | Description |
|-------|-------------|
| `current_version` | The protocol version currently in effect |
| `next_version` | The version that will become effective at `activation_time` |
| `activation_time` | Unix timestamp (seconds) when `next_version` takes effect |

On every request, both nodes and CLI tools resolve the **effective version**:

```text
effective_version = next_version  if current_time >= activation_time
                  = current_version  otherwise
```

When `effective_version` references a protocol version not installed in the binary, the request is refused with a clear error. This means:

- **Before `activation_time`**: requests use `current_version`. Old and new node binaries both serve the ring normally.
- **After `activation_time`**: requests use `next_version`. Nodes running old binaries (that don't support the new version) refuse all requests for the ring. Nodes running new binaries accept them.

The on-chain scheduling constraint enforces that `activation_time` is at least **600 seconds in the future** from the chain's block time at submission. This gives operators a guaranteed window to roll out new binaries before the flip.

## Prerequisites

Before scheduling an upgrade on-chain:

1. **All nodes** in the ring's committee must already be running a binary that supports the new protocol version. Verify with `cli-tool info`.
2. The ring must be **finalized** — `ring_pk` must be non-empty (DKG must have completed).
3. The operator must hold **ACP write access** to the ring.

## Upgrade Playbook (v0 → v1)

The same steps apply to any vN → vN+1 transition.

### Step 1 — Confirm the current state

```bash
# Check current ring state and its certified sequence
vera-admin --vera-config vera.json ring <RING_ID>

# Check what protocol versions each node supports
cli-tool info --endpoint http://<NODE>:50051
```

All nodes should show `supported_protocol_versions: [0]` before the upgrade.

### Step 2 — Roll out new node binaries

Deploy the new `orbis-node` binary to every node in the ring's committee. The new binary serves **both v0 and v1 gRPC routes simultaneously**, so in-flight v0 requests are not disrupted during the rollout.

Restart each node with the new binary. There is no required ordering.

### Step 3 — Verify all nodes report the new version

* This is not mandatory, the activation time should handle this but this is a really good nice to have if you can 
```bash
for NODE in <node1> <node2> <node3>; do
  echo "=== $NODE ==="
  cli-tool info --endpoint http://$NODE:50051
done
```

Every node must show `supported_protocol_versions: [0, 1]` before proceeding. If any node still shows only `[0]`, do not schedule the upgrade yet.

### Step 4 — Schedule the upgrade on-chain

Set activation at least 600 s (10 min) in the future; 900 s (15 min) is a safe
margin. Write an SDK `RingCommand` update with the ring's current certified
sequence, then prepare and submit it with `vera-admin` (see
[`bin/cli-tool/README.md`](bin/cli-tool/README.md) for the worker and
delegation setup):

```json
{"Update":{"ring_id":"<RING_ID>","expected_sequence":<SEQUENCE>,
  "update":{"ScheduleUpgrade":{"version":1,"activates_at":<UNIX_TS>}}}}
```

```bash
vera-admin --vera-config vera.json --directory operator --password-file password \
  prepare-ring upgrade.json --token-file ring-token
vera-admin --vera-config vera.json --directory operator --password-file password submit
```

Vera rejects the request if `activates_at` is less than 600 seconds after the
block time.

### Step 5 — Monitor the pending upgrade

```bash
vera-admin --vera-config vera.json ring <RING_ID>
```

The certified ring record shows the scheduled version and activation time.

### Step 6 — Wait for activation

```bash
sleep $(( <UNIX_TS> - $(date +%s) + 5 ))
```

After the activation time passes, every request to this ring resolves `effective_version = 1`.

### Step 7 — Confirm the flip

```bash
vera-admin --vera-config vera.json ring <RING_ID>
```

The effective version is now 1. Any client still running a v0-only binary will receive:

```
Ring <RING_ID> requires protocol version 1, but installed versions are [0]
```

Update all clients to a binary that includes v1 in `supported_protocol_versions`.

### Step 8 — (Optional) Decommission v0 routes

Once all clients are updated, you may redeploy nodes with `SUPPORTED_PROTOCOL_VERSIONS = [1]` only. Lingering v0 clients will then receive a clear unsupported-version error rather than silently failing.

## Rolling Back a Scheduled Upgrade

You can cancel a pending upgrade at any time **before** its activation time by
submitting the same kind of update with `"update":"CancelUpgrade"`. The effective
version then remains the current version. After activation the scheduled version
is already effective and cannot be cancelled.

## Operators Serving Multiple Rings

Protocol versions are scheduled **per ring**, by whoever holds ACP write access to
that ring — not bulletin-wide. This keeps upgrade timing under the control of the
ring (and its policy) rather than the bulletin owner, but it has a consequence for
node operators:

> A node that belongs to more than one ring may be required to run a single binary
> that serves **several protocol versions at once**, because each of its rings can
> schedule upgrades independently and on unrelated timelines.

Concretely:

- During any ring's upgrade window the node must serve both that ring's
  `current_version` and its `next_version`.
- Two rings that have flipped to different versions require the node to keep
  serving **both** for as long as it stays in both rings.
- A ring that jumps across a version gap (e.g. v1 → v4) may require a **per-ring**
  local-storage migration for that ring's keys — there is no automatic
  multi-version migration pipeline.

The node surfaces this in its logs on the PSS scheduler tick (throttled, and only
re-logged when the set of `(ring, version)` pairs changes):

- **INFO** — "This node is a member of multiple rings…" once the node is a current
  member of two or more rings, even while they still share one version.
- **WARN** — "…multiple rings whose protocol versions differ…" once the effective
  or pending versions across those rings are no longer identical, with a per-ring
  `ring=vN(pending vM)` breakdown.

If you operate a node in multiple rings, keep its binary at a version that covers
the union of every version its rings use or have scheduled, and treat the WARN
line as a prompt to check whether a local-storage migration is needed before a
ring's `activation_time`.

## Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| Refused `ScheduleUpgrade` receipt | Lead time is less than 600 s | Use `activates_at >= block_time + 600` (15 min recommended) |
| `Ring X requires protocol version 1, but installed versions are [0]` | CLI binary does not support v1 | Upgrade the CLI binary |
| `protocol version for ring X is not installed: effective_version=1 installed_versions=[0] ... route_version=0` | Node binary does not support v1 | Upgrade the node binary before `activation_time` |
