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

1. **All nodes** in the ring's committee must already be running a binary that supports the new protocol version. Verify with `orbis-cli info`.
2. The ring must be **finalized** — `ring_pk` must be non-empty (DKG must have completed).
3. The operator must hold **ACP write access** to the ring.

## Upgrade Playbook (v0 → v1)

The same steps apply to any vN → vN+1 transition.

### Step 1 — Confirm the current state

```bash
# Check current ring state
orbis-cli get-latest-ring --ring-id <RING_ID>

# Check what protocol versions each node supports
orbis-cli info --endpoint http://<NODE>:50051
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
  orbis-cli info --endpoint http://$NODE:50051
done
```

Every node must show `supported_protocol_versions: [0, 1]` before proceeding. If any node still shows only `[0]`, do not schedule the upgrade yet.

### Step 4 — Schedule the upgrade on-chain

```bash
# Set activation at least 600 s (10 min) in the future; 900 s (15 min) is a safe margin
ACTIVATION=$(( $(date +%s) + 900 ))

orbis-cli update-ring-post-by-acp \
  --id <RING_ID> \
  --next-version 1 \
  --activation-time $ACTIVATION
```

The chain will reject the transaction if `activation_time < block_time + 600`.

Both `--next-version` and `--activation-time` must be supplied together.

### Step 5 — Monitor the pending upgrade

```bash
orbis-cli read-bulletin-post --id <RING_ID>
```

The response will show:

```json
"upgrade_info": {
  "current_version": 0,
  "next_version": 1,
  "activation_time": <UNIX_TS>
}
```

### Step 6 — Wait for activation

```bash
sleep $(( ACTIVATION - $(date +%s) + 5 ))
```

After `activation_time` passes, every request to this ring resolves `effective_version = 1`.

### Step 7 — Confirm the flip

```bash
orbis-cli read-bulletin-post --id <RING_ID>
```

The `effective_version` is now 1. Any client still running a v0-only binary will receive:

```
Ring <RING_ID> requires protocol version 1, but installed versions are [0]
```

Update all clients to a binary that includes v1 in `supported_protocol_versions`.

### Step 8 — (Optional) Decommission v0 routes

Once all clients are updated, you may redeploy nodes with `SUPPORTED_PROTOCOL_VERSIONS = [1]` only. Lingering v0 clients will then receive a clear unsupported-version error rather than silently failing.

## Rolling Back a Scheduled Upgrade

You can cancel a pending upgrade at any time **before** `activation_time`:

```bash
orbis-cli update-ring-post-by-acp --id <RING_ID> --clear-upgrade
```

This removes `next_version` and `activation_time`. The `effective_version` remains `current_version` indefinitely. `--clear-upgrade` conflicts with `--next-version` and `--activation-time`.

After `activation_time` has passed the upgrade cannot be rolled back via `--clear-upgrade`; at that point `next_version` has already become the effective version.

## Error Reference

| Error | Cause | Fix |
|-------|-------|-----|
| `activation_time (X) must be at least Y` | Chain rejected — lead time is less than 600 s | Use `activation_time >= block_time + 600` (15 min recommended) |
| `Ring X requires protocol version 1, but installed versions are [0]` | CLI binary does not support v1 | Upgrade the CLI binary |
| `protocol version for ring X is not installed: effective_version=1 installed_versions=[0] ... route_version=0` | Node binary does not support v1 | Upgrade the node binary before `activation_time` |
| `next_version and activation_time must both be supplied` | Only one flag provided | Pass both `--next-version` and `--activation-time` |
| `next_version conflicts with clear_upgrade` | Both flags given at once | Use one or the other, not both |
