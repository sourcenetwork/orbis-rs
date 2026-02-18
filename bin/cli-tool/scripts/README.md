# Orbis CLI flow scripts

These scripts walk through the full Orbis flow: node info → register bulletin → DKG → get ring → policy & namespace → reader key → store secret → register object & relationship → PRE (re-encrypt and decrypt).

**Prerequisites**

- Run from the **workspace root** (`orbis-rs`).
- A running **orbis-node** (default gRPC: `http://localhost:50051`) or the full Docker integration stack (see below).
- Local chain (e.g. SourceHub) with the test account pre-funded.

---

## Docker integration flow (3 nodes, threshold 2)

Matches `test_cli_calls_dkg_and_pre_endpoint` in `bin/orbis-node/src/tests.rs` and uses `docker/docker-compose-integration-test.yml`.

1. Start the stack from the workspace root:
   ```bash
   docker compose -f docker/docker-compose-integration-test.yml up -d --build
   ```
2. Wait until sourcehub and all three nodes are healthy (ports 26657, 50051, 50052, 50053).
3. Run the full flow:
   ```bash
   ./bin/cli-tool/scripts/run_integration.sh
   ```

The script: queries all 3 nodes, transforms P2P addresses for inter-container communication (e.g. `peer_id@0.0.0.0:50051` → `peer_id@orbis-integration-node-1:50051`), registers the `orbis` namespace and adds all 3 node public addresses as collaborators, runs DKG with **threshold 2** and 3 peer IDs, waits 60s for completion, then runs policy/namespace, reader key, store secret, register object, set relationship, and PRE. Default user namespace is `docker_test_namespace` (override with `NAMESPACE=...`).

---

## Single-node (dev) flow

Use `run_all.sh` for one node (threshold 1) and a single peer, or run scripts in order and re-use the same shell (or re-source exports) between steps.

```bash
# From workspace root
cd /path/to/orbis-rs

# Option A: run full flow (exports vars between steps)
./bin/cli-tool/scripts/run_all.sh

# Option B: run step by step (eval exports into your shell)
eval $(./bin/cli-tool/scripts/0_info.sh)
./bin/cli-tool/scripts/1_register_orbis.sh
./bin/cli-tool/scripts/2_dkg.sh
sleep 15
eval $(./bin/cli-tool/scripts/3_get_ring.sh)
eval $(./bin/cli-tool/scripts/4_policy_and_namespace.sh)
eval $(./bin/cli-tool/scripts/5_reader_key.sh)
./bin/cli-tool/scripts/6_store_secret.sh
eval $(./bin/cli-tool/scripts/7_register_and_relationship.sh)
./bin/cli-tool/scripts/8_pre.sh
```

**Multi-node (manual)**

For 2+ nodes without Docker, set `PEER_IDS` (space-separated) and `THRESHOLD` before `2_dkg.sh`, and register all node public addresses as bulletin collaborators in step 1.

---

**Variables**

Scripts use (and export where relevant):

- `ENDPOINT` – node gRPC (default `http://localhost:50051`)
- `NODE_PEER_ID`, `NODE_PUBLIC_ADDRESS`, `NODE_P2P_ADDRESS` – from `info`
- `RING_ID`, `RING_PK` – from `get-latest-ring` after DKG
- `POLICY_ID`, `NAMESPACE` – from policy creation and namespace registration
- `READER_PK`, `READER_SK`, `READER_DID_PK` – from `generate-reader-key`
- `OBJECT_ID` – from store-secret output
