# Orbis network benchmark

`orbis-bench` is a workspace binary for measuring Orbis ceremonies on generated, isolated Docker networks. It is deliberately separate from `orbis-node`: the benchmark runtime image builds and copies only the production-feature `orbis-node` executable, while the host-side benchmark process owns orchestration and evidence collection.

The result is the largest reliable ring observed on the recorded host and emulated network profile. It is not a universal protocol limit.

## Quick start

Build the host tool with the same crypto implementation as the node image:

```console
cargo build -p orbis-bench --release
cargo build -p orbis-bench --release --no-default-features --features decaf377
```

Inspect a suite without starting Docker:

```console
cargo run -p orbis-bench -- plan --config bin/orbis-bench/examples/50-node.yaml
```

Run one case or the full example:

```console
cargo run -p orbis-bench -- run --network-size 3 --ring-size 3 --threshold 2
cargo run -p orbis-bench -- run --config bin/orbis-bench/examples/50-node.yaml
cargo run -p orbis-bench -- run --config bin/orbis-bench/examples/50-node-reshare.yaml
```

Run an advancing capacity sweep. Thresholds default to `ceil(2n/3)`:

```console
cargo run -p orbis-bench -- sweep --network-size 50 --ring-start 3 --ring-max 50 --ring-step 1
cargo run -p orbis-bench -- sweep --network-size 50 --ring-sizes 3,5,10,20,30,40,50
```

The sweep retains failed attempts and stops provisioning larger sizes after two consecutive non-viable sizes. A case is viable only when every configured measured trial passes correctness, finishes before its timeout, and has no restart/OOM/container failure.

Resume and cleanup use the run manifest as the authority:

```console
cargo run -p orbis-bench -- run --resume bench-results/<run-dir>
cargo run -p orbis-bench -- cleanup bench-results/<run-dir>
cargo run -p orbis-bench -- report bench-results/<run-dir>
```

`cleanup` refuses non-`orbis-bench-*` project names and removes only the exact Compose projects listed in that run's manifest. `--keep-network` leaves a failed or completed stack available for inspection.

## Doctor and images

`doctor` checks the Docker daemon, Compose v2, Docker CPU/RAM allocation, host disk, and—when an already-built image is supplied—the presence of `tc`, `NET_ADMIN`, and the absence of `orbis-bench` from the runtime filesystem:

```console
cargo run -p orbis-bench -- doctor
cargo run -p orbis-bench -- doctor --runtime-image orbis-bench-node:bls12-381
```

The benchmark node image is [Dockerfile.node](./Dockerfile.node). It uses the production features `redb`, `authz-sourcehub`, `bulletin-sourcehub`, and `iroh`, plus the selected crypto implementation. It adds only `iproute2` and basic health-check utilities to the runtime layer.

## Lifecycle

Each network-size/profile batch gets a unique Compose project, volumes, bridge network, host ports, labels, resolved Compose file, and genesis patch.

1. Nodes start against an ephemeral SourceHub chain. The production bootstrap Info service exposes their generated signing account and node key while they wait for funding.
2. The nodes stop without deleting their volumes. The tool deterministically assigns memberships and fresh ring IDs from the run seed, writes all rings into genesis, and recreates SourceHub.
3. Bounded multi-message transactions fund accounts, then the same volumes restart. The tool discovers routable Iroh addresses, updates NodeInfo, registers ring ACP objects, and grants committee operator relationships. Oversized or invalid transaction batches are bisected until the bad item is isolated.
4. LAN and WAN use fresh stacks. WAN grants `NET_ADMIN` only to node services and applies `tc netem` only to IPv4 UDP egress, covering Iroh/QUIC while leaving SourceHub TCP and host gRPC traffic unshaped. Applied qdisc output and a UDP calibration probe are recorded.

Capacity planning conservatively partitions stacks before any node could manage more than `MAX_LOCAL_RINGS_PER_NODE` (256). Cases and committee memberships are shuffled deterministically and initiators rotate from the recorded seed.

## Measurements

- Fresh DKG records request acknowledgement separately. Primary latency ends only after SourceHub finalization and matching local ring state on every committee node.
- PRE records server RPC, local decrypt, and total client-visible time and rejects a trial unless plaintext matches.
- SIGN records server RPC and client verification separately. Serial and load responses are verified against the derived public key.
- PSS refresh uses the production scheduler and a short genesis-only interval on a dedicated ring. It requires `last_pss` and every local polynomial to advance while the ring public key remains unchanged. Scheduler delay and ceremony time are recorded separately.
- PSS reshare is opt-in through `operations: [pss_reshare]` and requires an explicit `reshare_overlap`. Every attempt uses a fresh ring, triggers the transition through SourceHub, and succeeds only when the ring public key is unchanged, SourceHub has finalized the requested committee and threshold, all next-committee nodes expose matching local state, and overlapping members advance `last_pss`. The 50-node acceptance example uses old/new committees of 34, overlap 18, and threshold 23.
- PRE/SIGN load is closed-loop at the configured concurrency levels after a distinct warm-up window.

Metrics are scraped around trials and stored as exact deltas. Docker CPU, memory, network/block I/O, PIDs, restart state, and OOM state are sampled once per second.

The example uses a 15-second PSS interval. The production scheduler has a 10-second grace window, so validation requires benchmark intervals greater than 10 seconds; this leaves an observable due point while keeping smoke and capacity runs short.

## Evidence

Every run directory contains:

- `report.html` — self-contained offline HTML with inline SVG charts;
- `manifest.json` — resolved experiment, commit/dirty state, host and Docker allocation, image digests, SourceHub ref, calibration, crypto, and seed;
- `trials.jsonl` — append-only and synced after every attempt for crash-safe resume;
- `setup-failures.jsonl` — setup failures classified separately from protocol trials;
- `summary.csv` and `resource-samples.csv`;
- `stacks/<project>/compose.yaml` and `genesis-patch.json`;
- targeted logs for failed setup/cases.

The report explicitly warns about incomplete runs, small samples, host saturation, and the limitations of single-host Docker and synthetic WAN emulation. Keep the raw directory with any number quoted from the report.
