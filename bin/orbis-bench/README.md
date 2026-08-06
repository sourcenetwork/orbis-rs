# Orbis network benchmark

`orbis-bench` is a workspace binary for measuring Orbis ceremonies on generated, isolated Docker networks. It is deliberately separate from `orbis-node`: the benchmark runtime image builds and copies only the production-feature `orbis-node` executable, while the host-side benchmark process owns orchestration and evidence collection.

For DKG/PRE/SIGN measurements, an [in-process backend](#in-process-backend-no-docker-no-chain) runs nodes as tasks in the `orbis-bench` process itself, with no Docker and no chain involved at all.

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

## In-process backend (no Docker, no chain)

For DKG/PRE/SIGN measurements, `backend: in-process` runs every node as a real `orbis-node` instance inside the `orbis-bench` process itself — real Iroh P2P over loopback, real protocol code, but backed by a shared in-memory mock bulletin instead of a Dockerized SourceHub. There are no containers, no chain, and no external network dependency, so a run can't fail on SourceHub RPC hiccups, Iroh relay reachability, or Docker host contention — only on orbis's own protocol and networking code. The trade-off is realism: it measures orbis in isolation, not the full containerized/chain-backed deployment.

```console
cargo run -p orbis-bench -- plan --config bin/orbis-bench/examples/inprocess-50-node.yaml
cargo run --release -p orbis-bench -- run --config bin/orbis-bench/examples/inprocess-50-node.yaml
```

Build in `--release`; the cryptography is CPU-heavy and a debug build makes 50 nodes sharing one process's scheduler noticeably slower than a real deployment would be. No Docker daemon is required for either command.

This backend is v1: `Experiment::validate` rejects `backend: in-process` combined with any operation other than `dkg`/`pre`/`sign` (no `pss_refresh`/`pss_reshare` yet). PRE/SIGN need no chain-side ACP setup — the mock authz backend authorizes unconditionally — so there's no analogue of the Docker backend's policy/object/relationship registration transactions; a document is stored and a key derivation posted directly, same as the real protocol path minus the chain round trip. Evidence lands in the same `report.html`/`manifest.json`/`trials.jsonl`/`summary.csv` shape as the Docker backend — see [Evidence](#evidence) — except there are no `resource-samples.csv` values (no containers to sample) or `stacks/<project>/compose.yaml` artifacts.

WAN profiles (`delay_ms`/`jitter_ms`/`loss_percent`) work here too, but there's no per-node network namespace to run `tc netem` in, so they're approximated in software instead: `network::ShapedNetwork` (`crates/network/src/shape.rs`) wraps each node's own outbound traffic — on connections it opens *and* connections it accepts, matching Docker's per-container egress-only `tc netem` as closely as this architecture allows — and sleeps for `delay_ms ± jitter_ms` before each send, then fails the send/receive outright with probability `loss_percent`. That last part is the real divergence from Docker: `tc netem` drops individual UDP packets below QUIC, which mostly recovers transparently, so a small `loss_percent` there rarely surfaces as an application-visible failure. Here it's a hard per-message failure, so treat in-process WAN loss numbers as directional stress-testing, not a calibrated stand-in for `tc netem`'s numbers.

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

## Debugging a running or failed stack

While a run is in progress, or after `--keep-network` preserves a failed stack, tail live container logs directly through the generated Compose file. Its `name:` field already sets the project, so no `--project-name` is needed:

```console
docker compose -f bench-results/<run-dir>/stacks/<stack-name>/compose.yaml logs -f
docker compose -f bench-results/<run-dir>/stacks/<stack-name>/compose.yaml logs -f sourcehub-001 node-013
```

Every container also carries `dev.orbis.bench.run`, `dev.orbis.bench.stack`, `dev.orbis.bench.role`, and `dev.orbis.bench.node-index` labels, so you can find or follow one without knowing the exact Compose file path:

```console
docker ps --filter "label=dev.orbis.bench.run=<run-id>"
docker logs -f orbis-bench-<stack-suffix>-node-013-1
```

`cleanup bench-results/<run-dir>` tears the stack down when you are done inspecting it.
