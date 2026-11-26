# Orbis network benchmark

`orbis-bench` is a workspace binary for measuring Orbis ceremonies. Every node is a real `orbis-node` instance running as a task inside the `orbis-bench` process, talking real Iroh P2P over loopback, backed by a shared in-memory mock bulletin and mock authorization instead of Vera. There is no external network or service dependency, so a run can't fail on infrastructure unrelated to Orbis's own protocol and networking code. The trade-off is realism: it measures Orbis in isolation, not a deployment backed by Vera.

The result is the largest reliable ring observed on the recorded host and emulated network profile. It is not a universal protocol limit.

## Quick start

Build in `--release`; the cryptography is CPU-heavy and a debug build makes many nodes sharing one process's scheduler noticeably slower than a real deployment would be:

```console
cargo build -p orbis-bench --release
cargo build -p orbis-bench --release --no-default-features --features jubjub,orbis-node
```

Inspect a suite without starting nodes:

```console
cargo run -p orbis-bench -- plan --config bin/orbis-bench/examples/inprocess-50-node.yaml
```

Run one case or a full example:

```console
cargo run --release -p orbis-bench -- run --network-size 3 --ring-size 3 --threshold 2
cargo run --release -p orbis-bench -- run --config bin/orbis-bench/examples/inprocess-50-node.yaml
cargo run --release -p orbis-bench -- run --config bin/orbis-bench/examples/inprocess-pet-comparison.yaml
```

Run an advancing capacity sweep. Thresholds default to `ceil(2n/3)`:

```console
cargo run --release -p orbis-bench -- sweep --network-size 50 --ring-start 3 --ring-max 50 --ring-step 1
cargo run --release -p orbis-bench -- sweep --network-size 50 --ring-sizes 3,5,10,20,30,40,50
```

The sweep retains failed attempts and stops provisioning larger sizes after two consecutive non-viable sizes. A case is viable only when every configured measured trial passes correctness and finishes before its timeout.

Resume and report use the run manifest as the authority:

```console
cargo run --release -p orbis-bench -- run --resume bench-results/<run-dir>
cargo run -p orbis-bench -- report bench-results/<run-dir>
```

## Operations

Supported operations are `dkg`, `pre`, `pet`, `sign`, and `pss_refresh`. PRE/SIGN need no ACP setup — the mock authorization backend authorizes unconditionally — so a document is stored and a key derivation posted directly, the same as the real protocol path minus Vera.

WAN profiles (`delay_ms`/`jitter_ms`/`loss_percent`) are approximated in software: `network::ShapedNetwork` (`crates/network/src/shape.rs`) wraps each node's own outbound traffic, on connections it opens and connections it accepts, and sleeps for `delay_ms ± jitter_ms` before each send, then fails the send/receive outright with probability `loss_percent`. Packet loss below QUIC mostly recovers transparently, so a small loss rate on a real network rarely surfaces as an application-visible failure; here it's a hard per-message failure. Treat WAN loss numbers as directional stress-testing.

Capacity planning conservatively partitions stacks before any node could manage more than `MAX_LOCAL_RINGS_PER_NODE` (256). Cases and committee memberships are shuffled deterministically and initiators rotate from the recorded seed.

## Measurements

- Fresh DKG records request acknowledgement separately. Primary latency ends only after the ring is finalized on the bulletin and every committee node holds matching local ring state.
- PRE records server RPC, local decrypt, and total client-visible time and rejects a trial unless plaintext matches.
- PET runs PRE against a `requires_pet` ring, so the 3-round PET blind equality test runs before each node releases its reencryption share.
- SIGN records server RPC and client verification separately. Serial and load responses are verified against the derived public key.
- PSS refresh uses the production scheduler and a short interval on a dedicated ring. It requires `last_pss` and every local polynomial to advance while the ring public key remains unchanged.
- PRE/SIGN/PET load is closed-loop at the configured concurrency levels after a distinct warm-up window.

The production scheduler has a 10-second grace window, so validation requires benchmark PSS intervals greater than 10 seconds; this leaves an observable due point while keeping smoke and capacity runs short.

## Evidence

Every run directory contains:

- `report.html` — self-contained offline HTML with inline SVG charts;
- `manifest.json` — resolved experiment, commit/dirty state, host, crypto, and seed;
- `trials.jsonl` — append-only and synced after every attempt for crash-safe resume;
- `setup-failures.jsonl` — setup failures classified separately from protocol trials;
- `summary.csv`;
- targeted logs for failed setup/cases.

The report explicitly warns about incomplete runs, small samples, and the limitations of single-process measurement and synthetic WAN emulation. Keep the raw directory with any number quoted from the report.
