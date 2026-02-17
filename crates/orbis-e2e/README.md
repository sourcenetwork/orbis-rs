# orbis-e2e

Native integration tests for Orbis. Replaces the Docker-based test harness with
managed processes on localhost.

## How it works

```
┌──────────────────────────────────────────────┐
│  secret_lifecycle.rs (test)                  │
│  Uses cli_tool::* as a library to drive the  │
│  full DKG → Store → PRE → Decrypt pipeline   │
├──────────────────────────────────────────────┤
│  fixture.rs                                  │
│  setup_dkg() → DkgFixture                    │
│  Starts ring, runs DKG, returns owned handle │
│  Processes killed on drop                    │
├────────────┬─────────────────────────────────┤
│ orbis/     │ sourcehub/                      │
│ OrbisRing  │ SourceHubNode                   │
│ OrbisNode  │ Genesis provisioning            │
│ Health     │ Identity (secp256k1 → source1…) │
├────────────┴─────────────────────────────────┤
│  lib.rs                                      │
│  ManagedProcess  SIGTERM→wait→SIGKILL on drop│
│  TestRunDir      target/e2e/{run_id}/        │
│  allocate_ports  OS-assigned, no conflicts   │
└──────────────────────────────────────────────┘
```

## Running

```bash
# Build orbis-node first
cargo build -p orbis-node

# Requires sourcehubd on PATH
cargo test -p orbis-e2e --test secret_lifecycle -- --nocapture
```

Takes ~2 minutes. Starts 3 orbis-node processes + 1 SourceHub devnet.

## Key design decisions

- **Managed processes, not Docker.** Each `ManagedProcess` wraps a child process
  and sends SIGTERM on drop (SIGKILL fallback after 500ms).
- **OS-assigned ports.** `allocate_ports(n)` binds to port 0, grabs the assigned
  ports, releases them. No hardcoded ports, no conflicts between parallel runs.
- **Owned fixtures.** `setup_dkg()` returns an owned `DkgFixture`. When the test
  function returns, Rust drops the fixture and kills all processes. No leaks.
- **cli-tool as library.** Test code calls `cli_tool::do_dkg()`,
  `cli_tool::store_prepared_secret()`, etc. directly — no subprocess CLI invocation.
- **Artifacts.** Each run writes to `target/e2e/{run_id}/`. Cleaned on drop unless
  `ORBIS_E2E_KEEP=1`.
