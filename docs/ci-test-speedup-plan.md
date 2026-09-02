# CI / Test-suite speedup — plan

Working doc, same style as `security-review-findings.md`: tackle one item at a time,
check it off, keep the notes. Nothing here is committed behaviour yet.

Goal: get a PR's CI feedback from "hours / occasionally 2h+" down to a tight loop,
without losing coverage.

---

## What was measured (2026-09-02)

Read of `.github/workflows/*`, `Cargo.toml`s, `bin/orbis-node/src/tests/`, and
`crates/common/src/test_harness.rs`.

| # | Finding | Evidence |
|---|---------|----------|
| F1 | **No Rust/cargo caching anywhere.** No `Swatinem/rust-cache`, no `actions/cache`, no `sccache`. | `grep -rn 'cache' .github/` → only the docker-publish GHA cache |
| F2 | Every push/PR does **4 cold full-workspace compiles**: `clippy` ×2 crypto + `cargo test` build ×2 crypto. The two crypto matrices (`bls12-381` default vs `decaf377 --no-default-features`) can't share `target/`. | `rust.yml` `clippy` + `build` jobs, both matrices |
| F3 | `lint` job runs **`cargo install cargo-deny --locked`** from source every run (~3–5 min). | `rust.yml` lint step |
| F4 | **No `timeout-minutes`** on `rust.yml` jobs → a hung test runs to GitHub's 6h default. The 20-node scale test is documented as magicsock-race-prone. This is the likely "2h+" cause. | `rust.yml` (no timeout); `tests/scale_testing.rs` sleeps/retries |
| F5 | `build` job's spot runner requests `extras=s3-cache` but **no step uses it** — provisioned, unused. | `rust.yml` `build` `runs-on:` line, no cache step |
| F6 | `lint` + `clippy` run on **`ubuntu-latest` (2 vCPU)**; `clippy --all-targets` compiles the entire test tree (iroh, tonic, ark, decaf377/poseidon377). | `rust.yml` |
| F7 | **Layer-3 Docker tests build a release node inside Docker.** `IntegrationTestNetwork::build()` and `VeraTestContainer::new()` run `docker compose up -d --build`; the compose `build:` runs `cargo build --release --bin orbis-node --features "redb,integration-test,<crypto>"`. Dockerfile has BuildKit cache mounts but they're **cold in CI** (no `cache-from`/registry cache). | `test_harness.rs:135,608`; `docker/Dockerfile`; `docker-compose-integration-test.yml` |
| F8 | **No `[profile.test]` / `[profile.dev]` overrides.** Default `debug = true` (full debuginfo) → slower compile+link. No linker override (`lld`/`mold`). | `Cargo.toml` (no `[profile.*]`) |
| F9 | **No `cargo-nextest`.** Plain `cargo test`: no per-test timeout, no retry, no cross-binary parallelism, no timing report. `--verbose` adds log noise. | `rust.yml` `build` step |
| F10 | **874 `#[test]`/`#[tokio::test]` fns; 152 `#[serial]` sites.** `crates/network/src/iroh/tests.rs` is ~all `#[serial]`; `dkg/v0/tests/*`, `pre/v0/tests.rs`, `sign/v0/tests.rs`, `reporting/v0/tests.rs` also heavy on `#[serial]`. | grep counts |
| F11 | Scale test: `NETWORK_SIZE=20`, `DKG_DEADLINE=180s`, several `sleep(2s)`/`sleep(300ms)` + retry loops. | `tests/scale_testing.rs` |
| F12 | `fault_injection.rs`: 10 tests, `PRE_COLLECTION_TIMEOUT`/`SIGN_COLLECTION_TIMEOUT` = 30s each. | `constants.rs`, `tests/fault_injection.rs` |
| F13 | A **fast subset exists**: Docker modules (`concurrent`, `reporting`, `fault_injection`, `cancel_ring_reshare`, `pending_ring_cancellation`) are `#[cfg(feature = "integration-test")]`. But `tests/integration.rs` and `tests/upgrade.rs` are declared `mod` **ungated** yet `use common::IntegrationTestNetwork` — needs a look (see I2). | `tests/mod.rs`; grep for `#[cfg` in those files → 0 |
| F14 | `upgrade-compatibility.yml`: `timeout-minutes: 120`, `ubuntu-latest`, builds orbis images via Docker ×2 crypto, on every PR to `develop`. `--from` is hard-pinned to `baa27c4…` and ignores the resolved `steps.baseline.outputs.sha`. | `upgrade-compatibility.yml` |

---

## Phase 0 — Measure (do first, ~half a day)

Everything below is hypothesis until these land.

- [ ] **I1 — Get the real wall-time breakdown.** From a recent CI run's timing view:
  per job, and within `build`: "compile" vs "run tests" split, and the slowest 20
  individual tests. Cheapest: add `--nocapture` off + `cargo test -- --report-time`
  (unstable) or switch the measurement run to `cargo nextest run` (prints per-test
  timings) once. Record numbers here.
- [ ] **I2 — Fast-lane feasibility.** Confirm exactly which test modules compile &
  run without `--features integration-test,fault-injection,scale-testing`.
  `tests/integration.rs` / `tests/upgrade.rs` look ungated but reference
  `IntegrationTestNetwork`; determine whether they need `#[cfg(feature =
  "integration-test")]` added (they almost certainly should). Produce the exact
  feature/module split for a "fast" vs "slow" job.
- [ ] **I3 — Does the `build` runner have Docker, and do Layer-2/3 tests actually
  run in CI today?** (They need `docker`; `common`/`authz`/`bulletin` vera tests
  also need `curl`.) If they run, F7 is a top cost; if they're silently skipped,
  the plan changes.
- [ ] **I4 — How many distinct `docker compose … up --build` invocations happen per
  `cargo test` run** (per compose project name). If `reporting.rs`'s 14 tests each
  rebuild, that's the single biggest lever; if the project name is reused and the
  image is built once, less so.
- [ ] **I5 — `runs-on` s3-cache**: what's the supported way to persist `target/` and
  `~/.cargo` on these runners (their cache action vs plain `actions/cache` against
  the provisioned bucket).
- [ ] **I6 — Flaky-test census.** Re-run the suite 3–5× (nextest `--retries` or a
  loop); list tests that fail non-deterministically. These need fixing before any
  parallelism increase or they'll just fail faster.

---

## Phase 1 — Caching & quick wins (highest ROI, low risk)

- [x] **T1 — `Swatinem/rust-cache@v2` on `lint`, `clippy`, `build`** (2026-09-02).
  Placed after `rustup update stable`; `key: ${{ matrix.crypto }}` on the two matrix
  jobs so bls/decaf caches don't collide, `key: lint` on lint. On the `build` spot
  runner this also routes through the provisioned `extras=s3-cache` (covers T4).
- [x] **T2 — cargo-deny via `taiki-e/install-action@v2`** (`tool: cargo-deny`)
  instead of `cargo install cargo-deny --locked` (2026-09-02). Prebuilt binary,
  seconds not minutes.
- [ ] **T3 — `timeout-minutes` per job.** **Deferred by user** — some tests are
  legitimately long, so a blunt per-job cap risks false failures. Better fit: the
  per-test `slow-timeout` from `cargo-nextest` (T13), which fails only the wedged
  test. Revisit as a loose safety net (e.g. `build: 120`) once I1 gives real
  numbers.
- [ ] **T4 — Use the s3-cache on the `build` runner** for `target/` + registry
  (per I5). The runner already pays for it. (S–M)
- [ ] **T5 — Docker layer cache for the integration image.** Give the Layer-3
  compose build a warm start: either build the `orbis-node` integration image once
  per CI run as an explicit step with `docker buildx --cache-to/--cache-from
  type=gha` (or registry) and have `docker compose` reuse it (`pull_policy: never`,
  drop `--build`), or push a `:ci-cache` image nightly. Removes the cold
  `cargo build --release` from inside the test run. (M) — depends on I3/I4.
- [ ] **T6 — Drop `--verbose` from `cargo test`** (or move to `nextest`, T13). Minor,
  but the log volume slows the runner's stdout handling and buries failures. (S)

---

## Phase 2 — Compile time

- [ ] **T7 — `[profile.test]` / `[profile.dev]` tuning** in workspace `Cargo.toml`:
  `debug = "line-tables-only"`, `split-debuginfo = "unpacked"` (Linux),
  consider `opt-level = 1` for deps only via `[profile.dev.package."*"]`. Measure
  compile + link delta. (S, reversible)
- [ ] **T8 — Faster linker.** `.cargo/config.toml` `[target.x86_64-unknown-linux-gnu]
  rustflags = ["-C", "link-arg=-fuse-ld=lld"]` (install `lld` in CI) or `mold`.
  Linking this many crates + iroh is a real chunk of each compile. CI-only if you
  don't want to force it locally (put it behind an env or a CI-only config). (S–M)
- [ ] **T9 — Split `clippy` from the test build.** `clippy --all-targets` recompiles
  the whole test tree with clippy metadata that `cargo test` can't reuse. Options:
  keep `clippy` on lib+bins only (`--all-targets` → default targets) and let the
  `build` job's `cargo test` catch test-code warnings via `RUSTFLAGS=-Dwarnings`;
  or run clippy once and `cargo test` against the same profile. Needs care not to
  lose test-code lint coverage. (M)
- [ ] **T10 — Collapse or stage the crypto matrix.** Today every job is ×2 full cold
  builds. Consider: run the full `build` (tests) on **one** crypto per PR
  (whichever is default) and the other crypto's tests on `develop` push / nightly;
  keep `clippy` ×2 (cheap-ish, catches cfg breakage). Or gate the second matrix
  behind a label. (M, policy call)
- [ ] **T11 — `cargo-chef` for the integration Dockerfile** so the dependency
  compile is a cached layer independent of workspace source changes (the current
  `COPY . .` + BuildKit cache-mount only helps warm). Complements T5. (M)

---

## Phase 3 — Test execution restructure

- [ ] **T12 — Split CI into `fast` and `slow` jobs** (from I2):
  - `fast`: `cargo test` / `nextest` with **no** integration features — unit +
    in-process-no-Docker. Runs on every PR, must be quick (target < 10 min warm).
    Add `#[cfg(feature = "integration-test")]` to `integration.rs` / `upgrade.rs`
    if I2 confirms they're ungated.
  - `slow`: the Docker layers (`integration-test`, `fault-injection`) — runs on
    every PR too (for now) but as a separate, independently-timed job so a slow/
    hung Docker test doesn't hide unit failures.
  - `scale`: `scale-testing` — move to `develop` push + nightly + manual dispatch,
    **not** every PR. It's one test, 20 nodes, race-prone, and doesn't gate
    correctness the way the unit + 3-node tests do. (M)
- [ ] **T13 — Adopt `cargo-nextest`** for the test jobs. Gains: per-test timeout
  (`slow-timeout { period, terminate-after }`), `--retries` for known-flaky,
  parallel execution across test binaries, machine-readable timings, `--partition`
  for sharding. Add `.config/nextest.toml` with a `serial` test-group only where
  `#[serial]` truly needs it. (M)
- [ ] **T14 — Shard the slow/Docker job** with `nextest --partition` across N
  runners once T13 lands and I4 shows the image is built once (not per test). (M)
- [ ] **T15 — One shared chain container per Docker test binary.** If each test in
  `reporting.rs` spins its own `VeraTestContainer`/compose project, switch to a
  module-level shared fixture (once per binary, `OnceCell` + teardown) where the
  tests don't need isolation, or a pool. Big win if I4 shows per-test bringup. (M–L)

---

## Phase 4 — Test hygiene / flakiness

- [ ] **T16 — Audit the 152 `#[serial]` sites.** Many in-process tests
  (`dkg/v0/tests/*`, `pre/v0/tests.rs`, `sign/v0/tests.rs`) may be serial by
  copy-paste rather than necessity. Each unnecessary `#[serial]` is lost
  parallelism. Keep it only where there's real shared state (fixed ports, global
  iroh magicsock, a shared on-disk path, a shared Docker project). (M)
- [ ] **T17 — Fix or delete the flaky tests from I6.** Per repo precedent
  (`feedback_docker_race_vs_unit_test.md`): if a Docker test is a structurally
  unwinnable race, replace it with a fast deterministic unit test rather than
  tuning sleeps. (M, ongoing)
- [ ] **T18 — Scale test knobs.** If T12 keeps it on nightly, also parameterise
  `NETWORK_SIZE` (env, default 20 on nightly / 6–8 on a "smoke" variant for
  develop push) so there's a fast signal without the full 20-node race surface. (S)
- [ ] **T19 — Tighten Docker healthcheck waits.** `test_harness.rs` node wait is
  `max_attempts = 120` (~4 min); vera healthcheck `interval: 5s, retries: 30`.
  Once images are pre-built (T5), nodes start fast — drop the ceilings and shorten
  intervals so failures surface in seconds, not minutes. (S)
- [ ] **T20 — `upgrade-compatibility.yml`**: add caching (T1), fix the `--from` to
  use `steps.baseline.outputs.sha` instead of the hard-pinned `baa27c4…`, and
  consider moving it off every-PR to label / nightly if I1 shows it's a long pole. (S–M)

---

## Guardrails (adopt alongside)

- [x] **`concurrency:` group on `rust.yml`** (`group: ${{ github.workflow }}-${{
  github.ref }}`, `cancel-in-progress: true`) so a newer push cancels the
  superseded run (2026-09-02). Matches `docker-publish.yml`.
- [ ] Job `timeout-minutes` (T3 — deferred by user, see above).
- [ ] `nextest` per-test `slow-timeout` so one wedged test fails in minutes (T13).
- Keep `fail-fast: false` on matrices (already set) so one crypto failing still
  reports the other.

---

## Suggested order

1. **DONE 2026-09-02:** T1 (rust-cache ×3), T2 (cargo-deny binstall), `concurrency:`
   cancel-in-progress. Config-only; warms every compile and cancels stale runs.
   T3 (per-job timeout) deferred — long tests; use nextest per-test timeout instead.
2. **Measure:** Phase 0 (I1–I6) — do next, in parallel.
3. **Then:** T12 + T13 (fast/slow split + nextest) — the structural fix.
4. **Then, as data warrants:** T5/T11 (Docker build caching), T7/T8 (compile
   knobs), T10 (matrix staging), T15/T16 (fixture + serial audit).
5. **Cleanup:** T17–T20.
