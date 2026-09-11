# LaKey → existing Orbis PRE

This example tests whether LaKey can derive independent Decaf377 key shares
from fixed per-node master state and pass those shares into existing Orbis PRE.
For node integration, authenticated registration, provisioning and recovery, see
[the node integration guide](../../docs/lakey.md). The commands below exercise
the synthetic reference harness; they are not deployment provisioning.

Each node retains 512 master scalar shares (16 KiB, plus a file header),
independent of the number of identities. Four synthetic identities distinguish
Alice/Bob, amount/sender, and named/general scopes. Derived shares are transient;
PRE receives the derived key directly with `derivation = None`. Public keys must
be registered for encryptors: they cannot compute them from a public master key.

The MPC backend is the published LaKey research implementation, pinned below.
The example checks its output against an independent clear computation, builds
public polynomial commitments, and runs Orbis encryption, PRE share verification,
reconstruction, and decryption. It scans each ciphertext under all four scopes;
only the matching scope decrypts. Wrong public commitments, changed ephemeral
points, and insufficient shares are rejected. Restart and same-committee refresh
must preserve all derived public keys.

## Test boundary

**Use synthetic keys only.** The Rust driver reads every local node's fixture
and reconstructs the synthetic master for its independent reference check. It
is not production node isolation or a deployed Orbis ring. MPC itself runs real
malicious-Shamir processes with live preprocessing and TLS. No fake preprocessing
is used. This is an interoperability experiment, not a security proof of LaKey,
its parameter selection, or a complete Shieldd integration.

The reader supports the pinned backend's 64-bit little-endian Montgomery fixture
format. It removes the four transient derived-share slots after reading them.
The public reference file contains public keys only; retain it across restart
and refresh, and use a new file for a new master.

## Reproduction

Run heavy commands sequentially. The tested macOS ARM setup uses Homebrew GMP,
Boost, libsodium, and OpenSSL. Adapt dependency paths on other systems. Use a
fresh dependency checkout; never point this at operational ring state.

```sh
orbis_dir=/absolute/path/orbis-poc-lakey
mpc_dir=/absolute/path/MP-SPDZ-lakey
export CARGO_BUILD_JOBS=2 RAYON_NUM_THREADS=2
umask 077

git clone --branch lattice-prf https://github.com/MetaMask/MP-SPDZ.git "$mpc_dir"
cd "$mpc_dir"
git checkout 7a9efcadf134263a94cd0548456e60011a7d4492
git submodule update --init deps/simde
git apply "$orbis_dir/scripts/lakey/macos.patch"
cp "$orbis_dir/scripts/lakey/CONFIG.mine.macos" CONFIG.mine
make -j2 malicious-shamir-party.x
bash Scripts/setup-ssl.sh 5
chmod 600 Player-Data/*.key

for mode in init derive refresh; do
    python3 "$orbis_dir/scripts/lakey/prepare.py" . --mode "$mode"
    ./compile.py -O -g 256 "poc_lakey_$mode"
done

cd "$orbis_dir"
cargo build -p crypto --example lakey_pre --no-default-features --features decaf377
cd "$mpc_dir"
scalar_prime=2111115437357092606062206234695386632838870926408408195193685246394721360383
PLAYERS=5 THRESHOLD=2 bash Scripts/mal-shamir.sh poc_lakey_init --prime "$scalar_prime" -S 128
for mode in derive derive refresh; do
    PLAYERS=5 THRESHOLD=2 bash Scripts/mal-shamir.sh "poc_lakey_$mode" --prime "$scalar_prime" -S 128
    "$orbis_dir/target/debug/examples/lakey_pre" "$mpc_dir/Persistence" 5 3 "$mpc_dir/public-reference.json"
done
```

`THRESHOLD=2` is the MPC degree/corruption bound: reconstruction uses three
shares. All five MPC participants are online in this experiment; this does not
establish derivation availability with only three live nodes. Each repeated
execution starts fresh processes. Refresh adds fresh sharings of zero; it tests
same-committee key stability, not membership migration or secure erasure.

Parameters are REG32, dimension 512, 24 retained bits per row, and 128-bit
statistical settings. The runtime prime is the Decaf377 scalar field. The `-g 256`
compiler path uses bounded integer conversions; do not substitute `-P` without
checking conversion cost and bounds. The macOS patch adapts the old research fork
to current GMP/Boost. `NO_MIXED_CIRCUITS` disables its unused binary backend;
arithmetic malicious checks remain enabled. This patch needs upstream review.

## Work needed before production integration

- Provision, protect, back up, and refresh committee master shares. Define
  recovery and committee membership changes.
- Replace these four compiled fixtures with a fixed derivation program and
  canonical, domain-separated identities. Never accept caller-chosen matrices.
- Keep each derived share on its node. Authenticate public polynomial
  commitments and bind registered public keys to the exact identity and epoch.
- Add Orbis request routing and authorization for the derived key. Enforce ACP,
  recipient authorization, replay protection, and accepted-ciphertext binding.
  None of these service checks are provided by this example.
- Review LaKey parameters and implementation, side channels, erasure, concurrency,
  and abort/recovery behavior. Measure wider committees before selecting one;
  user count alone does not determine committee size.

The existing PRE functions accept the derived shares without algorithm changes.
Production integration still requires node orchestration and authenticated key
registration. This example does not make the existing public scalar derivation
safe for person-scoped access; it bypasses that derivation entirely.

[LaKey implementation](https://github.com/MetaMask/MP-SPDZ/tree/7a9efcadf134263a94cd0548456e60011a7d4492)
and [comparison experiments](https://github.com/mizufinance/shieldd/blob/ca88d386c34acd83560f4f44076b68a6440f7cb0/experiments/orbis-keys/REPORT.md).

## Validation recorded for this PoC

On macOS ARM, against Orbis base `4f9d23c6`:

- The Decaf377 example built; all 32 crypto library tests passed.
- Real five-process malicious-Shamir initialization, derivation, restart, and
  refresh passed with live preprocessing at the exact Decaf377 scalar modulus.
- All three Rust interoperability runs passed the clear reference and negative
  checks. Derived public keys stayed unchanged across restart and refresh.
- The final debug-mode PRE/encryption/decryption checks took approximately
  0.77 seconds for four ciphertexts scanned under four scopes. This excludes MPC
  derivation and is not a production latency benchmark.
- No new swap usage was observed. Rust formatting and Python syntax checks passed.

No live Orbis node API, ACP, Shieldd transaction circuit, browser/WASM, release
build, or production deployment check ran for this example-only PR.
