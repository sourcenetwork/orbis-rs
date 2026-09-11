# LaKey audit keys

Orbis evaluates LaKey through five node-local MPC workers and passes each
transient share to Decaf377 PRE with `derivation = None`. The five-node MPC
requires all five participants online; the PRE reconstruction threshold is three.
The fixed master state contains 512 scalar shares per node. Derived user shares
are not retained as permanent records.

## Identities and registration

An identity binds the Shieldd chain, Orbis ring, epoch, person/general scope,
and amount/sender/receiver field. Person identity uses canonical address bytes.
Asset is bound in Shieldd registration certificates and ACP, not in the PRF.

`SignService.EvaluateShielddAuditKey` requires the ring's
`audit_registration/derive` permission. The signed request binds the canonical
identity and a fresh shared MPC session. Each node signs its public evaluation
under its registered node identity. Certification requires all five signatures
and a consistent degree-two polynomial whose constant is the proposed key.

`SignService.SignShielddAuditRegistration` reconstructs the exact statement using
its configured Shieldd executable and chosen node. Each nonce/share participant
checks all five evaluations for each of the three fields, grants, root ring key,
and `audit_registration/certify` permission. The certificate uses the root FROST
key without derivation or metadata. Chain admission separately enforces registrar
allowlists and policy authority; a certificate alone does not admit an asset.

## Node configuration

- `SHIELDD_AUDIT_VERIFIER`: wallet-free `pcli` executable.
- `SHIELDD_AUDIT_NODE`: independently chosen Bankd/Shieldd node.
- `LAKEY_WORKER`: the `lakey-worker` executable.
- `LAKEY_NODE_CONFIGS`: JSON array of private node configuration paths.

Each namespace selects exactly one private master file and node index. Worker
configuration pins its master digest, executable/library, schedule, bytecode,
and every peer certificate and TLS trust entry.
Each worker has only its own master share and private TLS identity. Requests use
bounded private JSON-line input; nodes reject concurrent worker invocations.

The worker records an operation journal before MPC, verifies master-state
integrity on return/restart, clears transient files, and quarantines unexpected
master changes. Interrupted checks are not successes. Hard process termination
requires restart cleanup; cleanup is not a secure-erasure claim. Epoch rotation
must retain old state for old ciphertexts. Cryptographic review and coordinated
refresh remain deployment gates.

## Client interface

Build `orbis-audit` with `cli-tool --no-default-features --features decaf377`.
It accepts one bounded JSON request on stdin and writes JSON to stdout. Secrets
are never accepted as command-line arguments or echoed in diagnostics.

```json
{"version":1,"operation":{"kind":"capabilities"}}
```

| Operation | Purpose |
|---|---|
| `generate_reader` | Auditor-local random key generation and proof of possession |
| `authentication_identity` | Resolve the public DID for a private relay/registrar authentication seed |
| `registration_object` | Resolve the canonical ACP object for a LaKey identity before granting derivation access |
| `read_ring` | Retrieve ring metadata through a chosen Vera node using the existing bulletin adapter |
| `verify_reader` | Validate the public key and proof without the secret |
| `evaluate` | Obtain authenticated MPC key evaluations from all five nodes |
| `verify_registration` | Verify all five public evaluations against trusted ring metadata |
| `certify` | Obtain and locally verify a Shieldd registration certificate |
| `collect` | Delegated PRE, verifying exact accepted bytes, recipient and registered key |
| `verify` | Independently verify stored encrypted collection evidence |
| `decrypt` | Auditor-local verification and shared-point recovery |

`generate_reader` and `decrypt` output private material and belong only on the
auditor's computer. The intermediary uses `collect` without a reader secret.
The recovered shared point is passed to Shieldd's `disclosure audit-decode`, which
refetches the accepted ciphertext and decodes the selected payload. Decoding is
not PRE verification.

Trusted ring metadata, accepted selection bytes, EPK and registered public key
must come from independently validated configuration/chain/registration evidence,
never from the encrypted collection being verified. Collection results are
returned to Bankd for durable storage; Bankd must expose only stored references
until an independently authorized and audited read.

## Verification boundary

Real five-process tests using freshly MPC-initialized master state cover stable restart, person/field/general
isolation, rejection of public-ratio conversion, fresh-share PRE and substitutions.
Client tests cover changed selection/recipient/key, malformed shares, versions and
proofs of possession. Coordinated Bankd tests additionally exercised live Vera
ACP, five Orbis RPC nodes, accepted Shieldd TestHost transactions, private DefraDB
storage, audited retrieval and local decryption for three general and four named
selections. General keys were seeded in trusted genesis; person certificates were
issued through the live ring. Production setup approval and external cryptographic
review remain deployment gates. Bankd records exact commands and coverage limits
in `infra/disclosure-audit/verification.md`.

## Master provisioning and recovery

Compile `lakey_init_node` and `lakey_derive_node` from the pinned backend using
`scripts/lakey/prepare.py --mode init-node` and `--mode derive-node`. Initialization
checks a common namespace/session before generating the fixed master with MPC.
Do not use the synthetic-state fixture generator for deployment.

On each node, stage an approved public artifact directory, the five public TLS
certificates, its own private TLS key, and the ordered five-line peer list:

```sh
umask 077
python3 scripts/lakey/stage.py --root /private/lakey/epoch-1 \
  --config /private/lakey/epoch-1.json --artifacts /approved/mpc \
  --certificates /approved/committee-certs --tls-key /private/node.key \
  --peers /approved/committee-peers --node 0 --chain CHAIN --ring RING --epoch 1
python3 scripts/lakey/provision.py /private/lakey/epoch-1.json --session FRESH_64_HEX_CHARACTERS
```

Use the index assigned by the canonical sorted Orbis committee. Run initialization
on all five nodes with the same fresh public session. It writes only the local
master, syncs it, and pins its digest in that node's private configuration. Each
node retains only its own TLS private key and master share. Registration still
requires all five authenticated evaluations and a valid root certificate.

An interrupted initialization leaves a marker and cannot be blindly retried.
Diagnose it before resuming. If the master configuration was durably committed,
check its exact digest and committee-wide initialization outcome before removing
the marker. Otherwise use fresh private directories and a new ceremony session;
do not combine partial masters from different attempts.

Back up each node's master file, private configuration, own TLS key, and Orbis
local database independently, using encrypted operator backups. Restore the same
namespace/index and exact configured master digest. A missing participant prevents
derivation; the current protocol cannot recover availability from only three
online nodes. Never collect private master files on an audit intermediary.

Rotation initializes a new epoch and registers its new public keys. Keep the old
epoch's configuration and state for authorized access to historical ciphertexts.
Same-committee refresh requires coordinated backup, MPC completion, and approved
per-node digest updates; it is not exposed as an unattended runtime operation.
Changing a configured digest to silence an unexpected mutation is not recovery.
