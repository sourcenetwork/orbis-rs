# Deferred E2E coverage after harness unification

The backend-neutral E2E harness replaces the old native-only Rust and Python
runners. The shared scenarios currently qualify ordinary DKG, PRE, signing,
restart, member replacement, scheduled refresh, and the migrated reporting
flows on both backends.

Removing the one-off runners does **not** mean every assertion they contained
has been migrated. The following coverage is intentionally deferred and must
not be described as covered by the shared suite:

- PET committee replacement where the incoming member must receive both key
  shares, plus cleanup of the departed member's main/PET/pending/index state.
- Repeated PET member churn and restart/authorization soak coverage.
- Defra signing, persisted-signature recovery, forgery rejection, and document
  replication.
- Retention of PET fault reports and evidence receipts, including proof that a
  rejected or reported share does not mutate the encrypted bundle.
- Polynomial-state regressions that distinguish active, pending, and departed
  local state across refresh and reshare.
- Restart identity details beyond the current public identity and polynomial
  checks, including journal permissions/bytes and certified controller state.
- Crash/power-loss recovery and sustained-load qualification.

When this work is restored, protocol behavior shared by Vera and Hub belongs in
a backend-neutral scenario using `ScenarioFixture` and the existing driver
traits. Backend-specific setup and state inspection belong behind the selected
`TestEnvironment` adapter. Product-specific Trust/Defra behavior may remain a
specialized qualification, but it should use the shared Compose lifecycle and
must not recreate an independent node runner.

Add each migrated shared scenario to `scripts/check-e2e-inventory.sh` so both
backend/curve combinations are compile-discovered in CI without executing the
scenario during the inventory check.
