# Houseki ledger

A synchronous native reference execution engine for exact ordered payment and reward withdrawal occurrences. It validates bootstrap data, verifies complete source units, derives deterministic checkpoint ranges, applies conserved state effects, and publishes state plus replay history through one immutable ownership swap.

Default features are empty. The development preset requires `experimental-profiles`, which explicitly admits the existing experimental payment and withdrawal profiles. The library depends on verifier only `houseki-proofs` and receives public bodies, proofs and source signatures. Private wallet witnesses remain in the separate qualification producer.

## Execution boundary

1. Build a `ReferenceStore` from an independently trusted `BootstrapManifest`. Its expected state commitment and complete finite source identities must match actual reconstruction and the expected stream.
2. Construct `FixtureOrderVerifier` with the complete bounded fixture declarations and a parent snapshot. Verify a complete `RawOrderUnit`.
3. Call `LedgerEngine::authorize_unit` using one shared `ProofRuntime`. Every envelope must pass before the first range can prepare.
4. Call `prepare_next` against the current snapshot. Inspect its artifact, receipts, effects, next cursor and post state preview.
5. Commit the immutable candidate. A retained clone supports exact historical retry after a lost response.
6. Continue the same authorized unit while its persisted cursor remains active. Accounts, nonces and nullifiers are evaluated again under each checkpoint's fixed rules.

Every origin receives a receipt. An earlier state rejection does not suppress a later genuine occurrence. Fees go to the authenticated author of the first successful execution. Source/beneficiary aliasing retains the gross affordability requirement.

`CommittedCheckpoint::accepted_outputs()` joins accepted original body slots with actual appended positions. It preserves complete payment/withdrawal recovery context and repeated commitments, while excluding rejected outputs. Recipient recovery is performed locally through the existing note APIs.

## Reproduction

```sh
python3 crates/houseki-ledger/tools/reference_vectors.py --check crates/houseki-ledger/fixtures/reference-v1
cargo test -p houseki-ledger --locked --no-default-features
cargo test -p houseki-ledger --release --locked --features experimental-profiles
cargo run --release --manifest-path crates/houseki-ledger/qualification/Cargo.toml --locked --features prover -- generate-all /absolute/new-corpus
HOUSEKI_LEDGER_PUBLIC_CORPUS=/absolute/new-corpus cargo test --release --manifest-path crates/houseki-ledger/qualification/Cargo.toml --locked verifier_consumer:: -- --test-threads=1
cargo run -p houseki-ledger --release --locked --no-default-features --features experimental-profiles --example replay -- /absolute/new-corpus/value-loop
```

The producer covers eight payment shapes, signed withdrawal, the exact value loop, repeated commitments, conflicts, failed early copies, shared beneficiaries and real expired anchor verification after pruning. Generation creates new directories and exports public inputs with SHA3-512 file digests. Randomized regeneration produces new public identities. Keep each corpus and its own manifest together.

The replay container has an explicit schema 1 field order and bounded nested records. Decoding supplies representations. `replay` independently validates the bootstrap/source bindings, freshly authorizes complete units, recomputes checkpoints and compares every canonical record. A partly consumed unit retains its entire public input and verification prerequisites.

## Observations and scope

Preparation exposes separate operational reconstruction, state execution and commitment timings. The producer records authorization, publication and replay, complete input/body/proof bytes, retained unit/archive bytes and accepted recovery context costs. Byte categories overlap. `generate-all` runs each workload in a measured fresh process and records peak memory when available, explicitly marking unavailable observations.

Producer and fresh verifier reports include every checkpoint's artifact identity, accepted/rejected occurrence counts and appended output count. Qualification requires each named workload's exact outcomes and accounting in addition to byte identical replay, so a consistently rejected payment cannot qualify as a successful family workload.

The reference caps include 4,096 leaves and spent markers, 64 accounts/validators/units, 128 occurrences per unit, and 64 per checkpoint. Complete length prefixed component bytes are capped at 32 MiB per unit and 16 MiB per checkpoint. Retaining every historical reference snapshot can be expensive. The conservative archive decoder bound follows the finite record caps, and callers can supply a tighter `DecodeLimits` byte budget.

Fixture order reports `FinalityStatus::Unconfirmed` and `ExecutionProofStatus::Unverified`. A historical handle identifies its own checkpoint. The in memory store establishes process local atomic publication. Durable storage, live consensus, network resilience, LedgerAir and compact client scanning require their separately designed integrations.
