# Ledger qualification consumers

This standalone Cargo workspace keeps proving outside the ledger library and permits an independent default verifier build.

Generate a new public corpus with `cargo run --release --locked --features prover -- generate-all /absolute/new-corpus`. The supervisor runs all fifteen required workloads in fresh child processes and collects platform peak memory observations. The nine family workloads are `1-1` through `4-2` and `withdrawal`. The remaining scenarios are `value-loop`, `repeated-commitments`, `conflicts`, `failed-early-copy`, `shared-beneficiary` and `anchor-pruning`.

Use `generate /absolute/new-directory --workload 2-2` for one workload. Existing destinations fail before generation. Private allocation is guarded by `ProofAllocator<System>` only in proving executables and proving tests. Exported files contain public commitments, bodies, proofs, signatures, accounts, source declarations and replay data.

Set `HOUSEKI_LEDGER_PUBLIC_CORPUS` to the complete generated directory, then run `cargo test --release --locked verifier_consumer:: -- --test-threads=1` without `prover`. Missing workloads are failures. Run `cargo run --release --locked -- verify /absolute/new-corpus/value-loop` for one verifier only replay, or use the root ledger replay example in a separate build graph.

The digest bound public file reader is shared with that root example as source and uses only public ledger APIs. The selected local fixture manifest is the explicit trust input. These files do not carry a production genesis or consensus certificate.

Generation and fresh replay enforce the named workload's exact receipt outcomes, output counts and accounting. Both reports retain individual checkpoint identities and counts, including empty checkpoints. Malformed hexadecimal metadata returns a parsing error.

The value loop producer first executes a complete provisional one unit fixture so recovery uses a committed output view. That recovered note supplies the later payment witness. It then binds the complete final two unit stream and executes/replays both checkpoints again. Source binding changes artifact identities while the same ordered public effects preserve the note root needed by the subsequent payment.

Measurements separate proof production, source checking, authorization, reconstruction, ordered effects, commitments, publication and replay. The producer's internal replay runs in its proving build graph. The separate default consumer provides the independent verifier only check. Body/context, encapsulation and encrypted payload byte counts overlap. Peak memory is recorded from `/usr/bin/time` around each fresh workload child, with Linux high water data also collected directly when available.
