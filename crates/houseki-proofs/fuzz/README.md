# Adversarial proof validation

This isolated Rust package depends on the public verifier with `experimental-profiles` and no `prover` feature. It preserves the workspace's pinned dependencies and local backend patches in its own lockfile. Use Rust 1.99.1 and Python 3.12 or newer on macOS or Linux with `ps` available for process supervision. It needs no nightly compiler, witness data or network service.

From the repository root, build and check the harness, then run its deterministic conformance campaign.

```sh
cargo test --manifest-path crates/houseki-proofs/fuzz/Cargo.toml --release --locked
cargo clippy --manifest-path crates/houseki-proofs/fuzz/Cargo.toml --all-targets --locked -- -D warnings -D missing_docs -D clippy::missing_docs_in_private_items
cargo run --manifest-path crates/houseki-proofs/fuzz/Cargo.toml --release --locked -- conformance
```

Conformance verifies every original seed, changes both ends of every canonical body field occurrence and separately challenges encrypted suite, nonce, ciphertext and tag regions, swaps ordered effects, repeats an input marker, changes full anchor count endpoints and attacks all 104 header and dimension bytes. It attempts all ordered pairs of distinct seed proofs, including reheadered proofs. Parsed changed bodies use their matching recognized context and anchor so native context mismatch alone cannot stand in for transcript binding. The report distinguishes cryptographic body rejection from parser, context and statement rejection.

The bounded campaign freezes two 180 second deterministic streams with seeds 24301 and 12648430. Both streams visit all nine original statements and ten mutation classes. They include nested count inflation, omitted and duplicated multiproof nodes, noncanonical field words, repaired truncation and extension, header identity changes and full payload corruption. Inputs range from empty through 2,097,153 bytes, including the inclusive 2 MiB limit and its next byte. The timer begins after valid seed verification and ends before the final successful retry checks. Startup and final retries are included in the separate supervisor wall deadline.

The verifier must return within five seconds and remain below 128 MiB of simultaneously live observed allocations for each case. The supervisor samples process RSS every 200 milliseconds, terminates a worker above 384 MiB, and rejects a 15 second progress stall or a campaign that exceeds its duration by 60 seconds. RSS sampling is an observed process ceiling and can miss subinterval peaks. The allocation observer covers the actual serial verifier call and requires observed temporary allocations to be released on every return. The decoder's separate 16 MiB vector budget remains unchanged. The late-field inline regression requires zero decoder allocations even after scanning a complete real proof.

Check that rebuilding the original executable cannot replace the second stream's worker, then build the executable and run the frozen supervisor with an output directory outside tracked source.

```sh
python3 crates/houseki-proofs/fuzz/campaign.py --self-test
cargo build --manifest-path crates/houseki-proofs/fuzz/Cargo.toml --release --locked
python3 crates/houseki-proofs/fuzz/campaign.py --binary crates/houseki-proofs/fuzz/target/release/houseki-proofs-adversarial --output /tmp/houseki-fuzz-campaign
```

Adjust `--binary` when using `CARGO_TARGET_DIR`. The supervisor copies the executable into its result directory before launching either stream, validates all corpus hashes and records the revision, compiler, executable hash, corpus hash, platform, resource ceilings and completed stream statistics before declaring success. Panics and allocator aborts fail the worker and preserve its last indexed case. No panic catch converts a failure into a successful outcome. Accepted mutated proof bytes are reported for review because proof malleability alone need not change the verified statement.

Replay a case by its zero-based iteration and original stream seed without verifying all earlier mutations.

```sh
cargo run --manifest-path crates/houseki-proofs/fuzz/Cargo.toml --release --locked -- replay 123 24301
```

Run controlled constraint weakenings in a disposable archive of the committed revision. The runner leaves the current checkout untouched, requires each selected regression to pass before mutation, and requires a completed failing test rather than a compiler error or timeout to kill each mutant. Only one test must match each named filter. Every weakening is discarded with its temporary snapshot. The campaign includes primitive range and canonicality equations, native framing, key coefficient bounds, membership occupancy, family amount equality, payment register and accumulator continuity, opening linkage and allocation-free decoder scanning.

```sh
python3 crates/houseki-proofs/fuzz/constraints.py --output /tmp/houseki-constraint-campaign
```

`--only payment-opening-amount` selects one listed mutation. A surviving mutant fails the campaign and identifies missing regression sensitivity. The tests run in release so invalid constraints cannot be rejected only by debug assertions.

Compile real external consumers to check evidence ownership and API boundaries. This command requires a successful valid control and the exact intended compiler error for every negative case. It also checks that the verifier-only consumer cannot import the prover API.

```sh
python3 crates/houseki-proofs/fuzz/evidence.py --output /tmp/houseki-evidence-campaign
```

These campaigns are deterministic mutation fuzzing rather than coverage guided fuzzing. Their finite duration and selected constraint mutations do not establish complete coverage, a cryptographic security bound or zero knowledge. The obligation matrix under `../fixtures/adversarial/coverage.tsv` separates tested behavior from open cryptographic, ledger and platform qualification obligations.
