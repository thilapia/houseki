# Native proof qualification

This separate workspace consumes only public Houseki APIs. Its default build verifies public artifacts without witness owners, private allocation support or proving entropy. The `prover` feature installs `ProofAllocator<System>` and reuses the existing public example fixtures with fresh native owners for each attempt. All profiles remain experimental.

Use Rust 1.99.1 and the package's own lockfile. From the repository root, select any of `payment-1-1` through `payment-4-2` or `withdrawal`.

```sh
cargo test --manifest-path crates/houseki-proofs/qualification/Cargo.toml --release --features prover --locked
cargo run --manifest-path crates/houseki-proofs/qualification/Cargo.toml --release --features prover --locked -- produce payment-4-2 /tmp/payment-native 1
cargo run --manifest-path crates/houseki-proofs/qualification/Cargo.toml --release --locked -- verify payment-4-2 /tmp/payment-native/sample-0000 1
```

The third argument is an artifact directory and the fourth is an iteration count from 1 through 1000. Produce creates a new directory with `sample-0000` and subsequent immutable sample directories. Existing directories are rejected. Each sample contains public canonical body and proof bytes and, for payment, separately retained anchor root and count. No protected owner, trace, private opening or key is written. The verifier fixes expected rules independently of artifact headers. Its caller must trust the supplied synthetic anchor metadata independently of proof validity.

Every successful operation emits one JSON observation. `fixture_us` covers fresh native key, note, membership and encryption preparation. `prove_api_us` starts before context and witness preparation and ends with the complete encoded proof. `body_encode_us` measures subsequent public body serialization. `decode_us` covers body and expected context decoding after file transport. `verify_api_us` covers the public verifier call, including its internal proof decoder. Unmeasured phases are `null`. These public boundaries cannot separately attribute internal AIR preparation, backend proving and proof encoding. No misleading internal phase breakdown or complete transaction size is reported because the external transaction envelope is not frozen.

File transport and artifact persistence are outside these timings. Process memory must be measured by the supervising platform and includes the full process. A successful output proof does not establish withdrawal source signatures or account state. A successful payment proof does not establish eligible anchors, unspentness, fee policy or atomic ledger execution. The existing delivery examples exercise the separate native signature and recovery checks.
