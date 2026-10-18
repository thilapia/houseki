# Houseki proofs

`houseki-proofs` provides experimental payment and reward-withdrawal output proofs through one native Rust facade. Payment supports every combination of one through four inputs and one or two outputs. Withdrawal has one output.

The default build recognizes no production profile. `experimental-profiles` enables qualification of the retained experimental identities. Independent cryptographic review was skipped by the owner because paid review is unavailable. Tests and author review do not establish the open composed security claims. The [release policy](release-policy.json) records the exact release scope and remaining gates.

## Features and consumers

The default feature set provides the verifier interface without witness owners, a protected allocator or proving entropy. Enable `prover` for proving and `experimental-profiles` for the current candidate. Consumers use Houseki types and do not see backend field, AIR or proof object types.

The [payment example](examples/payment/main.rs) generates a real payment, authenticates delivery, recovers outputs, appends their commitments and spends the recovered notes. It demonstrates separate spent-set and eligible-anchor checks. The [withdrawal example](examples/reward_withdrawal/main.rs) proves the output relation and separately verifies the source signature and authenticated recovery.

```sh
cargo run -p houseki-proofs --release --locked --features prover,experimental-profiles --example payment -- --inputs 4 --outputs 2 --directory /tmp/payment-public
cargo run -p houseki-proofs --release --locked --features prover,experimental-profiles --example reward_withdrawal -- /tmp/withdrawal-public
cargo run -p houseki-proofs --release --locked --features experimental-profiles --example verify_reward_withdrawal -- /tmp/withdrawal-public
```

Use new output directories. They contain public interoperability bytes only. The independent payment verifier also requires an independently expected anchor root and occupied count, as documented in its [source](examples/verify_payment.rs). The [separate qualification workspace](qualification/README.md) supplies prover-enabled and verifier-only consumers, every supported workload, native measurements and an Android application harness.

## Ownership and admission

A proving application installs `ProofAllocator<System>` as its global allocator and keeps the backend serial with panic unwinding enabled. `ProofRuntime::check_prover_allocator` checks this integration before private work. Enabling backend parallelism or disabling panic unwinding makes the current protected proving configuration unavailable.

`PaymentWitness` borrows original native spend witnesses and output openings. Withdrawal proving borrows its output opening directly. Neither family clones keys into a public witness container. Keep original protected owners alive until the proving call returns. Private temporary work is cleared on ordinary return, supported cancellation and Rust unwinding. Process termination and operating-system suspension cannot promise destructor execution.

Each runtime admits one combined proof or verification operation. Excess calls return busy immediately without a queue. Multiple runtimes require an application-wide admission limit because their memory usage can add up. Each admitted proving attempt consumes its cancellation token, including attempts that fail validation. A retry creates a new token and obtains fresh proving entropy. Request cancellation when foreground execution ends. On resumption, finish discarding interrupted work before admitting a new attempt. Never checkpoint private traces to disk.

Successful verification returns family-specific evidence borrowing the exact checked body, context and payment anchor. Evidence is not an owned authorization certificate and cannot be rebound to different inputs. Errors never justify applying a partially verified transaction.

## External transaction checks

A withdrawal output proof establishes the output relation and binds the public body. The consuming protocol must independently verify the native source signature, account balance, nonce eligibility, activation and fee policy before atomic execution.

A payment proof establishes its supported relation under the supplied expected anchor. The consuming protocol must independently establish anchor eligibility, input unspentness, rule activation, fee policy, output-tree capacity and atomic state updates. Authentic encrypted delivery and recipient recovery remain native consumer operations. This crate does not implement a ledger, checkpoint consensus or a complete transaction envelope.

## Platform and resource contract

First releases target Apple Silicon macOS, Linux x86-64 and Android ARM64. Windows and iOS are deferred. The declared floor is macOS 15, Ubuntu 24.04 with glibc 2.39 and SSE2, and Android 14 API 34 with NEON. Optional CPU features must not enter portable builds without safe dispatch and a verified baseline fallback.

| Target | Current engineering evidence | Qualification still required |
| --- | --- | --- |
| Apple Silicon macOS | Native M4 library and public consumer runs | Reference M1 hardware, complete sample and power matrix, disposition of target misses |
| Linux x86-64 | Locked native CI and complete public proof exchange prepared | Actual candidate CI execution and reference laptop/desktop campaigns |
| Android ARM64 | Available Redmi library and real NativeActivity execution | Reference Pixel 8a, complete sample conditions and application lifecycle matrix |

Proofs are capped at 2,097,152 bytes, canonical bodies at 16,384 bytes and each encrypted output payload at 4,096 bytes. Dimension and decoded-allocation bounds apply in addition to encoded bytes. A byte cap alone is not a work bound. The full transaction envelope is not frozen, so these limits are not a complete transaction wire-size claim.

Mobile proving has a soft p95 target of 30 seconds. The preferred prover process footprint is 1 GiB and the upper planning target is 2 GiB, both soft targets. Misses require a measured disposition rather than proof rejection or an automatic proving timeout. Whole-process and verifier memory measurements remain separate. Qualification requires 30 fresh-process cold samples, 100 warm samples and 15 minutes of sustained work for every workload under declared reference conditions. Small exploratory runs do not establish those distributions.

## Compatibility and release preparation

Profile identities bind exact statements, shapes, constraints, transcript rules, cryptographic parameters and codecs. Preserve old identities immutably. Any incompatible change requires a new identity and fresh affected conformance, device and security evidence. Do not silently retarget an existing identifier to a different circuit or configuration.

The consuming protocol owns activation, deprecation and emergency admission policy. Disabling new proofs must remain distinct from historical verification under the original rules. Keep the original verification implementation and profile artifacts available for historical statements according to that protocol's retention policy.

The qualification [release tool](qualification/release.py) packages committed source, resolved dependency and license metadata, lockfile hashes, profile definition hashes, compiler identity and explicit evidence dispositions. It excludes local reports and caches. An optional exact-version OSV query records outstanding upstream advisories without treating database silence as a security proof. The current workspace disables package publication and has no selected Houseki project license. Those facts remain visible in the candidate manifest.

Diagnostics may contain fixed public error categories, supported profile identifiers, encoded sizes and timing. Never log keys, private openings, raw traces or private witness values. An upstream security change requires checking its effect on the retained dependency version and local patches, then rerunning affected qualification and review gates. Preparing a source package does not publish it or activate any network profile.
