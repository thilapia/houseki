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

## Android application

The qualification application uses the [NDK NativeActivity callbacks](https://developer.android.com/ndk/reference/struct/a-native-activity-callbacks) to resume foreground admission and request cancellation on pause, stop or destruction. A background Rust worker owns every private fixture until its operation returns. The process singleton retains only paths, public runtime state and the cancellation controller. A resumed request receives busy status until the interrupted worker drops its lease. The harness never queues the retry or checkpoints a trace. Forced process termination cannot run destructors.

Configure `ANDROID_HOME` or `ANDROID_SDK_ROOT`, an installed API 34 SDK, NDK and JDK on macOS or Linux. The builder discovers installed versions and records the actual selection. It uses no Android Studio, Gradle or Java proof implementation. Only the narrow application-private path and public lifecycle status cross the C callback boundary. Every accepted path is copied before return and callback panics are contained in Rust.

```sh
python3 crates/houseki-proofs/qualification/android.py --output /tmp/houseki-native-app
python3 crates/houseki-proofs/qualification/android_run.py --adb "$ANDROID_HOME/platform-tools/adb" --serial DEVICE_SERIAL --apk /tmp/houseki-native-app/qualification.apk --output /tmp/houseki-lifecycle --workload withdrawal --cancel
```

Accept the synthetic debug application installation on the phone when required. Add `--skip-install` for later workloads using the same APK. The runner verifies the installed APK's SHA3-512 digest, records actual callback events and kernel `VmHWM`, transfers only public files and stops the app after evidence retrieval. A lifecycle run requires cancellation cleanup within one second while scheduled and a later successful fresh attempt in the same process. Its separate 24 hour supervision ceiling accommodates full warm and sustained campaigns and is not a proving performance target. Process exit, panic, invalid proof or deadline failure fails the run rather than dropping an observation.

Transient USB loss may recover within an explicit bounded observation grace period without restarting the attempt. Every such gap is retained and prevents an uninterrupted-observation claim. The original process must still be alive after reconnection, so an automatically restarted application cannot silently replace a failed proof. The driver retains its own source snapshot and checksum alongside each run. Failed or incomplete evidence collection fails the result and still attempts to stop the synthetic application.

Use `--warm 100` for one initial proof followed by 100 fresh attempts in the same application process. Add `--soak-seconds 900` for sustained fresh attempts afterward. Foreground callbacks trigger each attempt, and the driver fails if the process changes during a warm series. The activity returns home between completed proofs and reenters foreground before starting the next, without intentionally cooling the device. A new attempt always gets its own cancellation token. The short validation runs of these modes remain exploratory. The full required cold series is collected with separate fresh-process invocations.

The APK uses compressed shared libraries with extraction enabled and 16 KiB ELF segment alignment. This follows Android's [documented extraction alternative](https://developer.android.com/guide/practices/page-sizes) and works with installed build tools that predate `zipalign -P`. It does not establish a physical 16 KiB device pass. The APK is debuggable solely for controlled synthetic measurement and public evidence retrieval. Do not distribute it as a wallet or place real secrets in it.

Application runs are explicitly exploratory until the contract's reference hardware, sample counts, power, battery, ambient and thermal conditions are satisfied. CLI execution and application execution remain separate evidence categories. iOS and Windows are deferred from the first-release matrix by the owner's decision.

## Native campaigns and exchange

The native measurement runner freezes its executable before any series and records exact source, compiler, binary digest and per-child kernel peak RSS. It preserves failed operations and all output. A failed proof, crash, allocation failure or supervision deadline never becomes a discarded timing sample. Medians, nearest-rank p95 and maxima remain separate by phase, workload and platform. Soft target misses are reported without turning them into proving timeouts.

```sh
python3 crates/houseki-proofs/qualification/campaign.py --self-test
cargo build --manifest-path crates/houseki-proofs/qualification/Cargo.toml --release --features prover --locked
python3 crates/houseki-proofs/qualification/campaign.py --binary crates/houseki-proofs/qualification/target/release/houseki-proofs-qualification --output /tmp/houseki-native-campaign --exploratory --cold 1 --warm 1 --soak-seconds 0
```

Remove `--exploratory` only for a contract campaign. The defaults require 30 cold samples, 100 warm samples and 900 sustained seconds for each of the nine workloads. Supply `--conditions` with measured `ambient_celsius` from 20 through 25, actual `power` as `external` or `battery`, `power_saver: false`, `physical: true` and the actual `reference_device` name. These are retained operator declarations, not an automatic hardware certification. The full platform and power matrix still needs a separate disposition. The `produce-for` consumer command executes sustained proofs in one process, using fresh fixtures and tokens, and lets an active proof finish after the requested duration.

The exchange runner generates all nine public artifacts, hashes every file and retains the 104 byte encoded header for exact profile provenance. A verifier checks the complete inventory, source revision and all digests before invoking the independent public verifier. Altered or escaping manifest paths fail before cryptographic work.

```sh
python3 crates/houseki-proofs/qualification/interoperability.py produce --binary PRODUCER_BINARY --output /tmp/producer-set
python3 crates/houseki-proofs/qualification/interoperability.py verify --binary VERIFIER_BINARY --input /tmp/producer-set --output /tmp/cross-verification
```

Build the verifier binary without `prover` and preserve it separately before building a producer in the same target directory. The native CI exchange uses Linux x86-64 and macOS ARM64 runners, generates real proofs on both and verifies every producer set on both. Runner architecture is checked explicitly. Hosted execution is interoperability evidence, not physical reference-device or mobile application qualification. Android application artifacts can be verified by the same default consumer using their independently selected workload.

## Exact candidate package

```sh
python3 crates/houseki-proofs/qualification/release.py --self-test
python3 crates/houseki-proofs/qualification/release.py --output /tmp/houseki-candidate --check-advisories
```

Run packaging only from a clean committed checkout. The package contains an exact Git source archive, SHA3-512 source inventory, resolved dependency and declared license inventory, all lockfiles, compiler identity, profile definition hashes and the tracked release policy. It does not require excluded local documents. Optional `--evidence` accepts an operator declaration naming that exact revision with `platforms` and `gates` statuses. Such declarations remain labeled operator evidence. Skipping independent review never becomes a passing independent assessment, even when other declared gates pass. The tool neither publishes nor enables production dispatch.
