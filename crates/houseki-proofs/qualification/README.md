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

Accept the synthetic debug application installation on the phone when required. Add `--skip-install` for later workloads using the same APK. The runner verifies the installed APK's SHA3-512 digest, records actual callback events and kernel `VmHWM`, transfers only public files and stops the app after evidence retrieval. A lifecycle run requires cancellation cleanup within one second while scheduled and a later successful fresh attempt in the same process. Its separate 1800 second supervision ceiling is not a proving performance target. Process exit, panic, invalid proof or deadline failure fails the run rather than dropping an observation.

The APK uses compressed shared libraries with extraction enabled and 16 KiB ELF segment alignment. This follows Android's [documented extraction alternative](https://developer.android.com/guide/practices/page-sizes) and works with installed build tools that predate `zipalign -P`. It does not establish a physical 16 KiB device pass. The APK is debuggable solely for controlled synthetic measurement and public evidence retrieval. Do not distribute it as a wallet or place real secrets in it.

Application runs are explicitly exploratory until the contract's reference hardware, sample counts, power, battery, ambient and thermal conditions are satisfied. CLI execution and application execution remain separate evidence categories. iOS and Windows are deferred from the first-release matrix by the owner's decision.
