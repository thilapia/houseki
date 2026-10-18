#!/usr/bin/env python3
"""Build the qualification NativeActivity with the configured SDK, NDK and public debug signing."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
from source_identity import identity


def newest(directory):
    """Select an installed numeric tool version without relying on a project-local SDK."""
    versions = [path for path in directory.iterdir() if path.is_dir() and all(
        part.isdecimal() for part in path.name.split("."))]
    if not versions:
        raise ValueError(f"no installed tool version under {directory}")
    return max(versions, key=lambda path: tuple(map(int, path.name.split("."))))


def build(output):
    """Create a reproducible native app and retain exact command, environment and binary records."""
    sdk_value = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk_value:
        raise ValueError("set ANDROID_HOME or ANDROID_SDK_ROOT")
    sdk = Path(sdk_value).resolve()
    ndk_value = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    ndk = Path(ndk_value).resolve() if ndk_value else newest(sdk / "ndk")
    build_tools = newest(sdk / "build-tools")
    host = "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64"
    compiler = ndk / "toolchains/llvm/prebuilt" / host / "bin/aarch64-linux-android34-clang"
    android_jar = sdk / "platforms/android-34/android.jar"
    for path in [compiler, android_jar, build_tools / "aapt2", build_tools / "apksigner", build_tools / "zipalign"]:
        if not path.is_file():
            raise ValueError(f"required tool missing: {path}")
    if not shutil.which("keytool"):
        raise ValueError("the configured JDK must expose keytool")
    output.mkdir(parents=True, exist_ok=False)
    package = Path(__file__).resolve().parent
    repository = package.parents[2]
    environment = dict(os.environ)
    environment["CARGO_TARGET_DIR"] = os.environ.get("CARGO_TARGET_DIR", str(output / "target"))
    environment["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"] = str(compiler)
    commands = []

    def run(arguments):
        """Fail on every tool error while retaining its full output beside the exact argv."""
        commands.append([str(value) for value in arguments])
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        with (output / "build.log").open("ab") as log:
            subprocess.run(commands[-1], cwd=repository, env=environment, stdout=log,
                           stderr=subprocess.STDOUT, check=True)

    metadata = {
        "source_identity": identity(repository),
        "revision": identity(repository)["revision"],
        "dirty": identity(repository)["dirty"],
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "sdk": str(sdk), "ndk": str(ndk), "build_tools": str(build_tools),
        "ndk_properties": (ndk / "source.properties").read_text(),
        "cargo_target_dir": environment["CARGO_TARGET_DIR"],
        "native_packaging": "compressed with extractNativeLibs=true and 16 KiB ELF alignment",
        "api": 34, "features": ["mobile", "prover", "experimental-profiles"],
        "purpose": "debug qualification harness with synthetic state, not a wallet distribution",
    }
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    run(["cargo", "build", "--manifest-path", package / "Cargo.toml", "--lib", "--release",
         "--features", "mobile", "--target", "aarch64-linux-android", "--locked"])
    library = Path(environment["CARGO_TARGET_DIR"]) / "aarch64-linux-android/release/libhouseki_proofs_qualification.a"
    shared = output / "libhouseki_qualification.so"
    run([compiler, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
         "-Wl,-z,max-page-size=16384", package / "android/native.c", library,
         "-landroid", "-llog", "-ldl", "-lm", "-o", shared])
    unsigned = output / "unsigned.apk"
    run([build_tools / "aapt2", "link", "-o", unsigned, "-I", android_jar,
         "--manifest", package / "android/AndroidManifest.xml", "--min-sdk-version", "34",
         "--target-sdk-version", "34"])
    with zipfile.ZipFile(unsigned, "a") as archive:
        archive.write(shared, "lib/arm64-v8a/libhouseki_qualification.so", compress_type=zipfile.ZIP_DEFLATED)
    aligned = output / "aligned.apk"
    run([build_tools / "zipalign", "-f", "4", unsigned, aligned])
    keystore = output / "qualification-debug.p12"
    run(["keytool", "-genkeypair", "-keystore", keystore, "-storepass", "android", "-keypass",
         "android", "-alias", "qualification", "-keyalg", "RSA", "-keysize", "2048",
         "-validity", "30", "-dname", "CN=Houseki Qualification"])
    apk = output / "qualification.apk"
    run([build_tools / "apksigner", "sign", "--ks", keystore, "--ks-pass", "pass:android",
         "--key-pass", "pass:android", "--out", apk, aligned])
    run([build_tools / "apksigner", "verify", "--verbose", apk])
    metadata["sha3_512"] = {path.name: hashlib.sha3_512(path.read_bytes()).hexdigest()
                            for path in [shared, apk]}
    (output / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(apk)


def main():
    """Require an explicit new output directory before building any artifacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    build(args.output)


if __name__ == "__main__":
    main()
