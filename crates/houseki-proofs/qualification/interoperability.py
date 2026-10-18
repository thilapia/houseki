#!/usr/bin/env python3
"""Generate and cross-verify complete public proof sets with immutable artifact provenance."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from source_identity import identity


def check_files(directory, manifest):
    """Reject missing, altered or escaping manifest entries before invoking the verifier."""
    root = directory.resolve()
    for name, expected in manifest.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("artifact path escapes the public root")
        path = directory / relative
        if not path.resolve().is_relative_to(root):
            raise ValueError("artifact symlink escapes the public root")
        with path.open("rb") as artifact:
            data = artifact.read(2097153)
        if len(data) > 2097152 or hashlib.sha3_512(data).hexdigest() != expected:
            raise ValueError(f"public artifact digest mismatch: {name}")


def workloads():
    """Return all nine immutable launch workload labels in the consumer's fixed order."""
    return [f"payment-{inputs}-{outputs}" for inputs in range(1, 5) for outputs in range(1, 3)] + ["withdrawal"]


def expected_files():
    """Require every public body and proof plus each independent payment anchor."""
    return {f"{workload}/sample-0000/{name}" for workload in workloads()
            for name in (["body.bin", "proof.bin", "anchor-root.bin", "anchor-count.bin"]
                         if workload != "withdrawal" else ["body.bin", "proof.bin"])}


def run(args):
    """Freeze the selected consumer and bind a complete native proof exchange to its source."""
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    worker = output / "worker"
    shutil.copyfile(args.binary, worker)
    worker.chmod(0o500)
    repository = Path(__file__).resolve().parents[3]
    source = identity(repository)
    revision = source["revision"]
    report = {
        "schema": 1, "status": "running", "revision": revision,
        "dirty": source["dirty"], "source_identity": source,
        "platform": platform.platform(), "machine": platform.machine(),
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "binary_sha3_512": hashlib.sha3_512(worker.read_bytes()).hexdigest(), "operations": [],
    }

    def save():
        """Retain failed and incomplete exchange attempts with the successful public data."""
        (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")

    def execute(command, log):
        """Record a full real consumer invocation and reject every nonzero exit."""
        with log.open("wb") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=False)
        report["operations"].append({"command": command, "exit": result.returncode, "log": log.name})
        save()
        if result.returncode:
            raise RuntimeError("public consumer operation failed")

    save()
    try:
        if args.operation == "produce":
            for workload in workloads():
                execute([str(worker), "produce", workload, str(output / workload), "1"], output / f"{workload}.log")
            report["files"] = {name: hashlib.sha3_512((output / name).read_bytes()).hexdigest()
                               for name in sorted(expected_files())}
            report["encoded_header_104_bytes_hex"] = {
                workload: (output / workload / "sample-0000/proof.bin").read_bytes()[:104].hex()
                for workload in workloads()}
            check_files(output, report["files"])
        else:
            roots = [args.input] if (args.input / "manifest.json").is_file() else sorted(
                path for path in args.input.iterdir() if (path / "manifest.json").is_file())
            if not roots:
                raise ValueError("no producer manifests found")
            expected_revision = args.expected_revision or revision
            for producer, root in enumerate(roots):
                manifest = json.loads((root / "manifest.json").read_text())
                if manifest["status"] != "complete" or manifest["revision"] != expected_revision:
                    raise ValueError("incomplete producer or unexpected source revision")
                if set(manifest["files"]) != expected_files():
                    raise ValueError("producer does not contain the complete nine-workload corpus")
                check_files(root, manifest["files"])
                for workload in workloads():
                    execute([str(worker), "verify", workload, str(root / workload / "sample-0000"), "1"],
                            output / f"producer-{producer}-{workload}.log")
        if hashlib.sha3_512(worker.read_bytes()).hexdigest() != report["binary_sha3_512"]:
            raise ValueError("frozen consumer changed")
        report["status"] = "complete"
    except BaseException as error:
        report["status"] = "failed"
        report["failure"] = str(error)
        raise
    finally:
        save()


class InteroperabilityTests(unittest.TestCase):
    """Public proof exchange must reject altered bytes and path traversal before cryptographic work."""

    def test_changed_artifact_cannot_use_original_manifest(self):
        """An altered artifact fails provenance even if all paths and source labels look correct."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "proof.bin").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                check_files(root, {"proof.bin": hashlib.sha3_512(b"original").hexdigest()})

    def test_manifest_cannot_escape_artifact_root(self):
        """Public manifests cannot cause the harness to read a file outside their own directory."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                check_files(Path(directory), {"../outside": "0" * 128})


def main():
    """Choose generation or cross-verification without accepting incomplete workload inventories."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("operation", nargs="?", choices=["produce", "verify"])
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--expected-revision")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    elif args.operation is None or args.binary is None or args.output is None:
        parser.error("operation, --binary and --output are required")
    elif args.operation == "verify" and args.input is None:
        parser.error("--input is required for cross-verification")
    else:
        run(args)


if __name__ == "__main__":
    main()
