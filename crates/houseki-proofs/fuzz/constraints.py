#!/usr/bin/env python3
"""Check constraint sensitivity in an isolated snapshot of the committed revision."""

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time


def run_test(root, target, test, log):
    """Run one release regression and retain its complete diagnostic output."""
    command = [
        "cargo", "test", "-p", "houseki-proofs", "--lib", "--release",
        "--all-features", "--locked", test, "--", "--test-threads=1",
    ]
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
    with log.open("w") as output:
        result = subprocess.run(
            command, cwd=root, env=environment, stdout=output,
            stderr=subprocess.STDOUT, timeout=600, check=False,
        )
    text = log.read_text()
    if "running 1 test\n" not in text:
        raise RuntimeError(f"expected exactly one compiled regression, see {log}")
    return result.returncode, text


def main():
    """Require a green original and a failed regression for every selected weakening."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--only", help="one mutation identifier")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    mutations = json.loads(Path(__file__).with_name("constraints.json").read_text())
    if args.only:
        mutations = [item for item in mutations if item["id"] == args.only]
        if not mutations:
            parser.error("unknown mutation identifier")

    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    archive = subprocess.check_output(["git", "archive", revision], cwd=root)
    report = {"revision": revision, "rustc": subprocess.check_output(
        ["rustc", "--version"], text=True).strip(), "results": []}
    with tempfile.TemporaryDirectory(prefix="houseki-constraints-") as temporary:
        snapshot = Path(temporary) / "source"
        snapshot.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as files:
            files.extractall(snapshot, filter="data")
        target = Path(temporary) / "target"
        for mutation in mutations:
            source = snapshot / mutation["path"]
            original = source.read_text()
            if original.count(mutation["before"]) != 1:
                raise RuntimeError(f"mutation {mutation['id']} no longer matches exactly once")
            baseline, _ = run_test(snapshot, target, mutation["test"], output / f"{mutation['id']}-green.log")
            if baseline:
                raise RuntimeError(f"original regression failed for {mutation['id']}")

            started = time.monotonic()
            try:
                source.write_text(original.replace(mutation["before"], mutation["after"]))
                status, text = run_test(snapshot, target, mutation["test"], output / f"{mutation['id']}-red.log")
                killed = status == 101 and "test result: FAILED." in text and f"{mutation['test']} ... FAILED" in text
                report["results"].append({"id": mutation["id"], "test": mutation["test"],
                                          "killed": killed, "seconds": time.monotonic() - started})
                (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
                print(f"{mutation['id']}: {'killed' if killed else 'SURVIVED'}", flush=True)
            finally:
                source.write_text(original)

    if not all(item["killed"] for item in report["results"]):
        raise SystemExit("constraint sensitivity campaign failed")


if __name__ == "__main__":
    main()
