#!/usr/bin/env python3
"""Supervise the stable-toolchain mutation campaigns with wall and process memory ceilings."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import time


def supervise(binary, root, output, seconds, seed):
    """Kill a stalled or oversized worker and preserve its case log for indexed replay."""
    log = output / f"fuzz-{seed}.log"
    started = time.monotonic()
    peak = 0
    last_progress = started
    previous_size = 0
    failure = None
    with log.open("w") as stream:
        process = subprocess.Popen(
            [str(binary), "fuzz", str(seconds), str(seed)], cwd=root,
            stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            while process.poll() is None:
                observed = subprocess.run(
                    ["ps", "-o", "rss=", "-p", str(process.pid)],
                    capture_output=True, text=True, timeout=2, check=False,
                ).stdout.strip()
                if observed:
                    peak = max(peak, int(observed) * 1024)
                size = log.stat().st_size
                now = time.monotonic()
                if size != previous_size:
                    previous_size = size
                    last_progress = now
                if peak > 384 * 1024 * 1024:
                    failure = "worker exceeded 384 MiB process RSS"
                elif now - started > seconds + 60:
                    failure = "worker exceeded campaign wall deadline"
                elif now - last_progress > 15:
                    failure = "worker made no case progress for 15 seconds"
                if failure:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.2)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            status = process.wait(timeout=5)
    text = log.read_text()
    summary = next((line for line in reversed(text.splitlines()) if line.startswith("fuzz iterations=")), None)
    result = {"seed": seed, "seconds": time.monotonic() - started,
              "peak_rss_bytes": peak, "exit": status, "failure": failure,
              "summary": summary}
    if status or not summary:
        result["failure"] = failure or "worker failed before its complete summary"
    return result


def main():
    """Record exact source, corpus and executable identities before running both frozen streams."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    original_binary = args.binary.resolve(strict=True)
    binary = output / "worker"
    shutil.copyfile(original_binary, binary)
    binary.chmod(0o500)
    manifest = root / "crates/houseki-proofs/fixtures/adversarial/manifest.sha3"
    for line in manifest.read_text().splitlines():
        expected, name = line.split("  ", 1)
        actual = hashlib.sha3_512((manifest.parent / name).read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"corpus checksum mismatch for {name}")

    report = {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "platform": platform.platform(), "machine": platform.machine(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "binary_sha3_512": hashlib.sha3_512(binary.read_bytes()).hexdigest(),
        "binary_origin": str(original_binary),
        "binary_snapshot": str(binary),
        "corpus_manifest_sha3_512": hashlib.sha3_512(manifest.read_bytes()).hexdigest(),
        "features": ["experimental-profiles"], "prover": False,
        "seconds_per_stream": 180, "seeds": [24301, 12648430],
        "max_input_bytes": 2097153, "max_live_verifier_bytes": 134217728,
        "max_rss_bytes": 402653184, "case_return_deadline_seconds": 5,
        "stall_deadline_seconds": 15, "streams": [],
    }
    (output / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")
    for seed in report["seeds"]:
        result = supervise(binary, root, output, report["seconds_per_stream"], seed)
        report["streams"].append(result)
        (output / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if result["failure"]:
            raise SystemExit("bounded campaign failed, retain log and replay its last indexed case")


class CampaignTests(unittest.TestCase):
    """Check executable provenance using actual supervised child processes."""

    def test_rebuild_cannot_replace_the_second_stream_worker(self):
        """Both streams must run the recorded executable even if its original path changes."""
        with tempfile.TemporaryDirectory(prefix="houseki-supervisor-test-") as temporary:
            directory = Path(temporary)
            binary = directory / "worker"
            original = "#!/bin/sh\necho original\necho 'fuzz iterations=1'\n"
            binary.write_text(original)
            binary.chmod(0o700)
            output = directory / "results"
            original_supervise = supervise

            def launch(worker, root, destination, seconds, seed):
                """Simulate a rebuild after the first real worker has exited."""
                result = original_supervise(worker, root, destination, seconds, seed)
                binary.write_text(original.replace("original", "replacement"))
                binary.chmod(0o700)
                return result

            arguments = [sys.argv[0], "--binary", str(binary), "--output", str(output)]
            with patch.object(sys, "argv", arguments), patch.object(sys.modules[__name__], "supervise", launch):
                main()
            self.assertIn("original\n", (output / "fuzz-12648430.log").read_text())


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
    else:
        main()
