#!/usr/bin/env python3
"""Measure frozen native public consumers without discarding failed correctness observations."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics as descriptive
import subprocess
import sys
import tempfile
import time
import unittest


def percentile(values, fraction):
    """Return the contract's nearest-rank quantile of a nonempty observation set."""
    if not values or not 0 < fraction <= 1:
        raise ValueError("expected observations and a quantile in (0, 1]")
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def execute(command, log, deadline):
    """Retain a real child operation's status, output and native process resource counter."""
    with log.open("wb") as stream:
        start = time.monotonic()
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        exceeded = False
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() - start > deadline:
                exceeded = True
                os.killpg(process.pid, signal.SIGKILL)
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(0.02)
    return {
        "exit": process.returncode, "supervision_deadline_exceeded": exceeded,
        "seconds": time.monotonic() - start,
        "kernel_peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
        "memory_counter": "wait4 ru_maxrss whole child process, native platform units converted to bytes",
    }


def qualification_request(cold, warm, soak, exploratory):
    """Prevent small exploratory runs from receiving the contract campaign label."""
    if cold < 1 or warm < 1 or not 0 <= soak <= 1000:
        raise ValueError("expected positive cold and warm counts and 0 through 1000 soak seconds")
    if not exploratory and (cold < 30 or warm < 100 or soak < 900):
        raise ValueError("qualification requires at least 30 cold, 100 warm and 900 soak seconds")


def statistics(samples):
    """Preserve median, nearest-rank p95 and maximum without mixing unrelated phases or platforms."""
    return {field: {"median": descriptive.median(values), "p95": percentile(values, 0.95),
                    "maximum": max(values)}
            for field in ["prove_api_us", "verify_api_us", "decode_us", "fixture_us", "body_encode_us"]
            if (values := [sample[field] for sample in samples if sample[field] is not None])}


def run(args):
    """Freeze one executable and retain every cold, warm and sustained series before assessing it."""
    qualification_request(args.cold, args.warm, args.soak_seconds, args.exploratory)
    if not hasattr(os, "wait4") or (sys.platform, platform.machine()) not in [
            ("darwin", "arm64"), ("linux", "x86_64")]:
        raise ValueError("run natively on Apple Silicon macOS or Linux x86-64")
    conditions = json.loads(args.conditions.read_text()) if args.conditions else None
    if not args.exploratory:
        if conditions is None or not 20 <= conditions.get("ambient_celsius", -1) <= 25:
            raise ValueError("declare measured ambient conditions from 20 through 25 Celsius")
        if conditions.get("power") not in ("external", "battery") or conditions.get("power_saver") is not False:
            raise ValueError("declare the actual power source and disabled power saver")
        if conditions.get("physical") is not True or not conditions.get("reference_device"):
            raise ValueError("declare the actual physical reference device")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    worker = output / "worker"
    shutil.copyfile(args.binary, worker)
    worker.chmod(0o500)
    digest = hashlib.sha3_512(worker.read_bytes()).hexdigest()
    repository = Path(__file__).resolve().parents[3]
    report = {
        "schema": 1, "status": "running", "platform_qualified": False,
        "classification": "exploratory" if args.exploratory else "contract sample campaign",
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repository)),
        "platform": platform.platform(), "machine": platform.machine(),
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "binary_origin": str(args.binary.resolve()), "binary_sha3_512": digest,
        "conditions_declaration": conditions,
        "cold_per_workload": args.cold, "warm_per_workload": args.warm,
        "soak_seconds_per_workload": args.soak_seconds, "series": [],
        "limitations": ["Binary digest binds execution, source-to-binary provenance requires the retained build record.",
                        "A campaign does not establish the complete target, power or hardware qualification matrix.",
                        "CLI measurements do not establish Android application lifecycle qualification."],
    }

    def save():
        """Keep a usable partial report even when a later operation fails."""
        (output / "campaign.json").write_text(json.dumps(report, indent=2) + "\n")

    def series(workload, phase, index, count, timed=False):
        """Require the exact number of successful proof observations before computing any statistics."""
        directory = output / workload / f"{phase}-{index:04}"
        log = directory.with_suffix(".log")
        command = [str(worker), "produce-for" if timed else "produce", workload, str(directory), str(count)]
        result = {"workload": workload, "phase": phase, "index": index, "command": command}
        result.update(execute(command, log, args.safety_deadline))
        report["series"].append(result)
        save()
        if result["exit"] != 0 or result["supervision_deadline_exceeded"]:
            raise RuntimeError(f"{workload} {phase} failed, its output and status are retained")
        samples = [json.loads(line) for line in log.read_text().splitlines()]
        if not samples or (not timed and len(samples) != count):
            raise RuntimeError("missing or extra successful observations")
        for sample in samples:
            if sample["workload"] != workload or sample["prove_api_us"] is None:
                raise RuntimeError("unexpected workload or missing proving measurement")
            if not 0 < sample["proof_bytes"] <= 2097152 or not 0 < sample["body_bytes"] <= 16384:
                raise RuntimeError("structural public byte limit exceeded")
        result["samples"] = len(samples)
        result["statistics"] = statistics(samples)
        result["soft_target_misses"] = []
        prove_limit = 15_000_000 if phase == "cold" else 10_000_000
        verify_limit = 500_000 if phase == "cold" else 250_000
        for metric, limit in [("prove_api_us", prove_limit), ("verify_api_us", verify_limit)]:
            if result["statistics"][metric]["p95"] > limit:
                result["soft_target_misses"].append({"metric": metric, "target": limit})
        if result["kernel_peak_rss_bytes"] > 1024 ** 3:
            result["soft_target_misses"].append({"metric": "preferred_prover_memory", "target": 1024 ** 3})
        if result["kernel_peak_rss_bytes"] > 2 * 1024 ** 3:
            result["soft_target_misses"].append({"metric": "upper_planning_memory", "target": 2 * 1024 ** 3})
        save()

    save()
    try:
        for workload in args.workloads:
            (output / workload).mkdir()
            for index in range(args.cold):
                series(workload, "cold", index, 1)
            series(workload, "warm", 0, args.warm)
            if args.soak_seconds:
                series(workload, "sustained", 0, args.soak_seconds, timed=True)
        if hashlib.sha3_512(worker.read_bytes()).hexdigest() != digest:
            raise RuntimeError("frozen worker changed during the campaign")
        report["status"] = "complete"
    except BaseException as error:
        report["status"] = "failed"
        report["failure"] = str(error)
        raise
    finally:
        save()


class CampaignTests(unittest.TestCase):
    """Statistical contract and real process failure preservation."""

    def test_nearest_rank_contract(self):
        """Thirty cold and one hundred warm observations use ranks 29 and 95 respectively."""
        self.assertEqual(percentile(list(range(1, 31)), 0.95), 29)
        self.assertEqual(percentile(list(range(1, 101)), 0.95), 95)

    def test_real_child_failure_is_retained(self):
        """A child that prints evidence and fails cannot become a successful timing sample."""
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "failure.log"
            result = execute([sys.executable, "-c", "print('failure retained'); raise SystemExit(7)"], log, 10)
            self.assertEqual(result["exit"], 7)
            self.assertIn("failure retained", log.read_text())

    def test_small_campaign_cannot_claim_contract_counts(self):
        """Exploratory counts are permitted only with their explicit nonqualification label."""
        with self.assertRaises(ValueError):
            qualification_request(1, 2, 0, False)
        qualification_request(1, 2, 0, True)
        qualification_request(30, 100, 900, False)

    def test_supervision_timeout_is_a_failed_child(self):
        """A real stalled process is killed under a separate safety ceiling and remains failed."""
        with tempfile.TemporaryDirectory() as directory:
            result = execute([sys.executable, "-c", "import time; time.sleep(10)"], Path(directory) / "stall.log", 0.1)
            self.assertTrue(result["supervision_deadline_exceeded"])
            self.assertNotEqual(result["exit"], 0)

    def test_even_sample_median_uses_both_middle_observations(self):
        """The descriptive median remains distinct from a nearest-rank p95 calculation."""
        samples = [{name: value for name in ["prove_api_us", "verify_api_us", "decode_us",
                                            "fixture_us", "body_encode_us"]}
                   for value in range(1, 31)]
        self.assertEqual(statistics(samples)["prove_api_us"]["median"], 15.5)


def main():
    """Keep contract sample counts as defaults and require explicit exploratory reductions."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--conditions", type=Path)
    parser.add_argument("--cold", type=int, default=30)
    parser.add_argument("--warm", type=int, default=100)
    parser.add_argument("--soak-seconds", type=int, default=900)
    parser.add_argument("--safety-deadline", type=int, default=86400)
    parser.add_argument("--exploratory", action="store_true")
    labels = [f"payment-{inputs}-{outputs}" for inputs in range(1, 5) for outputs in range(1, 3)] + ["withdrawal"]
    parser.add_argument("--workloads", nargs="+", choices=labels, default=labels)
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    elif args.binary is None or args.output is None:
        parser.error("--binary and --output are required for a campaign")
    else:
        run(args)


if __name__ == "__main__":
    main()
