#!/usr/bin/env python3
"""Exercise the real NativeActivity and retain public artifacts and lifecycle evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import unittest


def retain_process(expected, observed):
    """Reject an unplanned process replacement instead of accepting a silently retried proof."""
    if not observed.isdecimal() or (expected is not None and observed != expected):
        raise RuntimeError("application process changed during the correctness run")
    return observed


class ObservationTests(unittest.TestCase):
    """Transport recovery cannot erase a process failure or substitute another worker."""

    def test_recovery_requires_the_original_process(self):
        """A live replacement process fails the run even when its public output looks valid."""
        self.assertEqual(retain_process(None, "123"), "123")
        self.assertEqual(retain_process("123", "123"), "123")
        with self.assertRaises(RuntimeError):
            retain_process("123", "456")


def run(args):
    """Install the synthetic debug application and require actual worker completion or cancellation."""
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_bytes = Path(__file__).read_bytes()
    (output / "android-runner.py").write_bytes(source_bytes)
    package = "org.houseki.proofs.qualification"
    component = package + "/android.app.NativeActivity"
    commands = []

    def adb(*arguments, check=True, binary=False):
        """Retain every explicit device command and fail on unexpected device errors."""
        command = [str(args.adb), "-s", args.serial, *map(str, arguments)]
        commands.append(command)
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        result = subprocess.run(command, capture_output=True, check=False)
        with (output / "device.log").open("ab") as log:
            log.write(result.stdout if not binary else b"public binary transfer\n")
            log.write(result.stderr)
        if check and result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()[:500]
            raise RuntimeError(f"device {arguments[0]} command failed with code {result.returncode}: {detail}")
        return result.stdout if binary else result.stdout.decode("utf-8", errors="replace")

    environment = {
        "classification": "exploratory application execution, not device qualification",
        "serial": args.serial, "workload": args.workload,
        "warm_requested": args.warm, "sustained_seconds_requested": args.soak_seconds,
        "driver_sha3_512": hashlib.sha3_512(source_bytes).hexdigest(),
        "apk_sha3_512": hashlib.sha3_512(args.apk.read_bytes()).hexdigest(),
        "device": adb("shell", "getprop"),
        "battery_before": adb("shell", "dumpsys", "battery"),
        "thermal_before": adb("shell", "dumpsys", "thermalservice"),
        "page_size": adb("shell", "getconf", "PAGE_SIZE").strip(),
    }
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    if not args.skip_install:
        adb("install", "--no-incremental", "-r", "-t", args.apk)
    installed = adb("shell", "pm", "path", package).strip()
    if not installed.startswith("package:") or "\n" in installed:
        raise RuntimeError("expected one installed qualification APK")
    installed_bytes = adb("exec-out", "cat", installed.removeprefix("package:"), binary=True)
    installed_digest = hashlib.sha3_512(installed_bytes).hexdigest()
    if installed_digest != environment["apk_sha3_512"]:
        raise RuntimeError("installed APK differs from the explicitly selected binary")
    environment["installed_apk_sha3_512"] = installed_digest
    (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    adb("shell", "am", "force-stop", package)
    adb("shell", "run-as", package, "mkdir", "-p", "files")
    # Only fixed public workload labels reach the device shell.
    adb("shell", "run-as", package, "sh", "-c", f"'printf \"{args.workload}\\n\" > files/request.txt'")
    original = adb("shell", "run-as", package, "cat", "files/events.jsonl", check=False)
    original_lines = len(original.splitlines()) if original.lstrip().startswith("{") else 0
    maximum_rss = 0
    maximum_hwm = 0
    latest = []
    observed_pid = None
    transport_gaps = []
    deadline = time.monotonic() + args.safety_deadline
    startup_deadline = time.monotonic() + 30

    def connected():
        """Recover only the transport without restarting, replacing or discarding a proof attempt."""
        started = time.monotonic()
        if adb("get-state", check=False).strip() == "device":
            return
        gap = {"host_monotonic_start": started, "recovered": False}
        transport_gaps.append(gap)
        (output / "transport-gaps.json").write_text(json.dumps(transport_gaps, indent=2) + "\n")
        while time.monotonic() - started < args.reconnect_seconds:
            time.sleep(0.5)
            if adb("get-state", check=False).strip() == "device":
                gap["recovered"] = True
                gap["seconds"] = time.monotonic() - started
                (output / "transport-gaps.json").write_text(json.dumps(transport_gaps, indent=2) + "\n")
                return
        raise RuntimeError("device transport did not recover within its observation grace period")

    def observe():
        """Read actual process events and retain kernel high-water memory while the app is alive."""
        nonlocal maximum_rss, maximum_hwm, latest, observed_pid
        connected()
        text = adb("shell", "run-as", package, "cat", "files/events.jsonl", check=False)
        latest = [json.loads(line) for line in text.splitlines()[original_lines:] if line.startswith("{")]
        (output / "events.json").write_text(json.dumps(latest, indent=2) + "\n")
        pid = adb("shell", "pidof", package, check=False).strip()
        if not pid.isdecimal() and observed_pid is not None:
            connected()
            pid = adb("shell", "pidof", package, check=False).strip()
        if pid.isdecimal():
            observed_pid = retain_process(observed_pid, pid)
            status = adb("shell", "run-as", package, "cat", f"/proc/{pid}/status", check=False)
            if not re.search(r"^VmHWM:", status, flags=re.MULTILINE):
                connected()
                status = adb("shell", "run-as", package, "cat", f"/proc/{pid}/status")
            if not re.search(r"^VmHWM:", status, flags=re.MULTILINE):
                raise RuntimeError("kernel process memory high-water counter unavailable")
            with (output / "memory.log").open("a") as log:
                log.write(status + "\n")
            for field, value in re.findall(r"^(VmRSS|VmHWM):\s+(\d+) kB", status, flags=re.MULTILINE):
                if field == "VmHWM":
                    maximum_hwm = max(maximum_hwm, int(value) * 1024)
                else:
                    maximum_rss = max(maximum_rss, int(value) * 1024)
        elif observed_pid is not None:
            connected()
            raise RuntimeError("application process exited during the correctness run")
        if not latest and time.monotonic() > startup_deadline:
            raise TimeoutError("application did not start a worker within 30 seconds")
        if any(event["event"] in ("failed", "panic") for event in latest):
            raise RuntimeError("real application worker failed")
        if time.monotonic() > deadline:
            raise TimeoutError("application safety deadline exceeded, correctness run failed")
        return latest

    def wait_for(event_name, after=0):
        """Wait for an actual callback or worker event rather than guessing a proving duration."""
        while True:
            events = observe()
            match = next((event for event in events if event["event"] == event_name
                          and event["attempt"] > after), None)
            if match:
                return match
            time.sleep(0.5)

    result = {"passed": False, "warm_completed": 0, "sustained_completed": 0}
    try:
        adb("shell", "am", "start", "-n", component)
        first = wait_for("started")
        if args.cancel:
            time.sleep(0.25)
            adb("shell", "input", "keyevent", "KEYCODE_HOME")
            cancelled = wait_for("cancelled")
            request = next(event for event in latest if event["event"] == "cancel_requested")
            cleanup_us = cancelled["elapsed_us"] - request["elapsed_us"]
            if not 0 <= cleanup_us <= 1_000_000:
                raise RuntimeError("scheduled cancellation cleanup exceeded one second")
            result["cancellation_cleanup_us"] = cleanup_us
            adb("shell", "am", "start", "-n", component)
            restarted = wait_for("started", first["attempt"])
            if restarted["pid"] != first["pid"]:
                raise RuntimeError("resumption unexpectedly restarted the process")
            result["resumed_attempt"] = restarted["attempt"]
            completed = wait_for("complete", first["attempt"])
        else:
            completed = wait_for("complete")

        def next_attempt(previous):
            """Reenter foreground with fresh admission while keeping the initialized process alive."""
            adb("shell", "input", "keyevent", "KEYCODE_HOME")
            adb("shell", "am", "start", "-n", component)
            started = wait_for("started", previous["attempt"])
            if started["pid"] != first["pid"]:
                raise RuntimeError("warm series lost its original application process")
            return wait_for("complete", previous["attempt"])

        for _ in range(args.warm):
            completed = next_attempt(completed)
            result["warm_completed"] += 1
        sustained_start = time.monotonic()
        while time.monotonic() - sustained_start < args.soak_seconds:
            completed = next_attempt(completed)
            result["sustained_completed"] += 1
        result["passed"] = True
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        result["sampled_peak_rss_bytes"] = maximum_rss
        result["kernel_peak_rss_bytes"] = maximum_hwm
        result["memory_counter"] = "Android /proc/PID/status VmHWM, with VmRSS samples"
        try:
            connected()
            environment["battery_after"] = adb("shell", "dumpsys", "battery", check=False)
            environment["thermal_after"] = adb("shell", "dumpsys", "thermalservice", check=False)
            (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
            archive = output / "public.tar"
            archive.write_bytes(adb("exec-out", "run-as", package, "tar", "-cf", "-", "files", binary=True))
            with tarfile.open(archive) as public:
                public.extractall(output / "public", filter="data")
        except Exception as error:
            result["passed"] = False
            result["evidence_error"] = str(error)
            if "error" not in result:
                raise
        finally:
            adb("shell", "am", "force-stop", package, check=False)
            result["transport_gaps"] = transport_gaps
            result["uninterrupted_observation"] = not transport_gaps
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")


def main():
    """Require an explicitly selected phone and new evidence directory."""
    if "--self-test" in sys.argv:
        unittest.main(argv=[sys.argv[0]])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    labels = [f"payment-{inputs}-{outputs}" for inputs in range(1, 5) for outputs in range(1, 3)]
    parser.add_argument("--workload", choices=labels + ["withdrawal"], default="withdrawal")
    parser.add_argument("--cancel", action="store_true")
    parser.add_argument("--skip-install", action="store_true",
                        help="verify the installed APK hash and reuse it without another install prompt")
    parser.add_argument("--warm", type=int, default=0,
                        help="additional fresh attempts in the same process after its initial proof")
    parser.add_argument("--soak-seconds", type=int, default=0,
                        help="sustained same-process fresh attempts after the warm series")
    parser.add_argument("--reconnect-seconds", type=int, default=15,
                        help="bounded transport recovery without retrying the running proof")
    parser.add_argument("--safety-deadline", type=int, default=86400,
                        help="separate supervision ceiling, never the soft proving latency target")
    args = parser.parse_args()
    if not 0 <= args.warm <= 1000 or not 0 <= args.soak_seconds <= 1000:
        parser.error("warm iterations and sustained seconds must be between zero and 1000")
    if not 0 <= args.reconnect_seconds <= 30:
        parser.error("transport recovery must be between zero and 30 seconds")
    run(args)


if __name__ == "__main__":
    main()
