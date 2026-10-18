#!/usr/bin/env python3
"""Exercise the real NativeActivity and retain public artifacts and lifecycle evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import time


def run(args):
    """Install the synthetic debug application and require actual worker completion or cancellation."""
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
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
            raise RuntimeError(f"device command failed with code {result.returncode}")
        return result.stdout if binary else result.stdout.decode("utf-8", errors="replace")

    environment = {
        "classification": "exploratory application execution, not device qualification",
        "serial": args.serial, "workload": args.workload,
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
    deadline = time.monotonic() + args.safety_deadline
    startup_deadline = time.monotonic() + 30

    def observe():
        """Read actual process events and retain kernel high-water memory while the app is alive."""
        nonlocal maximum_rss, maximum_hwm, latest, observed_pid
        text = adb("shell", "run-as", package, "cat", "files/events.jsonl", check=False)
        latest = [json.loads(line) for line in text.splitlines()[original_lines:] if line.startswith("{")]
        (output / "events.json").write_text(json.dumps(latest, indent=2) + "\n")
        pid = adb("shell", "pidof", package, check=False).strip()
        if pid.isdecimal():
            observed_pid = pid
            status = adb("shell", "run-as", package, "cat", f"/proc/{pid}/status", check=False)
            with (output / "memory.log").open("a") as log:
                log.write(status + "\n")
            for field, value in re.findall(r"^(VmRSS|VmHWM):\s+(\d+) kB", status, flags=re.MULTILINE):
                if field == "VmHWM":
                    maximum_hwm = max(maximum_hwm, int(value) * 1024)
                else:
                    maximum_rss = max(maximum_rss, int(value) * 1024)
        elif observed_pid is not None:
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
            time.sleep(0.2)

    result = {"passed": False}
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
            wait_for("complete", first["attempt"])
        else:
            wait_for("complete")
        result["passed"] = True
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        result["sampled_peak_rss_bytes"] = maximum_rss
        result["kernel_peak_rss_bytes"] = maximum_hwm
        result["memory_counter"] = "Android /proc/PID/status VmHWM, with VmRSS samples"
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        environment["battery_after"] = adb("shell", "dumpsys", "battery", check=False)
        environment["thermal_after"] = adb("shell", "dumpsys", "thermalservice", check=False)
        (output / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
        archive = output / "public.tar"
        archive.write_bytes(adb("exec-out", "run-as", package, "tar", "-cf", "-", "files", binary=True, check=False))
        if archive.stat().st_size:
            with tarfile.open(archive) as public:
                public.extractall(output / "public", filter="data")
        adb("shell", "am", "force-stop", package, check=False)


def main():
    """Require an explicitly selected phone and new evidence directory."""
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
    parser.add_argument("--safety-deadline", type=int, default=1800,
                        help="separate supervision ceiling, never the soft proving latency target")
    run(parser.parse_args())


if __name__ == "__main__":
    main()
