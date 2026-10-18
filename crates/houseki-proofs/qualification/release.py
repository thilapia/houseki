#!/usr/bin/env python3
"""Prepare an exact unreviewed candidate package without publication or profile activation."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
import urllib.error
import urllib.request

# First-release targets selected explicitly by the owner on 2026-10-18.
REQUIRED_TARGETS = ("macos-arm64", "linux-x86_64", "android-arm64")

# Separate evidence obligations that cannot be inferred from a successful package build.
REQUIRED_GATES = ("security_composition", "profile_freeze", "license", "clean_reproduction",
                  "final_tests", "operating_limits", "interoperability", "device_qualification", "advisories")


def readiness(review, evidence, gates=None):
    """Keep independent review and each required platform gate distinct from owner decisions."""
    return (review == "passed" and set(evidence) == set(REQUIRED_TARGETS)
            and all(value == "passed" for value in evidence.values())
            and gates is not None and set(gates) == set(REQUIRED_GATES)
            and all(value == "passed" for value in gates.values()))


def digest(path):
    """Hash complete retained files without allocating their full contents at once."""
    checksum = hashlib.sha3_512()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest()


def dependencies(repository, manifest):
    """Retain resolved package versions and declared licensing without leaking local source paths."""
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--manifest-path", str(manifest), "--format-version", "1",
        "--all-features", "--locked"], cwd=repository, text=True))
    return [{"name": package["name"], "version": package["version"],
             "license": package["license"], "license_file_declared": package["license_file"] is not None,
             "source": package["source"] or "workspace or retained vendor patch",
             "repository": package["repository"]}
            for package in sorted(metadata["packages"], key=lambda value: (value["name"], value["version"]))]


def advisories(packages):
    """Query OSV for exact registry versions while preserving unavailable and untriaged outcomes."""
    registry = [package for package in packages if package["source"].startswith("registry+")]
    queries = [{"package": {"ecosystem": "crates.io", "name": package["name"]},
                "version": package["version"]} for package in registry]
    request = urllib.request.Request("https://api.osv.dev/v1/querybatch",
                                     data=json.dumps({"queries": queries}).encode(),
                                     headers={"Content-Type": "application/json"})
    report = {"service": "https://api.osv.dev/v1/querybatch",
              "checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "exact registry versions, local vendor patch behavior requires separate assessment"}
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError("advisory response exceeds its evidence bound")
        results = json.loads(data)["results"]
        if len(results) != len(registry):
            raise ValueError("advisory response omitted a queried package")
        report["status"] = "queried"
        report["packages"] = [{"name": package["name"], "version": package["version"], "result": result}
                              for package, result in zip(registry, results, strict=True)]
        report["response_sha3_512"] = hashlib.sha3_512(data).hexdigest()
        report["untriaged_advisories"] = sum(len(result.get("vulns", [])) for result in results)
    except (OSError, ValueError, KeyError) as error:
        report["status"] = "unavailable"
        report["error"] = str(error)
    return report


def package(args):
    """Archive committed source and exact metadata while leaving every unfulfilled gate visible."""
    root = Path(__file__).resolve().parents[3]
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root):
        raise ValueError("commit or preserve working changes before packaging the exact candidate")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    policy = json.loads((root / "crates/houseki-proofs/release-policy.json").read_text())
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    source = output / "source.tar"
    subprocess.run(["git", "archive", "--format=tar", "--output", str(source), revision], cwd=root, check=True)
    files = {}
    with tarfile.open(source) as archive:
        for item in archive:
            if item.isfile():
                stream = archive.extractfile(item)
                checksum = hashlib.sha3_512()
                while chunk := stream.read(1024 * 1024):
                    checksum.update(chunk)
                files[item.name] = checksum.hexdigest()
            elif item.issym():
                files[item.name] = {"symlink": item.linkname}
    (output / "source-sha3-512.json").write_text(json.dumps(files, indent=2, sort_keys=True) + "\n")
    packages = dependencies(root, root / "Cargo.toml")
    consumers = dependencies(root, root / "crates/houseki-proofs/qualification/Cargo.toml")
    (output / "dependencies.json").write_text(json.dumps({"workspace": packages, "qualification": consumers}, indent=2) + "\n")
    declaration = json.loads(args.evidence.read_text()) if args.evidence else {}
    if declaration and declaration.get("revision") != revision:
        raise ValueError("evidence declaration must identify this exact release candidate")
    platforms = declaration.get("platforms", {name: "pending" for name in REQUIRED_TARGETS})
    gates = declaration.get("gates", {name: "pending" for name in REQUIRED_GATES})
    report = {
        "schema": 1, "revision": revision, "source_archive_sha3_512": digest(source),
        "rustc": subprocess.check_output(["rustc", "-Vv"], text=True),
        "cargo": subprocess.check_output(["cargo", "-V"], text=True).strip(),
        "release_policy": policy, "operator_evidence_declaration": declaration,
        "platform_evidence": platforms, "gates": gates,
        "independent_review": policy["independent_review"],
        "production_qualified": readiness(policy["independent_review"]["status"], platforms, gates),
        "published": False, "network_profile_activated": False,
        "source_manifest_sha3_512": digest(output / "source-sha3-512.json"),
        "dependency_manifest_sha3_512": digest(output / "dependencies.json"),
        "lockfiles": {name: files[name] for name in files if name.endswith("Cargo.lock")},
        "profile_definitions": {name: checksum for name, checksum in files.items()
                                if name.startswith("crates/houseki-proofs/src/profile/")},
        "unspecified_workspace_licenses": sorted({item["name"] for item in packages
                                                  if item["name"].startswith("houseki-") and item["license"] is None}),
    }
    if args.check_advisories:
        report["advisory_inventory"] = advisories(packages)
    else:
        report["advisory_inventory"] = {"status": "not_queried"}
    (output / "candidate.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"revision": revision, "production_qualified": report["production_qualified"],
                      "source_archive_sha3_512": report["source_archive_sha3_512"]}))


class ReleaseTests(unittest.TestCase):
    """Skipped review and incomplete device evidence must not become a production readiness claim."""

    def test_skipping_review_is_not_a_passing_independent_assessment(self):
        """Even complete platform evidence cannot manufacture an independent review verdict."""
        platforms = {name: "passed" for name in ["macos-arm64", "linux-x86_64", "android-arm64"]}
        self.assertFalse(readiness("skipped_by_owner", platforms))

    def test_missing_platform_is_not_hidden_by_other_passing_targets(self):
        """A missing Android or native Linux result blocks the aggregate qualification claim."""
        self.assertFalse(readiness("passed", {"macos-arm64": "passed"}))

    def test_each_gate_matters_after_the_positive_control(self):
        """A complete control passes, while removing any required gate or review verdict fails."""
        platforms = {name: "passed" for name in REQUIRED_TARGETS}
        gates = {name: "passed" for name in REQUIRED_GATES}
        self.assertTrue(readiness("passed", platforms, gates))
        self.assertFalse(readiness("skipped_by_owner", platforms, gates))
        for name in REQUIRED_GATES:
            changed = dict(gates)
            changed[name] = "pending"
            self.assertFalse(readiness("passed", platforms, changed))


def main():
    """Prepare a local source package only, with optional exact-version advisory lookup."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--check-advisories", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]])
    elif args.output is None:
        parser.error("--output is required")
    else:
        package(args)


if __name__ == "__main__":
    main()
