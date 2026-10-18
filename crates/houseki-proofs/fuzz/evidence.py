#!/usr/bin/env python3
"""Compile external consumers and require the intended privacy and lifetime diagnostics."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


CASES = [
    ("forge-payment", "E0451", '''
use houseki_proofs::{ProofContext, VerifiedPayment};
use houseki_types::{NoteTreeAnchor, PaymentBody};
fn forge<'a>(body: &'a PaymentBody, anchor: &'a NoteTreeAnchor, context: &'a ProofContext) -> VerifiedPayment<'a> {
    VerifiedPayment { body, anchor, context }
}
'''),
    ("forge-withdrawal", "E0451", '''
use houseki_proofs::{ProofContext, VerifiedRewardWithdrawal};
use houseki_types::RewardWithdrawalBody;
fn forge<'a>(body: &'a RewardWithdrawalBody, context: &'a ProofContext) -> VerifiedRewardWithdrawal<'a> {
    VerifiedRewardWithdrawal { body, context }
}
'''),
    ("rebind-body", "E0616", '''
use houseki_proofs::VerifiedPayment;
use houseki_types::PaymentBody;
fn rebind<'a>(evidence: &mut VerifiedPayment<'a>, body: &'a PaymentBody) {
    evidence.body = body;
}
'''),
    ("rebind-context", "E0616", '''
use houseki_proofs::{ProofContext, VerifiedRewardWithdrawal};
fn rebind<'a>(evidence: &mut VerifiedRewardWithdrawal<'a>, context: &'a ProofContext) {
    evidence.context = context;
}
'''),
    ("escape-anchor", "E0515", '''
use houseki_proofs::{ProofContext, ProofRuntime, VerifiedPayment, verify_payment};
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};
fn escape<'a>(body: &'a PaymentBody, anchor: NoteTreeAnchor, proof: &EncodedTransactionProof, context: &'a ProofContext) -> VerifiedPayment<'a> {
    verify_payment(&ProofRuntime::new(), body, &anchor, proof, context).unwrap()
}
'''),
    ("mutate-verified-body", "E0506", '''
use houseki_proofs::{ProofContext, ProofRuntime, VerifiedPayment, verify_payment};
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};
fn mutate<'a>(body: &'a mut PaymentBody, replacement: PaymentBody, anchor: &'a NoteTreeAnchor, proof: &EncodedTransactionProof, context: &'a ProofContext) -> VerifiedPayment<'a> {
    let evidence = verify_payment(&ProofRuntime::new(), body, anchor, proof, context).unwrap();
    *body = replacement;
    evidence
}
'''),
    ("cross-family-evidence", "E0308", '''
use houseki_proofs::{VerifiedPayment, VerifiedRewardWithdrawal};
fn substitute(evidence: VerifiedPayment<'_>) -> VerifiedRewardWithdrawal<'_> {
    evidence
}
'''),
]
"""Independent external construction, rebinding, lifetime and family substitution cases."""


def check(project, source, output):
    """Compile one actual external source and retain machine-readable compiler messages."""
    (project / "src/main.rs").write_text(source + "\nfn main() {}\n")
    result = subprocess.run(
        ["cargo", "check", "--offline", "--locked", "--message-format=json"],
        cwd=project, capture_output=True, text=True, timeout=180, check=False,
    )
    output.write_text(result.stdout + result.stderr)
    codes = set()
    for line in result.stdout.splitlines():
        item = json.loads(line)
        if item.get("reason") == "compiler-message":
            message = item["message"]
            if message["level"] == "error" and message.get("code"):
                codes.add(message["code"]["code"])
    return result.returncode, codes


def main():
    """Require a successful control before compiling every expected failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[3]
    with tempfile.TemporaryDirectory(prefix="houseki-consumers-") as temporary:
        project = Path(temporary)
        (project / "src").mkdir()
        (project / "src/main.rs").write_text("fn main() {}\n")
        manifest = '''[package]
name = "external-evidence-probe"
version = "0.0.0"
edition = "2024"
[workspace]
[dependencies]
houseki-proofs = { path = PATH_PROOFS, features = ["experimental-profiles"] }
houseki-types = { path = PATH_TYPES }
[patch.crates-io]
'''.replace("PATH_PROOFS", json.dumps(str(root / "crates/houseki-proofs"))).replace("PATH_TYPES", json.dumps(str(root / "crates/houseki-types")))
        for name in ["air", "util", "dft", "fri", "uni-stark"]:
            manifest += f'p3-{name} = {{ path = {json.dumps(str(root / "vendor/plonky3" / name))} }}\n'
        (project / "Cargo.toml").write_text(manifest)
        locked = subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=project, capture_output=True, text=True, check=False)
        (output / "lockfile.log").write_text(locked.stdout + locked.stderr)
        if locked.returncode:
            raise RuntimeError(locked.stderr)
        control = '''
use houseki_proofs::{ProofContext, ProofRuntime, VerifiedPayment, verify_payment};
use houseki_types::{EncodedTransactionProof, NoteTreeAnchor, PaymentBody};
fn verify<'a>(body: &'a PaymentBody, anchor: &'a NoteTreeAnchor, proof: &EncodedTransactionProof, context: &'a ProofContext) -> VerifiedPayment<'a> {
    verify_payment(&ProofRuntime::new(), body, anchor, proof, context).unwrap()
}
'''
        status, codes = check(project, control, output / "control.jsonl")
        if status or codes:
            raise RuntimeError("external control did not compile")
        results = []
        for name, expected, source in CASES:
            status, codes = check(project, source, output / f"{name}.jsonl")
            if status != 101 or codes != {expected}:
                raise RuntimeError(f"{name}: expected only {expected}, got exit {status} with {codes}")
            results.append({"case": name, "code": expected})
            print(f"{name}: rejected with {expected}", flush=True)

        status, codes = check(project, "use houseki_proofs::prove_payment;", output / "verifier-only.jsonl")
        if status != 101 or codes != {"E0432"}:
            raise RuntimeError("verifier-only consumer exposed proving capability")
        results.append({"case": "verifier-only", "code": "E0432"})
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
