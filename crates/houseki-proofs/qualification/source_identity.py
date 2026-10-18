#!/usr/bin/env python3
"""Resolve the candidate itself without accidentally attributing an archive to a parent checkout."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


def identity(repository):
    """Return the exact candidate revision and whether tracked source differs from it."""
    repository = repository.resolve()
    archival = repository / ".git_archival.txt"
    if not (repository / ".git").exists():
        record = archival.read_text() if archival.is_file() else ""
        match = re.fullmatch(r"revision=([0-9a-f]{40})\n?", record)
        if match is None:
            raise ValueError("candidate has neither its own Git metadata nor an exported source identity")
        return {"revision": match[1], "dirty": None, "origin": "git-archive"}
    top = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=repository, text=True).strip()).resolve()
    if top != repository:
        raise ValueError("Git resolved a different source directory")
    return {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repository)),
        "origin": "git-checkout",
    }


class SourceIdentityTests(unittest.TestCase):
    """A source archive must retain its own identity even outside its original Git checkout."""

    def test_archive_uses_its_exported_revision(self):
        """The substituted archival record is authoritative when the archive contains no Git data."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git_archival.txt").write_text("revision=" + "a" * 40 + "\n")
            self.assertEqual(identity(root)["revision"], "a" * 40)
            self.assertEqual(identity(root)["origin"], "git-archive")

    def test_missing_identity_is_not_silently_guessed(self):
        """An unidentified directory cannot inherit a nearby checkout's revision."""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                identity(Path(directory))


if __name__ == "__main__":
    unittest.main()
