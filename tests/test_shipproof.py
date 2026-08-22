"""Behavioral and adversarial tests for Agent ShipProof."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "plugins" / "agent-shipproof" / "scripts" / "shipproof.py"
SPEC = importlib.util.spec_from_file_location("candidate_shipproof", MODULE)
assert SPEC and SPEC.loader
shipproof = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shipproof
SPEC.loader.exec_module(shipproof)


class ShipProofTests(unittest.TestCase):
    def make_root(self, *, with_git: bool = False) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        (root / "src").mkdir()
        (root / "src" / "file.txt").write_text("one\n", encoding="utf-8")
        (root / "test.py").write_text("print('ok')\n", encoding="utf-8")
        if with_git:
            for args in (("init", "-q"), ("config", "user.email", "test@example.invalid"), ("config", "user.name", "Test"), ("add", "."), ("commit", "-qm", "baseline")):
                subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
        return temp, root

    def create(self, root: Path, **kwargs):
        return shipproof.create_receipt(
            root, root / "receipt.json", ["Command completed."], [sys.executable, "test.py"],
            ["src/**", "test.py"], [], **kwargs,
        )

    def test_create_and_verify_unchanged(self) -> None:
        temp, root = self.make_root(with_git=True); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        result = shipproof.verify_receipt(root, receipt)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(receipt["command"]["exit_code"], 0)

    def test_changed_file_is_reported_without_contents(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        (root / "src" / "file.txt").write_text("secret new content\n", encoding="utf-8")
        result = shipproof.verify_receipt(root, receipt)
        rendered = json.dumps(result)
        self.assertEqual(result["artifacts"]["changed"], ["src/file.txt"])
        self.assertNotIn("secret new content", rendered)

    def test_added_and_removed_files_are_reported(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        (root / "src" / "file.txt").unlink()
        (root / "src" / "new.txt").write_text("new", encoding="utf-8")
        result = shipproof.verify_receipt(root, receipt)
        self.assertEqual(result["artifacts"]["added"], ["src/new.txt"])
        self.assertEqual(result["artifacts"]["removed"], ["src/file.txt"])

    def test_receipt_tamper_blocks_artifact_verification(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        receipt["claims"][0]["text"] = "tampered"
        result = shipproof.verify_receipt(root, receipt)
        self.assertEqual(result["receipt_integrity"], "fail")
        self.assertEqual(result["artifacts"]["status"], "not_checked_untrusted_receipt")

    def test_self_consistent_but_malformed_receipt_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        del receipt["command"]["output_limit_bytes"]
        body = {key: value for key, value in receipt.items() if key != "integrity"}
        receipt["integrity"]["payload_sha256"] = shipproof.sha256_bytes(shipproof.canonical_bytes(body))
        with self.assertRaisesRegex(shipproof.ShipProofError, "command fields"):
            shipproof.verify_receipt(root, receipt)

    def test_distinct_exit_codes_produce_distinct_payload_digests(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        first = shipproof.finalize_receipt({"command": {"exit_code": 0}}, None, None)
        second = shipproof.finalize_receipt({"command": {"exit_code": 1}}, None, None)
        self.assertNotEqual(first["integrity"]["payload_sha256"], second["integrity"]["payload_sha256"])

    def test_distinct_file_hashes_produce_distinct_payload_digests(self) -> None:
        first = shipproof.finalize_receipt({"artifacts": [{"sha256": "a" * 64}]}, None, None)
        second = shipproof.finalize_receipt({"artifacts": [{"sha256": "b" * 64}]}, None, None)
        self.assertNotEqual(first["integrity"]["payload_sha256"], second["integrity"]["payload_sha256"])

    def test_hmac_round_trip(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root, hmac_key=b"pilot secret", key_id="pilot-01")
        result = shipproof.verify_receipt(root, receipt, b"pilot secret")
        self.assertEqual(result["authentication"]["status"], "pass")
        self.assertNotIn("pilot secret", json.dumps(receipt))

    def test_wrong_hmac_key_fails(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root, hmac_key=b"one", key_id="pilot-01")
        result = shipproof.verify_receipt(root, receipt, b"two")
        self.assertEqual(result["status"], "drift")
        self.assertEqual(result["authentication"]["status"], "fail")

    def test_hmac_key_id_tamper_fails(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root, hmac_key=b"one", key_id="pilot-01")
        receipt["integrity"]["authentication"]["key_id"] = "pilot-02"
        result = shipproof.verify_receipt(root, receipt, b"one")
        self.assertEqual(result["authentication"]["status"], "fail")

    def test_hmac_claim_boundary_tamper_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root, hmac_key=b"one", key_id="pilot-01")
        receipt["integrity"]["authentication"]["claim_boundary"] = "signature"
        with self.assertRaisesRegex(shipproof.ShipProofError, "claim boundary"):
            shipproof.verify_receipt(root, receipt, b"one")

    def test_hmac_extra_field_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root, hmac_key=b"one", key_id="pilot-01")
        receipt["integrity"]["authentication"]["unexpected"] = True
        with self.assertRaisesRegex(shipproof.ShipProofError, "authentication block"):
            shipproof.verify_receipt(root, receipt, b"one")

    def test_hmac_key_rejects_unsigned_receipt(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        with self.assertRaisesRegex(shipproof.ShipProofError, "downgrade"):
            shipproof.verify_receipt(root, receipt, b"one")

    def test_missing_hmac_key_is_tool_error(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root, hmac_key=b"one", key_id="pilot-01")
        with self.assertRaisesRegex(shipproof.ShipProofError, "provide --hmac-key-env"):
            shipproof.verify_receipt(root, receipt)

    def test_hmac_requires_key_id(self) -> None:
        with self.assertRaisesRegex(shipproof.ShipProofError, "key-id"):
            shipproof.finalize_receipt({"x": 1}, b"one", None)

    def test_claim_is_required(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(shipproof.ShipProofError, "claim"):
            shipproof.create_receipt(root, root / "r.json", [], [sys.executable, "test.py"], ["src/**"], [])

    def test_claim_with_common_credential_shape_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(shipproof.ShipProofError, "claim appears"):
            shipproof.create_receipt(root, root / "r.json", ["token sk-12345678"], [sys.executable, "test.py"], ["src/**"], [])

    def test_argv_with_common_credential_shape_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(shipproof.ShipProofError, "argument appears"):
            shipproof.create_receipt(root, root / "r.json", ["x"], [sys.executable, "-c", "print('ghp_12345678')"], ["src/**"], [])

    def test_include_is_required(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(shipproof.ShipProofError, "include"):
            shipproof.create_receipt(root, root / "r.json", ["x"], [sys.executable, "test.py"], [], [])

    def test_include_escape_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(shipproof.ShipProofError, "escapes"):
            shipproof.create_receipt(
                root, root / "receipt.json", ["Command completed."], [sys.executable, "test.py"],
                ["../secret"], [],
            )

    def test_receipt_overwrite_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        path = root / "receipt.json"
        path.write_text("existing", encoding="utf-8")
        with self.assertRaisesRegex(shipproof.ShipProofError, "overwrite"):
            self.create(root)
        self.assertEqual(path.read_text(encoding="utf-8"), "existing")

    def test_receipt_path_outside_root_is_rejected(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        outside = root.parent / f"{root.name}-outside-receipt.json"
        with self.assertRaisesRegex(shipproof.ShipProofError, "inside the receipt root"):
            shipproof.create_receipt(
                root, outside, ["Command completed."], [sys.executable, "test.py"],
                ["src/**"], [],
            )
        self.assertFalse(outside.exists())

    def test_root_symlink_check_precedes_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(shipproof.ShipProofError, "root must not"):
                shipproof.collect_artifacts(Path(temp), ["**/*"], [])

    def test_selected_symlink_is_rejected_when_supported(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        link = root / "src" / "link.txt"
        try:
            link.symlink_to(root / "src" / "file.txt")
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(shipproof.ShipProofError, "symbolic link"):
            shipproof.collect_artifacts(root, ["src/**"], [])

    def test_command_runs_without_shell(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        result = shipproof.run_command(root, [sys.executable, "-c", "print('hello')"], 10)
        self.assertFalse(result["shell"])
        self.assertEqual(result["stdout"]["excerpt"], "hello")

    def test_command_timeout_records_124(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        result = shipproof.run_command(root, [sys.executable, "-c", "import time; time.sleep(3)"], 1)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], 124)

    def test_command_start_failure_is_tool_error(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(shipproof.ShipProofError, "could not start"):
            shipproof.run_command(root, ["definitely-missing-command-shipproof"], 1)

    def test_output_excerpt_redacts_common_secret_shape(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        result = shipproof.run_command(root, [sys.executable, "-c", "print('sk-' + 'A'*10)"], 10)
        self.assertIn("[REDACTED]", result["stdout"]["excerpt"])

    def test_output_excerpt_redacts_aws_shapes(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        script = "print('AKIA' + 'A'*16); print('aws_secret_access_key=' + 'B'*40)"
        result = shipproof.run_command(root, [sys.executable, "-c", script], 10)
        rendered = result["stdout"]["excerpt"]
        self.assertNotIn("AKIA" + "A" * 16, rendered)
        self.assertNotIn("B" * 40, rendered)
        self.assertGreaterEqual(rendered.count("[REDACTED]"), 2)

    def test_output_limit_bounds_receipt_evidence(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        result = shipproof.run_command(
            root,
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*200000)"],
            10,
            max_output_bytes=10_000,
        )
        self.assertTrue(result["output_limit_exceeded"])
        self.assertEqual(result["exit_code"], 125)
        self.assertIn("[truncated]", result["stdout"]["excerpt"])
        self.assertLess(len(json.dumps(result)), 20_000)

    def test_git_state_changes_after_worktree_change(self) -> None:
        temp, root = self.make_root(with_git=True); self.addCleanup(temp.cleanup)
        before = shipproof.git_state(root, [])
        (root / "src" / "file.txt").write_text("two\n", encoding="utf-8")
        after = shipproof.git_state(root, [])
        self.assertNotEqual(before["status_sha256"], after["status_sha256"])

    def test_nested_root_does_not_inherit_ancestor_git_state(self) -> None:
        temp, root = self.make_root(with_git=True); self.addCleanup(temp.cleanup)
        nested = root / "nested" / "candidate"
        nested.mkdir(parents=True)
        self.assertEqual(shipproof.git_state(nested, []), {"available": False})

    def test_receipt_path_is_excluded_from_git_state(self) -> None:
        temp, root = self.make_root(with_git=True); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        result = shipproof.verify_receipt(root, receipt)
        self.assertEqual(result["git"]["status"], "pass")

    def test_cli_verify_exit_codes(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(shipproof.main(["verify", str(root / "receipt.json"), "--root", str(root)]), 0)
        (root / "src" / "file.txt").write_text("two", encoding="utf-8")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(shipproof.main(["verify", str(root / "receipt.json"), "--root", str(root)]), 1)

    def test_missing_hmac_environment_is_cli_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), redirect_stderr(io.StringIO()):
            self.assertEqual(shipproof.main(["verify", "missing.json", "--hmac-key-env", "MISSING"]), 2)

    def test_load_receipt_rejects_wrong_artifact_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "r.json"
            path.write_text('{"schema_version":"1.0","artifact_name":"Proof"}', encoding="utf-8")
            with self.assertRaises(shipproof.ShipProofError):
                shipproof.load_receipt(path)

    def test_absolute_paths_are_not_in_receipt(self) -> None:
        temp, root = self.make_root(); self.addCleanup(temp.cleanup)
        receipt = self.create(root)
        self.assertNotIn(str(root), json.dumps(receipt))
        self.assertEqual(receipt["root"], ".")


if __name__ == "__main__":
    unittest.main()
