from __future__ import annotations

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "plugins" / "agent-shipproof" / "scripts" / "shipproof.py"
SPEC = importlib.util.spec_from_file_location("shipproof_observed_evidence_tests", SCRIPT)
assert SPEC and SPEC.loader
shipproof = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shipproof
SPEC.loader.exec_module(shipproof)


class ObservedEvidenceTests(unittest.TestCase):
    def create(self, root: Path) -> dict:
        (root / "sample.txt").write_text("selected evidence\n", encoding="utf-8")
        return shipproof.create_receipt(
            root,
            root / "receipt.json",
            ["Selected evidence command completed"],
            [sys.executable, "-c", "print('ok')"],
            ["sample.txt"],
            [],
        )

    def test_new_receipt_contains_bounded_observed_evidence_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = self.create(root)
            envelope = receipt["observed_evidence"]
            self.assertEqual(envelope["contract"], "observed-evidence-envelope-v1")
            self.assertEqual(envelope["environment"]["cwd"], ".")
            self.assertFalse(envelope["environment"]["environment_variables_captured"])
            self.assertIn("absolute paths", envelope["omissions"])
            self.assertEqual(envelope["artifacts"], receipt["artifacts"])
            self.assertEqual(shipproof.verify_receipt(root, receipt)["status"], "pass")

    def test_valid_v010_body_remains_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = self.create(root)
            legacy_body = {key: copy.deepcopy(value) for key, value in current.items() if key not in {"integrity", "observed_evidence"}}
            legacy_body["tool"]["version"] = "0.1.0"
            shipproof.validate_receipt_body(legacy_body)
            legacy = shipproof.finalize_receipt(legacy_body, None, None)
            self.assertEqual(shipproof.verify_receipt(root, legacy)["status"], "pass")


if __name__ == "__main__":
    unittest.main()
