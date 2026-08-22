"""Focused public-release validator regression tests."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sp_validator", ROOT / "tools" / "validate_release_candidate.py")
assert spec and spec.loader
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class Tests(unittest.TestCase):
    def test_revision_ignores_validation_and_residue(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "validation").mkdir()
            (root / "build").mkdir()
            (root / "a").write_text("1", encoding="utf-8")
            (root / "validation" / "x").write_text("1", encoding="utf-8")
            (root / "build" / "x").write_text("1", encoding="utf-8")
            first = v.product_revision(root)[0]
            (root / "validation" / "x").write_text("2", encoding="utf-8")
            (root / "build" / "x").write_text("2", encoding="utf-8")
            second = v.product_revision(root)[0]
            (root / "a").write_text("2", encoding="utf-8")
            third = v.product_revision(root)[0]
        self.assertEqual(first, second)
        self.assertNotEqual(second, third)

    def test_residue_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "build").mkdir()
            (root / "plugin.egg-info").mkdir()
            (root / "build" / "output.py").write_text("generated", encoding="utf-8")
            (root / "plugin.egg-info" / "PKG-INFO").write_text("generated", encoding="utf-8")
            self.assertEqual(v.residue_paths(root), ["build/output.py", "plugin.egg-info/PKG-INFO"])

    def test_current_receipt_rejects_stale_or_external(self) -> None:
        self.assertIn("example: stale revision", v.current_receipt("example", {"status": "pass", "product_revision_sha256": "old", "publication_action": "none"}, "new"))
        self.assertIn("example: publication action", v.current_receipt("example", {"status": "pass", "product_revision_sha256": "new", "publication_action": "submitted"}, "new"))

    def test_transparent_master_and_icon_are_safe(self) -> None:
        self.assertEqual(v.assets(), [])

    def test_provider_packages_are_aligned(self) -> None:
        self.assertEqual(v.validate_packages(), [])

    def test_public_text_is_safe(self) -> None:
        self.assertEqual(v.safety(), [])

    def test_specific_failure_preserved(self) -> None:
        names = ("required", "safety", "metadata", "behavior", "assets", "logo_provenance", "validate_packages", "receipts")
        patches = [mock.patch.object(v, name, return_value=[]) for name in names]
        with ExitStack() as stack:
            required = stack.enter_context(patches[0])
            for patch in patches[1:]:
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(v, "rev", return_value="a" * 64))
            required.return_value = ["one"]
            result = v.run_validation()
        self.assertEqual(result["errors"], ["one"])
        self.assertEqual(result["checks"]["required_files"], "fail")


if __name__ == "__main__":
    unittest.main()
