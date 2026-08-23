#!/usr/bin/env python3
"""Run the committed Agent ShipProof create/verify/tamper proof."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "plugins" / "agent-shipproof" / "scripts" / "shipproof.py"
SPEC = importlib.util.spec_from_file_location("agent_shipproof_demo", MODULE)
assert SPEC and SPEC.loader
shipproof = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shipproof
SPEC.loader.exec_module(shipproof)


def git(root: Path, *args: str) -> None:
    completed = subprocess.run(["git", "-C", str(root), *args], check=False, capture_output=True, text=True)
    if completed.returncode:
        raise RuntimeError(completed.stderr)


def main() -> int:
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "src").mkdir()
        source = root / "src" / "answer.txt"
        source.write_text("42\n", encoding="utf-8")
        check = root / "check.py"
        check.write_text("from pathlib import Path\nraise SystemExit(0 if Path('src/answer.txt').read_text() == '42\\n' else 1)\n", encoding="utf-8")
        git(root, "init", "-q")
        git(root, "config", "user.email", "demo@example.invalid")
        git(root, "config", "user.name", "ShipProof Demo")
        git(root, "add", ".")
        git(root, "commit", "-qm", "demo baseline")
        receipt_path = root / "completion-receipt.json"
        receipt = shipproof.create_receipt(
            root, receipt_path, ["The committed validation command exited successfully."],
            [sys.executable, "check.py"], ["src/**", "check.py"], [],
        )
        first = shipproof.verify_receipt(root, receipt)
        if first["status"] != "pass":
            raise SystemExit("demo failed: unchanged checkout did not verify")
        source.write_text("43\n", encoding="utf-8")
        second = shipproof.verify_receipt(root, receipt)
        if second["status"] != "drift" or second["artifacts"]["changed"] != ["src/answer.txt"]:
            raise SystemExit("demo failed: changed path was not identified")
        print(json.dumps({
            "created": {"artifact": "Completion Receipt", "payload_sha256": receipt["integrity"]["payload_sha256"], "command_exit_code": receipt["command"]["exit_code"]},
            "unchanged_verification": first,
            "after_tamper": second,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
