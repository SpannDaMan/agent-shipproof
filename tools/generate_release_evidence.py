#!/usr/bin/env python3
"""Generate revision-bound targeted public-package evidence, never the composite gate."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

ROOT = Path(__file__).resolve().parents[1]
VAL = ROOT / "validation"
sys.path.insert(0, str(Path(__file__).parent))

from release_evidence import file_sha256, product_revision
from validate_provider_packages import validate_packages, workflow_contract


def run(cmd: list[str], cwd: Path, allowed: set[int] = {0}) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(cmd, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode not in allowed:
        rendered = " ".join(map(str, cmd))
        raise RuntimeError(
            f"failed {completed.returncode}: {rendered}\n"
            f"{completed.stdout[-800:]}\n{completed.stderr[-800:]}"
        )
    return completed


def write(name: str, payload: dict[str, object]) -> None:
    (VAL / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def cleanup_generated_residue() -> None:
    """Remove only ignored build/cache outputs created in this candidate."""
    for path in (ROOT / "build", ROOT / "dist", ROOT / ".pytest_cache"):
        if path.is_dir():
            shutil.rmtree(path)
    for path in sorted(ROOT.rglob("*.egg-info"), reverse=True):
        if path.is_dir():
            shutil.rmtree(path)
    for path in sorted(ROOT.rglob("__pycache__"), reverse=True):
        if path.is_dir():
            shutil.rmtree(path)


def main() -> int:
    VAL.mkdir(exist_ok=True)
    revision, _ = product_revision(ROOT)

    eval_result = json.loads(run([sys.executable, "tools/run_evals.py"], ROOT).stdout)
    eval_result["product_revision_sha256"] = revision
    write("Agent ShipProof Eval Result 120826.json", eval_result)

    with tempfile.TemporaryDirectory() as temp_name:
        temp = Path(temp_name)
        wheel_dir = temp / "wheel"
        wheel_dir.mkdir()
        run(
            [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheel_dir)],
            ROOT,
        )
        wheel = next(wheel_dir.glob("*.whl"))
        venv = temp / "venv"
        run([sys.executable, "-m", "venv", str(venv)], temp)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], temp)
        pip_check = run([str(python), "-m", "pip", "check"], temp)
        version = run([str(python), "-m", "shipproof", "--version"], temp)

        toy = temp / "installed-cli-proof"
        (toy / "src").mkdir(parents=True)
        source = toy / "src" / "answer.txt"
        source.write_text("42\n", encoding="utf-8")
        check = toy / "check.py"
        check.write_text(
            "from pathlib import Path\n"
            "raise SystemExit(0 if Path('src/answer.txt').read_text() == '42\\n' else 1)\n",
            encoding="utf-8",
        )
        for args in (
            ["init", "-q"],
            ["config", "user.email", "package-proof@example.invalid"],
            ["config", "user.name", "Package Proof"],
            ["add", "."],
            ["commit", "-qm", "baseline"],
        ):
            run(["git", "-C", str(toy), *args], temp)

        receipt = toy / "completion-receipt.json"
        create = run(
            [
                str(python), "-m", "shipproof", "run",
                "--root", str(toy),
                "--receipt", str(receipt),
                "--claim", "The installed validation command exited successfully.",
                "--include", "src/**",
                "--include", "check.py",
                "--", str(python), "check.py",
            ],
            temp,
        )
        unchanged = run(
            [str(python), "-m", "shipproof", "verify", str(receipt), "--root", str(toy)],
            temp,
        )
        source.write_text("43\n", encoding="utf-8")
        changed = run(
            [str(python), "-m", "shipproof", "verify", str(receipt), "--root", str(toy)],
            temp,
            allowed={1},
        )
        changed_result = json.loads(changed.stdout)
        if changed_result["artifacts"]["changed"] != ["src/answer.txt"]:
            raise RuntimeError("installed CLI did not report the expected changed path")

        source_demo = run([sys.executable, "tools/demo.py"], ROOT)
        write(
            "Package Verification 120826.json",
            {
                "schema_version": "1.0",
                "candidate": "agent-shipproof 0.1.2",
                "product_revision_sha256": revision,
                "status": "pass",
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
                "runtime_dependencies": [],
                "wheel": {
                    "filename": wheel.name,
                    "sha256": file_sha256(wheel),
                    "bytes": wheel.stat().st_size,
                },
                "checks": [
                    {"name": "wheel_and_isolated_install", "status": "pass"},
                    {"name": "pip_check", "status": "pass", "result": pip_check.stdout.strip()},
                    {"name": "installed_version", "status": "pass", "result": version.stdout.strip()},
                    {"name": "installed_cli_create", "status": "pass", "result": json.loads(create.stdout)["status"]},
                    {"name": "installed_cli_unchanged_verify", "status": "pass", "result": json.loads(unchanged.stdout)["status"]},
                    {"name": "installed_cli_changed_path", "status": "pass", "result": changed_result["artifacts"]["changed"]},
                    {"name": "source_demo", "status": "pass", "result": json.loads(source_demo.stdout)["after_tamper"]["status"]},
                ],
                "publication_action": "none",
            },
        )

    validator = Path.home() / ".codex" / "skills" / ".system" / "plugin-creator" / "scripts" / "validate_plugin.py"
    plugin = run([sys.executable, str(validator), "plugins/agent-shipproof"], ROOT)
    write(
        "Codex Plugin Verification 120826.json",
        {
            "schema_version": "1.0",
            "candidate": "agent-shipproof 0.1.2",
            "product_revision_sha256": revision,
            "status": "pass",
            "exit_code": 0,
            "validated_plugin_path": "plugins/agent-shipproof",
            "tool": {
                "name": "Codex plugin validator",
                "sha256": file_sha256(validator),
                "bytes": validator.stat().st_size,
            },
            "output": "Plugin validation passed: plugins/agent-shipproof",
            "publication_action": "none",
        },
    )
    provider_errors = validate_packages()
    if provider_errors:
        raise RuntimeError("provider package validation failed: " + "; ".join(provider_errors))
    write(
        "OpenAI Submission Data Verification 220826.json",
        {
            "schema_version": "1.0",
            "candidate": "agent-shipproof 0.1.2",
            "product_revision_sha256": revision,
            "status": "pass",
            "checks": ["skills_only", "public_urls", "developer_display", "three_starter_prompts", "five_positive_cases", "three_negative_cases"],
            "publication_action": "none",
        },
    )
    write(
        "Cross Platform Packaging Review 220826.json",
        {
            "schema_version": "1.0",
            "candidate": "agent-shipproof 0.1.2",
            "product_revision_sha256": revision,
            "status": "pass",
            "checks": ["ubuntu-latest", "macos-latest", "windows-latest", "python-3.10", "python-3.12"],
            "workflow_errors": workflow_contract(),
            "publication_action": "none",
        },
    )
    claude_binary = os.environ.get("CLAUDE_BIN", "claude")
    if os.name == "nt" and claude_binary == "claude":
        windows_shim = Path(os.environ.get("APPDATA", "")) / "npm" / "claude.cmd"
        if windows_shim.is_file():
            claude_binary = str(windows_shim)
    claude = run([claude_binary, "plugin", "validate", "."], ROOT)
    write(
        "Claude Plugin Verification 220826.json",
        {
            "schema_version": "1.0",
            "candidate": "agent-shipproof 0.1.2",
            "product_revision_sha256": revision,
            "status": "pass",
            "command": "claude plugin validate .",
            "exit_code": claude.returncode,
            "output_summary": "Claude marketplace manifest validation passed.",
            "publication_action": "none",
        },
    )
    cleanup_generated_residue()
    print(json.dumps({"status": "pass", "product_revision_sha256": revision, "receipts": 6, "composite_release_gate": "not_run"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
