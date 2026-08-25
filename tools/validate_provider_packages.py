#!/usr/bin/env python3
"""Fail-closed structural validation for the public provider package surfaces."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "agent-shipproof"
SHORT = "Record what the agent ran."
LONG = (
    "Use this when you have an approved local command to run and need a verifiable record of what happened. "
    "Completion Receipt runs only that command, records its exit status, hashes selected files, captures Git state, "
    "and later reports added, removed, or changed paths without file contents. Receipt inputs and metadata still need "
    "local sensitivity review because redaction is best effort. Do not treat the receipt as proof of correctness, "
    "security, identity, authorization, or sandboxing."
)
PROMPTS = [
    "We’re about to ship a billing migration, and Finance needs a clear record of what the agent actually ran before they sign off. Run the approved validation command and create a receipt with its exit status, selected file hashes, and current Git state. Do not include file contents or claim the build is correct.",
    "The engineering agent says the release checks are complete. Verify the receipt against the current checkout and give Product, Finance, and Engineering a concise list of only the selected paths that changed, plus anything the receipt cannot prove.",
    "Before I approve this deployment, explain what this receipt proves, what changed since it was created, and what still needs independent review.",
]


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def workflow_contract() -> list[str]:
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")
    errors: list[str] = []
    for token in ("ubuntu-latest", "macos-latest", "windows-latest", '"3.10"', '"3.12"', "contents: read"):
        if token not in workflow:
            errors.append(f"workflow missing cross-platform contract: {token}")
    return errors


def validate_packages() -> list[str]:
    errors: list[str] = []
    try:
        codex = load(PLUGIN / ".codex-plugin" / "plugin.json")
        claude_marketplace = load(ROOT / ".claude-plugin" / "marketplace.json")
        claude_plugin = load(PLUGIN / ".claude-plugin" / "plugin.json")
        submission = load(ROOT / "submission" / "openai-plugin-submission.json")
        funding = (ROOT / ".github" / "FUNDING.yml").read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as exc:
        return [f"provider package read failed: {exc}"]

    interface = codex.get("interface", {})
    if codex.get("name") != "agent-shipproof" or codex.get("version") != "0.1.2":
        errors.append("Codex manifest identity mismatch")
    if interface.get("developerName") != "Orbral" or interface.get("category") != "Developer Tools":
        errors.append("Codex public display metadata mismatch")
    if interface.get("shortDescription") != "Record what the agent ran." or interface.get("longDescription") != LONG:
        errors.append("Codex public description mismatch")
    if interface.get("defaultPrompt") != PROMPTS:
        errors.append("Codex starter prompts mismatch")
    if "screenshots" in interface:
        errors.append("skills-only plugin must not declare interface.screenshots")
    if "mcp" in json.dumps(codex).casefold():
        errors.append("Codex manifest must remain skills-only without MCP")

    entries = claude_marketplace.get("plugins", [])
    entry = entries[0] if len(entries) == 1 else {}
    if claude_marketplace.get("owner", {}).get("name") != "Orbral":
        errors.append("Claude marketplace owner mismatch")
    if entry.get("name") != "completion-receipt" or entry.get("source") != "./plugins/agent-shipproof" or entry.get("version") != "0.1.2":
        errors.append("Claude marketplace entry mismatch")
    if claude_plugin.get("name") != "completion-receipt" or claude_plugin.get("version") != "0.1.2":
        errors.append("Claude plugin identity mismatch")
    expected_claude_description = "Use when an approved local command needs a verifiable receipt with exit status, selected file hashes, observed Git state, and later path-level drift checks."
    if claude_plugin.get("author", {}).get("name") != "Orbral" or claude_plugin.get("description") != expected_claude_description:
        errors.append("Claude plugin public metadata mismatch")

    if submission.get("schema_version") != "1.0" or submission.get("submission_type") != "skills_only":
        errors.append("OpenAI submission must declare skills_only schema 1.0")
    expected = {
        "plugin_name": "Completion Receipt",
        "publisher": "Orbral",
        "category": "Developer Tools",
        "subtitle": "Record what the agent ran",
        "short_description": SHORT,
        "long_description": LONG,
    }
    for key, value in expected.items():
        if submission.get(key) != value:
            errors.append(f"OpenAI submission {key} mismatch")
    if submission.get("starter_prompts") != PROMPTS:
        errors.append("OpenAI submission starter prompts mismatch")
    if len(submission.get("positive_tests", [])) != 5 or len(submission.get("negative_tests", [])) != 3:
        errors.append("OpenAI submission must contain five positive and three negative cases")
    if "mcp" in json.dumps(submission).casefold() and "no mcp server" not in json.dumps(submission).casefold():
        errors.append("OpenAI submission must not declare an MCP surface")
    for key in ("website_url", "support_url", "privacy_policy_url", "terms_url"):
        if not str(submission.get(key, "")).startswith("https://github.com/SpannDaMan/agent-shipproof"):
            errors.append(f"OpenAI submission {key} must use the public repository URL")
    if funding.strip() != "github: [SpannDaMan]":
        errors.append("funding profile target mismatch")
    errors.extend(workflow_contract())
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    errors = validate_packages()
    result = {"status": "pass" if not errors else "fail", "errors": errors}
    print(json.dumps(result, indent=2) if args.json else result["status"])
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
