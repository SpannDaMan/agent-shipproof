#!/usr/bin/env python3
"""Fail-closed validation for the frozen Agent ShipProof public candidate."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "agent-shipproof"
sys.path.insert(0, str(Path(__file__).parent))
from release_evidence import product_revision
from validate_provider_packages import validate_packages

TRANSPARENT_MASTER = "plugins/agent-shipproof/assets/Agent ShipProof Transparent Master 220826.png"
TRANSPARENT_HASH = "d0d8d27f8061a63f1c675e6ac5d5db332b6098c2b97c924694c127695f7ffe05"
SILVER_MASTER = "plugins/agent-shipproof/assets/Completion Receipt Silver Satin Master 240826.png"
SILVER_HASH = "30555a9081360d1f1fc63d253e93906375f0b1b7740231cb73fc80dc6c42e18a"
SILVER_BACKGROUND_HASH = "5ef688ba56bd8e8b185903df3a73262400859f0bb0791009b437f5d13ff8a579"
OPAQUE_PARENT_HASH = "4ca4186ac0b3f73d20e2d32890fa42764f7b65abb4e1bc078a8f745295362dd3"
REQUIRED = [
    ".gitignore", "LICENSE", "README.md", "BRAND.md", "CHANGELOG.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "DESIGN.md", "design.tokens.json", "MAINTAINER-PILOT.md", "PRIVACY.md", "PROVENANCE.md", "PUBLICATION-GATE.md", "RELEASE-CHECKLIST.md", "SECURITY.md", "SUPPORT.md", "TERMS.md", "THREAT-MODEL.md", "pyproject.toml", ".agents/plugins/marketplace.json", ".claude-plugin/marketplace.json", ".github/FUNDING.yml", ".github/workflows/test.yml", "docs/CLAUDE-INSTALL.md", "docs/CODEX-INSTALL.md", "docs/OPENAI-PLUGIN-SUBMISSION.md", "docs/RECEIPT-CONTRACT.md", "docs/RELEASE-EVIDENCE.md", "submission/openai-plugin-submission.json", "evals/shipproof-suite.json", "evals/agent-shipproof-activation-golden.json", "plugins/agent-shipproof/.claude-plugin/plugin.json", "plugins/agent-shipproof/.codex-plugin/plugin.json", "plugins/agent-shipproof/receipt.schema.json", "plugins/agent-shipproof/scripts/shipproof.py", "plugins/agent-shipproof/skills/agent-shipproof/SKILL.md", TRANSPARENT_MASTER, "plugins/agent-shipproof/assets/Agent ShipProof Transparent Extraction Receipt 220826.json", "plugins/agent-shipproof/assets/Logo Generation Manifest 140826.json", "plugins/agent-shipproof/assets/icon.png", "plugins/agent-shipproof/assets/logo.png", "plugins/agent-shipproof/assets/logo-dark.png", "plugins/agent-shipproof/assets/screenshot1.png", "plugins/agent-shipproof/assets/social-preview.png", "tests/test_shipproof.py", "tests/test_release_validator.py", "tests/test_activation_golden.py", "tools/demo.py", "tools/generate_release_evidence.py", "tools/release_evidence.py", "tools/render_brand_assets.ps1", "tools/run_evals.py", "tools/validate_provider_packages.py", "tools/validate_release_candidate.py", "tools/validate_activation_golden.py",
    "docs/GITHUB-ACTIONS.md", "examples/ci/generic-ci.md", SILVER_MASTER, "plugins/agent-shipproof/assets/Silver Satin Background Master 240826.png",
]
PNG = {
    TRANSPARENT_MASTER: (1254, 1254),
    SILVER_MASTER: (1254, 1254),
    "plugins/agent-shipproof/assets/icon.png": (512, 512),
    "plugins/agent-shipproof/assets/logo.png": (1024, 1024),
    "plugins/agent-shipproof/assets/logo-dark.png": (1024, 1024),
    "plugins/agent-shipproof/assets/screenshot1.png": (1600, 900),
    "plugins/agent-shipproof/assets/social-preview.png": (1600, 900),
}
PRIVATE_MARKERS = ("agent smith projects", "agent-smith-task-force", "diggy digital", "markeys meta ad specialist", "mr krabs", "appollonia", "showtime", "slack-agent-hub", "obsidian brains", "runtime/astf/", "chatgpt.com/g/", "conversation_url", "chat_url", "container_service")
SECRETS = (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), re.compile(r"\bghp_[A-Za-z0-9]{16,}"), re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}"), re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}"), re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+", re.I))
TEXT_SUFFIXES = {".md", ".json", ".py", ".toml", ".yml", ".yaml", ".txt", ".ps1", ".svg"}
RESIDUE_NAMES = {"build", "dist", "__pycache__", ".pytest_cache", ".venv", "venv"}


def rev() -> str:
    return product_revision(ROOT)[0]


def required() -> list[str]:
    return [f"missing required file: {path}" for path in REQUIRED if not (ROOT / path).is_file()]


def residue_paths(root: Path = ROOT) -> list[str]:
    paths: list[str] = []
    for path in root.rglob("*"):
        relative_path = path.relative_to(root)
        relative = relative_path.as_posix()
        if not path.is_file():
            continue
        if path.suffix == ".pyc" or any(part in RESIDUE_NAMES or part.endswith(".egg-info") for part in relative_path.parts):
            paths.append(relative)
    return sorted(paths)


def safety() -> list[str]:
    errors: list[str] = []
    this_file = Path(__file__).resolve()
    for path in ROOT.rglob("*"):
        if path.resolve() == this_file or not path.is_file() or path.is_symlink() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"invalid UTF-8: {path.relative_to(ROOT)}: {exc}")
            continue
        lowered = text.casefold()
        for marker in PRIVATE_MARKERS:
            if marker in lowered:
                errors.append(f"private marker in {path.relative_to(ROOT)}: {marker}")
        for pattern in SECRETS:
            if pattern.search(text):
                errors.append(f"sensitive pattern in {path.relative_to(ROOT)}: {pattern.pattern}")
    errors.extend(f"generated residue in public candidate: {path}" for path in residue_paths())
    return errors


def png_rgba_metrics(path: Path) -> tuple[int, int, tuple[int, int, int, int], tuple[int, int, int, int], tuple[int, int]]:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("invalid PNG signature")
    offset = 8
    width = height = bit_depth = color_type = interlace = None
    compressed = bytearray()
    while offset < len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        if kind == b"IHDR":
            width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", payload)
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            break
    if None in (width, height, bit_depth, color_type, interlace) or bit_depth != 8 or color_type != 6 or interlace != 0:
        raise ValueError("expected non-interlaced 8-bit RGBA PNG")
    raw = zlib.decompress(compressed)
    stride = width * 4
    previous = bytearray(stride)
    alpha_min, alpha_max = 255, 0
    left = top = None
    right = bottom = 0
    corners: tuple[int, int, int, int] | None = None
    cursor = 0
    for y in range(height):
        filter_type = raw[cursor]
        cursor += 1
        row = bytearray(raw[cursor:cursor + stride])
        cursor += stride
        for x in range(stride):
            a = row[x - 4] if x >= 4 else 0
            b = previous[x]
            c = previous[x - 4] if x >= 4 else 0
            if filter_type == 1:
                row[x] = (row[x] + a) & 255
            elif filter_type == 2:
                row[x] = (row[x] + b) & 255
            elif filter_type == 3:
                row[x] = (row[x] + ((a + b) // 2)) & 255
            elif filter_type == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                predictor = a if pa <= pb and pa <= pc else b if pb <= pc else c
                row[x] = (row[x] + predictor) & 255
            elif filter_type != 0:
                raise ValueError(f"unsupported PNG filter: {filter_type}")
        for x in range(width):
            alpha = row[x * 4 + 3]
            alpha_min, alpha_max = min(alpha_min, alpha), max(alpha_max, alpha)
            if alpha >= 8:
                left = x if left is None else min(left, x)
                top = y if top is None else min(top, y)
                right, bottom = max(right, x + 1), max(bottom, y + 1)
        if y == 0:
            top_left, top_right = row[3], row[(width - 1) * 4 + 3]
        if y == height - 1:
            corners = (top_left, top_right, row[3], row[(width - 1) * 4 + 3])
        previous = row
    if left is None or top is None or corners is None:
        raise ValueError("PNG has no visible pixels")
    return width, height, (left, top, right, bottom), corners, (alpha_min, alpha_max)


def assets() -> list[str]:
    errors: list[str] = []
    metrics: dict[str, tuple[int, int, tuple[int, int, int, int], tuple[int, int, int, int], tuple[int, int]]] = {}
    for relative, expected in PNG.items():
        path = ROOT / relative
        if not path.is_file():
            continue
        try:
            metric = png_rgba_metrics(path)
        except Exception as exc:
            errors.append(f"{relative}: {exc}")
            continue
        metrics[relative] = metric
        if metric[:2] != expected:
            errors.append(f"{relative}: expected {expected}, got {metric[:2]}")
    for relative in (TRANSPARENT_MASTER,):
        if relative not in metrics:
            continue
        width, height, box, corners, alpha = metrics[relative]
        if corners != (0, 0, 0, 0) or alpha[0] != 0 or alpha[1] != 255:
            errors.append(f"{relative}: transparent corners and alpha range are required")
        fill_width, fill_height = (box[2] - box[0]) / width, (box[3] - box[1]) / height
        if fill_width < 0.75 or fill_height < 0.85 or fill_width > 0.96 or fill_height > 0.96:
            errors.append(f"{relative}: unsafe visible fill {fill_width:.3f}x{fill_height:.3f}")
    master = ROOT / TRANSPARENT_MASTER
    if master.is_file() and hashlib.sha256(master.read_bytes()).hexdigest() != TRANSPARENT_HASH:
        errors.append("transparent master hash mismatch")
    for relative in (SILVER_MASTER, "plugins/agent-shipproof/assets/icon.png", "plugins/agent-shipproof/assets/logo.png", "plugins/agent-shipproof/assets/logo-dark.png"):
        if relative not in metrics:
            continue
        _, _, _, corners, alpha = metrics[relative]
        if corners != (255, 255, 255, 255) or alpha[0] != 255 or alpha[1] != 255:
            errors.append(f"{relative}: opaque full-bleed Silver Satin corners are required")
    return errors


def logo_provenance() -> list[str]:
    errors: list[str] = []
    manifest_path = PLUGIN / "assets" / "Logo Generation Manifest 140826.json"
    receipt_path = PLUGIN / "assets" / "Agent ShipProof Transparent Extraction Receipt 220826.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"logo provenance read failed: {exc}"]
    expected = {
        "canonical_master": SILVER_MASTER,
        "master_sha256": SILVER_HASH,
        "source_type": "deterministic_exact_mark_composite",
        "source_background_policy": "opaque full-bleed silver satin",
        "mark_source_sha256": TRANSPARENT_HASH,
        "shared_background_sha256": SILVER_BACKGROUND_HASH,
        "local_edit_status": "background-only deterministic composition",
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            errors.append(f"logo manifest {key} mismatch")
    if receipt.get("opaque_parent_sha256") != OPAQUE_PARENT_HASH or receipt.get("transparent_derivative_sha256") != TRANSPARENT_HASH:
        errors.append("transparent extraction receipt hash mismatch")
    if "unedited original" not in str(receipt.get("non_claim", "")).casefold():
        errors.append("transparent extraction receipt must disclaim an unedited-source claim")
    for forbidden in ("chat_url", "conversation_url", "container_service", "browser_content_id", "lease_status", "project"):
        if forbidden in manifest:
            errors.append(f"logo manifest retains private field: {forbidden}")
    renderer = (ROOT / "tools" / "render_brand_assets.ps1").read_text(encoding="utf-8")
    for control in ("deterministic_exact_mark_composite", "opaque full-bleed silver satin", "mark_source_sha256", "shared_background_sha256", "none_verify_only"):
        if control not in renderer:
            errors.append(f"brand renderer is missing source-only control: {control}")
    for forbidden in ("FillEllipse", "FillPolygon", "DrawLines", "DrawPath", "GraphicsPath"):
        if forbidden.casefold() in renderer.casefold():
            errors.append(f"brand renderer contains prohibited logo-origin operation: {forbidden}")
    return errors


def metadata() -> list[str]:
    try:
        plugin = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        marketplace = json.loads((ROOT / ".agents" / "plugins" / "marketplace.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"metadata failed: {exc}"]
    errors: list[str] = []
    if plugin.get("name") != "agent-shipproof" or plugin.get("version") != "0.1.3" or plugin.get("license") != "MIT":
        errors.append("plugin identity mismatch")
    if marketplace.get("owner", {}).get("name") != "Orbral" or marketplace.get("plugins", [{}])[0].get("source") != "./plugins/agent-shipproof":
        errors.append("marketplace public metadata mismatch")
    return errors


def behavior() -> list[str]:
    completed = subprocess.run([sys.executable, "tools/demo.py"], cwd=ROOT, capture_output=True, text=True)
    if completed.returncode:
        return ["five-minute demo failed"]
    text = "\n".join((ROOT / "README.md").read_text(encoding="utf-8").casefold().splitlines()[:40])
    return [f"first-screen claim boundary missing: {phrase}" for phrase in ("record what the agent ran", "does **not** prove", "not a public-key signature") if phrase not in text]


def fresh_upgrade_evidence() -> list[str]:
    completed = subprocess.run(
        [
            sys.executable,
            "tools/validate_activation_golden.py",
            "--suite",
            "evals/agent-shipproof-activation-golden.json",
            "--product-revision",
            rev(),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return [] if completed.returncode == 0 else [f"activation golden suite failed: {(completed.stdout + completed.stderr).strip()[-500:]}"]


def current_receipt(name: str, data: dict[str, Any], revision: str) -> list[str]:
    if data.get("status") not in {"pass", "eligible_for_public_package"}:
        return [f"{name}: nonpassing current status"]
    if data.get("product_revision_sha256") != revision:
        return [f"{name}: stale revision"]
    if data.get("publication_action") != "none":
        return [f"{name}: publication action"]
    return []


def receipts() -> list[str]:
    errors: list[str] = []
    revision = rev()
    names = ["Agent ShipProof Eval Result 120826.json", "Package Verification 120826.json", "Codex Plugin Verification 120826.json", "Claude Plugin Verification 220826.json", "OpenAI Submission Data Verification 220826.json", "Cross Platform Packaging Review 220826.json"]
    for name in names:
        try:
            data = json.loads((ROOT / "validation" / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        errors.extend(current_receipt(name, data, revision))
    for path in (ROOT / "validation").glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if "product_revision_sha256" in data and data.get("status") in {"pass", "eligible_for_public_package"} and data.get("product_revision_sha256") != revision:
            errors.append(f"{path.name}: stale current receipt")
    return errors


def run_validation() -> dict[str, Any]:
    checks = {
        "required_files": required(),
        "text_safety": safety(),
        "metadata": metadata(),
        "claims_and_behavior": behavior(),
        "assets": assets(),
        "logo_provenance": logo_provenance(),
        "provider_packages": validate_packages(),
        "fresh_upgrade_evidence": fresh_upgrade_evidence(),
        "revision_bound_receipts": receipts(),
    }
    errors = sorted({item for group in checks.values() for item in group})
    return {"status": "pass" if not errors else "fail", "candidate": "agent-shipproof 0.1.3", "product_revision_sha256": rev(), "checks": {name: "pass" if not values else "fail" for name, values in checks.items()}, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_validation()
    print(json.dumps(result, indent=2) if args.json else ("PASS: Completion Receipt release candidate" if result["status"] == "pass" else "FAIL: Completion Receipt release candidate"))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
