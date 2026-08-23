#!/usr/bin/env python3
"""Completion Receipt: create and verify honest local records of observed execution."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


VERSION = "0.1.1"
SCHEMA_VERSION = "1.0"
EXIT_PASS = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2
CLAIM_BOUNDARY = "Binds declared claims to observed local evidence; does not guarantee correctness, security, authenticity, authorship, authorization, or sandboxing."
HMAC_BOUNDARY = "Shared-secret tamper authentication only; not a public-key signature, identity proof, or attestation."
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_EXCLUDES = (
    ".git/**", ".hg/**", ".svn/**", ".venv/**", "venv/**", "node_modules/**",
    "dist/**", "build/**", "__pycache__/**", "*.pyc",
)
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{8,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{8,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(?:aws_secret_access_key|secret_access_key|password|passwd)\s*[:=]\s*[^\s,;]{8,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class ShipProofError(ValueError):
    """An input or environment error that prevents a trustworthy receipt operation."""


@dataclass(frozen=True)
class Artifact:
    path: str
    bytes: int
    sha256: str


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(value: str, root: Path | None = None) -> str:
    """Redact common credential shapes and the local root from display-only evidence."""

    rendered = value
    if root is not None:
        variants = {str(root), str(root).replace("\\", "/")}
        for variant in sorted(variants, key=len, reverse=True):
            rendered = rendered.replace(variant, ".")
    for pattern in SECRET_PATTERNS:
        rendered = pattern.sub("[REDACTED]", rendered)
    return "".join(character if character.isprintable() or character in "\n\t" else " " for character in rendered)


def excerpt(path: Path, root: Path, limit: int = 4096) -> str:
    size = path.stat().st_size
    with path.open("rb") as handle:
        raw = handle.read(limit)
    text = raw.decode("utf-8", errors="replace")
    clipped = size > limit
    value = redact(text, root).rstrip()
    return value + ("\n…[truncated]" if clipped else "")


def validate_patterns(patterns: Iterable[str], label: str) -> tuple[str, ...]:
    output: list[str] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.strip():
            raise ShipProofError(f"{label} patterns must be non-empty strings")
        normalized = pattern.replace("\\", "/")
        if Path(normalized).is_absolute() or normalized == ".." or normalized.startswith("../") or "/../" in normalized:
            raise ShipProofError(f"{label} pattern escapes the receipt root: {pattern}")
        output.append(normalized)
    if not output and label == "include":
        raise ShipProofError("at least one --include pattern is required")
    return tuple(sorted(set(output)))


def matches(relative: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(relative, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatchcase(relative, pattern[3:]):
            return True
    return False


def collect_artifacts(
    root: Path,
    includes: Iterable[str],
    excludes: Iterable[str],
    *,
    max_files: int = 10000,
    max_bytes: int = 100_000_000,
) -> list[Artifact]:
    """Collect one deterministic, symlink-free artifact manifest."""

    includes = validate_patterns(includes, "include")
    excludes = validate_patterns(excludes, "exclude")
    if root.is_symlink():
        raise ShipProofError("receipt root must not be a symbolic link")
    root = root.resolve()
    if not root.is_dir():
        raise ShipProofError(f"receipt root is not a directory: {root}")
    artifacts: list[Artifact] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: (item.relative_to(root).as_posix().casefold(), item.relative_to(root).as_posix())):
        relative = path.relative_to(root).as_posix()
        if matches(relative, excludes) or not matches(relative, includes):
            continue
        if path.is_symlink():
            raise ShipProofError(f"selected artifact is a symbolic link: {relative}")
        if not path.is_file():
            continue
        size = path.stat().st_size
        total_bytes += size
        if len(artifacts) + 1 > max_files:
            raise ShipProofError(f"selected artifact count exceeds --max-files ({max_files})")
        if total_bytes > max_bytes:
            raise ShipProofError(f"selected artifact bytes exceed --max-bytes ({max_bytes})")
        artifacts.append(Artifact(relative, size, sha256_file(path)))
    return artifacts


def _run_git(root: Path, args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(root), *args], check=False, capture_output=True, timeout=10)


def _normalized_git_status(raw: bytes, ignored: set[str]) -> tuple[str, int]:
    tokens = raw.split(b"\x00")
    records: list[bytes] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if not token:
            continue
        status = token[:2]
        first = token[3:].decode("utf-8", errors="surrogateescape").replace("\\", "/")
        paths = [first]
        if b"R" in status or b"C" in status:
            if index < len(tokens) and tokens[index]:
                paths.append(tokens[index].decode("utf-8", errors="surrogateescape").replace("\\", "/"))
                index += 1
        if any(path in ignored for path in paths):
            continue
        records.append(status + b"\x00" + b"\x00".join(path.encode("utf-8", errors="surrogateescape") for path in paths))
    normalized = b"\n".join(sorted(records))
    return sha256_bytes(normalized), len(records)


def git_state(root: Path, ignored_paths: Iterable[str]) -> dict[str, Any]:
    """Capture local Git identity and normalized working-state digest without networking."""

    # A candidate nested below a larger private workspace must not inherit the
    # ancestor repository's identity. Git evidence is available only when the
    # declared receipt root itself carries a .git directory/file or symlink.
    git_entry = root / ".git"
    if not git_entry.exists() and not git_entry.is_symlink():
        return {"available": False}
    try:
        head = _run_git(root, ["rev-parse", "HEAD"])
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False}
    if head.returncode != 0:
        return {"available": False}
    branch = _run_git(root, ["branch", "--show-current"])
    status = _run_git(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if branch.returncode != 0 or status.returncode != 0:
        raise ShipProofError("Git repository was found but its local state could not be read")
    status_digest, dirty_count = _normalized_git_status(status.stdout, set(ignored_paths))
    return {
        "available": True,
        "head": head.stdout.decode("ascii", errors="replace").strip(),
        "branch": branch.stdout.decode("utf-8", errors="replace").strip() or "(detached)",
        "status_sha256": status_digest,
        "dirty_entry_count": dirty_count,
        "network_used": False,
    }


def run_command(
    root: Path,
    argv: list[str],
    timeout_seconds: int,
    max_output_bytes: int = 10_000_000,
) -> dict[str, Any]:
    """Run one explicit argv without a shell and capture bounded display evidence plus full output hashes."""

    if not argv:
        raise ShipProofError("a command is required after --")
    if timeout_seconds < 1 or timeout_seconds > 86400:
        raise ShipProofError("--timeout must be between 1 and 86400 seconds")
    if max_output_bytes < 1024 or max_output_bytes > 1_000_000_000:
        raise ShipProofError("--max-output-bytes must be between 1024 and 1000000000")
    with tempfile.TemporaryDirectory() as temp_name:
        stdout_path = Path(temp_name) / "stdout.bin"
        stderr_path = Path(temp_name) / "stderr.bin"
        started = time.monotonic()
        try:
            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                process = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=stdout_handle, stderr=stderr_handle, shell=False)
                timed_out = False
                output_limit_exceeded = False
                deadline = started + timeout_seconds
                while process.poll() is None:
                    captured_bytes = stdout_path.stat().st_size + stderr_path.stat().st_size
                    if captured_bytes > max_output_bytes:
                        process.kill()
                        process.wait()
                        output_limit_exceeded = True
                        exit_code = 125
                        break
                    if time.monotonic() >= deadline:
                        process.kill()
                        process.wait()
                        timed_out = True
                        exit_code = 124
                        break
                    time.sleep(0.02)
                else:
                    exit_code = int(process.returncode)
                final_captured_bytes = stdout_path.stat().st_size + stderr_path.stat().st_size
                if not timed_out and final_captured_bytes > max_output_bytes:
                    output_limit_exceeded = True
                    exit_code = 125
        except OSError as exc:
            raise ShipProofError(f"command could not start: {exc}") from exc
        duration_ms = int((time.monotonic() - started) * 1000)
        raw_argv = b"\x00".join(item.encode("utf-8", errors="surrogateescape") for item in argv)
        return {
            "argv_display": [redact(item, root) for item in argv],
            "argv_sha256": sha256_bytes(raw_argv),
            "shell": False,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "output_limit_exceeded": output_limit_exceeded,
            "output_limit_bytes": max_output_bytes,
            "duration_ms": duration_ms,
            "stdout": {"bytes": stdout_path.stat().st_size, "sha256": sha256_file(stdout_path), "excerpt": excerpt(stdout_path, root)},
            "stderr": {"bytes": stderr_path.stat().st_size, "sha256": sha256_file(stderr_path), "excerpt": excerpt(stderr_path, root)},
        }


def receipt_body(
    *, root: Path, claims: list[str], command: dict[str, Any], includes: tuple[str, ...], excludes: tuple[str, ...],
    artifacts: list[Artifact], git: dict[str, Any],
) -> dict[str, Any]:
    selection = {
        "includes": list(includes),
        "excludes": list(excludes),
        "symlinks_followed": False,
    }
    artifact_records = [asdict(item) for item in artifacts]
    observed_evidence = {
        "contract": "observed-evidence-envelope-v1",
        "command": {
            "argv_sha256": command["argv_sha256"],
            "exit_code": command["exit_code"],
            "timed_out": command["timed_out"],
            "output_limit_exceeded": command["output_limit_exceeded"],
            "stdout_sha256": command["stdout"]["sha256"],
            "stderr_sha256": command["stderr"]["sha256"],
        },
        "artifacts": [
            {"path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"]}
            for item in artifact_records
        ],
        "git": git,
        "environment": {
            "cwd": ".",
            "os_family": os.name,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "environment_variables_captured": False,
        },
        "omissions": [
            "absolute paths",
            "credentials and environment-variable values",
            "file contents beyond bounded redacted command excerpts",
            "identity and authorization",
            "network and runtime behavior not present in the selected evidence",
        ],
        "provenance": {
            "root": ".",
            "selection_sha256": sha256_bytes(canonical_bytes(selection)),
            "artifact_manifest_sha256": sha256_bytes(canonical_bytes(artifact_records)),
            "git_observation_sha256": sha256_bytes(canonical_bytes(git)),
        },
        "claim_boundary": "Records selected observations and explicit omissions only; it does not prove correctness, security, identity, authorization, certification, or sandboxing.",
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "agent-shipproof", "version": VERSION},
        "artifact_name": "Completion Receipt",
        "claim_boundary": CLAIM_BOUNDARY,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": ".",
        "claims": [{"text": claim, "status": "declared_not_semantically_verified"} for claim in claims],
        "command": command,
        "selection": selection,
        "artifacts": artifact_records,
        "git": git,
        "observed_evidence": observed_evidence,
    }


def finalize_receipt(body: dict[str, Any], hmac_key: bytes | None, key_id: str | None) -> dict[str, Any]:
    payload = canonical_bytes(body)
    integrity: dict[str, Any] = {"payload_sha256": sha256_bytes(payload), "authentication": None}
    if hmac_key is not None:
        if not key_id:
            raise ShipProofError("--hmac-key-id is required when --hmac-key-env is used")
        authentication_material = b"agent-shipproof-pilot-hmac-v1\x00" + key_id.encode("utf-8") + b"\x00" + payload
        integrity["authentication"] = {
            "type": "pilot_hmac_sha256",
            "key_id": key_id,
            "tag": hmac.new(hmac_key, authentication_material, hashlib.sha256).hexdigest(),
            "claim_boundary": HMAC_BOUNDARY,
        }
    return {**body, "integrity": integrity}


def create_receipt(
    root: Path,
    receipt_path: Path,
    claims: list[str],
    argv: list[str],
    includes: list[str],
    excludes: list[str],
    *,
    timeout_seconds: int = 600,
    max_files: int = 10000,
    max_bytes: int = 100_000_000,
    max_output_bytes: int = 10_000_000,
    hmac_key: bytes | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ShipProofError(f"refusing to overwrite existing receipt: {receipt_path}")
    if not claims or any(not claim.strip() for claim in claims):
        raise ShipProofError("at least one non-empty --claim is required")
    for claim in claims:
        if any(pattern.search(claim) for pattern in SECRET_PATTERNS):
            raise ShipProofError("a declared claim appears to contain a credential; remove it before capture")
    for argument in argv:
        if any(pattern.search(argument) for pattern in SECRET_PATTERNS):
            raise ShipProofError("a command argument appears to contain a credential; pass secrets through the command's own environment instead")
    if root.is_symlink():
        raise ShipProofError("receipt root must not be a symbolic link")
    root = root.resolve()
    if not root.is_dir():
        raise ShipProofError(f"receipt root is not a directory: {root}")
    includes_tuple = validate_patterns(includes, "include")
    all_excludes = list(DEFAULT_EXCLUDES) + list(excludes)
    try:
        receipt_relative = receipt_path.resolve().relative_to(root).as_posix()
    except ValueError as exc:
        raise ShipProofError("receipt path must stay inside the receipt root") from exc
    all_excludes.append(receipt_relative)
    excludes_tuple = validate_patterns(all_excludes, "exclude")
    command = run_command(root, argv, timeout_seconds, max_output_bytes)
    artifacts = collect_artifacts(root, includes_tuple, excludes_tuple, max_files=max_files, max_bytes=max_bytes)
    git = git_state(root, [receipt_relative])
    body = receipt_body(root=root, claims=claims, command=command, includes=includes_tuple, excludes=excludes_tuple, artifacts=artifacts, git=git)
    receipt = finalize_receipt(body, hmac_key, key_id)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt_path.parent.resolve().relative_to(root)
    except ValueError as exc:
        raise ShipProofError("receipt parent resolved outside the receipt root") from exc
    with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(receipt, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return receipt


def load_receipt(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ShipProofError(f"cannot load Completion Receipt: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION or payload.get("artifact_name") != "Completion Receipt":
        raise ShipProofError("unsupported or invalid Completion Receipt")
    return payload


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def validate_receipt_body(body: dict[str, Any]) -> None:
    """Fail closed when a self-consistent receipt does not match the v1 contract."""

    tool = body.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "agent-shipproof" or tool.get("version") not in {"0.1.0", VERSION}:
        raise ShipProofError("Completion Receipt tool identity is invalid")
    expected_keys = {
        "schema_version", "tool", "artifact_name", "claim_boundary", "captured_at_utc",
        "root", "claims", "command", "selection", "artifacts", "git",
    }
    if tool.get("version") == VERSION:
        expected_keys.add("observed_evidence")
    if set(body) != expected_keys:
        raise ShipProofError("Completion Receipt body fields are invalid")
    if body.get("schema_version") != SCHEMA_VERSION or body.get("artifact_name") != "Completion Receipt":
        raise ShipProofError("Completion Receipt identity is invalid")
    if body.get("root") != "." or body.get("claim_boundary") != CLAIM_BOUNDARY:
        raise ShipProofError("Completion Receipt claim boundary is invalid")
    captured = body.get("captured_at_utc")
    try:
        parsed = datetime.fromisoformat(captured) if isinstance(captured, str) else None
    except ValueError as exc:
        raise ShipProofError("Completion Receipt capture time is invalid") from exc
    if parsed is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ShipProofError("Completion Receipt capture time must use UTC")

    claims = body.get("claims")
    if not isinstance(claims, list) or not claims:
        raise ShipProofError("Completion Receipt claims are invalid")
    for claim in claims:
        if not isinstance(claim, dict) or set(claim) != {"text", "status"}:
            raise ShipProofError("Completion Receipt claim entry is invalid")
        text = claim.get("text")
        if not isinstance(text, str) or not text.strip() or claim.get("status") != "declared_not_semantically_verified":
            raise ShipProofError("Completion Receipt claim boundary is invalid")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            raise ShipProofError("Completion Receipt claim contains a recognized credential shape")

    command = body.get("command")
    command_keys = {
        "argv_display", "argv_sha256", "shell", "exit_code", "timed_out",
        "output_limit_exceeded", "output_limit_bytes", "duration_ms", "stdout", "stderr",
    }
    if not isinstance(command, dict) or set(command) != command_keys:
        raise ShipProofError("Completion Receipt command fields are invalid")
    if not isinstance(command.get("argv_display"), list) or not command["argv_display"] or not all(isinstance(item, str) for item in command["argv_display"]):
        raise ShipProofError("Completion Receipt command argv is invalid")
    if any(pattern.search(item) for item in command["argv_display"] for pattern in SECRET_PATTERNS):
        raise ShipProofError("Completion Receipt command argv contains a recognized credential shape")
    if not _is_sha256(command.get("argv_sha256")) or command.get("shell") is not False:
        raise ShipProofError("Completion Receipt command identity is invalid")
    if not isinstance(command.get("exit_code"), int) or isinstance(command.get("exit_code"), bool):
        raise ShipProofError("Completion Receipt command exit is invalid")
    if not isinstance(command.get("timed_out"), bool) or not isinstance(command.get("output_limit_exceeded"), bool):
        raise ShipProofError("Completion Receipt command termination state is invalid")
    if command["timed_out"] and command["output_limit_exceeded"]:
        raise ShipProofError("Completion Receipt command has conflicting termination states")
    if command["timed_out"] and command["exit_code"] != 124:
        raise ShipProofError("Completion Receipt timeout exit is invalid")
    if command["output_limit_exceeded"] and command["exit_code"] != 125:
        raise ShipProofError("Completion Receipt output-limit exit is invalid")
    if not _is_nonnegative_int(command.get("duration_ms")) or not _is_nonnegative_int(command.get("output_limit_bytes")):
        raise ShipProofError("Completion Receipt command limits are invalid")
    for stream_name in ("stdout", "stderr"):
        stream = command.get(stream_name)
        if not isinstance(stream, dict) or set(stream) != {"bytes", "sha256", "excerpt"}:
            raise ShipProofError(f"Completion Receipt {stream_name} fields are invalid")
        if not _is_nonnegative_int(stream.get("bytes")) or not _is_sha256(stream.get("sha256")) or not isinstance(stream.get("excerpt"), str):
            raise ShipProofError(f"Completion Receipt {stream_name} evidence is invalid")
        if any(pattern.search(stream["excerpt"]) for pattern in SECRET_PATTERNS):
            raise ShipProofError(f"Completion Receipt {stream_name} contains a recognized credential shape")

    selection = body.get("selection")
    if not isinstance(selection, dict) or set(selection) != {"includes", "excludes", "symlinks_followed"} or selection.get("symlinks_followed") is not False:
        raise ShipProofError("Completion Receipt selection contract is invalid")
    if not isinstance(selection.get("includes"), list) or not isinstance(selection.get("excludes"), list):
        raise ShipProofError("Completion Receipt selection patterns are invalid")
    if list(validate_patterns(selection["includes"], "include")) != selection["includes"] or list(validate_patterns(selection["excludes"], "exclude")) != selection["excludes"]:
        raise ShipProofError("Completion Receipt selection patterns are not canonical")

    artifacts = body.get("artifacts")
    if not isinstance(artifacts, list):
        raise ShipProofError("Completion Receipt artifact manifest is invalid")
    paths: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"path", "bytes", "sha256"}:
            raise ShipProofError("Completion Receipt artifact entry is invalid")
        path = artifact.get("path")
        if not isinstance(path, str) or not path or any(character in path for character in "*?["):
            raise ShipProofError("Completion Receipt artifact path is invalid")
        if list(validate_patterns([path], "include")) != [path]:
            raise ShipProofError("Completion Receipt artifact path is not canonical")
        if not _is_nonnegative_int(artifact.get("bytes")) or not _is_sha256(artifact.get("sha256")):
            raise ShipProofError("Completion Receipt artifact evidence is invalid")
        paths.append(path)
    if paths != sorted(set(paths), key=lambda item: (item.casefold(), item)):
        raise ShipProofError("Completion Receipt artifact paths are duplicated or unsorted")

    git = body.get("git")
    if not isinstance(git, dict) or not isinstance(git.get("available"), bool):
        raise ShipProofError("Completion Receipt Git state is invalid")
    if git["available"] is False:
        if set(git) != {"available"}:
            raise ShipProofError("Completion Receipt unavailable Git state is invalid")
    else:
        expected_git = {"available", "head", "branch", "status_sha256", "dirty_entry_count", "network_used"}
        if set(git) != expected_git or git.get("network_used") is not False:
            raise ShipProofError("Completion Receipt Git fields are invalid")
        if not isinstance(git.get("head"), str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", git["head"]) is None:
            raise ShipProofError("Completion Receipt Git HEAD is invalid")
        if not isinstance(git.get("branch"), str) or not git["branch"] or not _is_sha256(git.get("status_sha256")) or not _is_nonnegative_int(git.get("dirty_entry_count")):
            raise ShipProofError("Completion Receipt Git evidence is invalid")

    if tool.get("version") == VERSION:
        envelope = body.get("observed_evidence")
        envelope_keys = {"contract", "command", "artifacts", "git", "environment", "omissions", "provenance", "claim_boundary"}
        if not isinstance(envelope, dict) or set(envelope) != envelope_keys or envelope.get("contract") != "observed-evidence-envelope-v1":
            raise ShipProofError("Observed Evidence Envelope fields are invalid")
        expected_command = {
            "argv_sha256": command["argv_sha256"],
            "exit_code": command["exit_code"],
            "timed_out": command["timed_out"],
            "output_limit_exceeded": command["output_limit_exceeded"],
            "stdout_sha256": command["stdout"]["sha256"],
            "stderr_sha256": command["stderr"]["sha256"],
        }
        if envelope.get("command") != expected_command or envelope.get("artifacts") != artifacts or envelope.get("git") != git:
            raise ShipProofError("Observed Evidence Envelope does not match receipt observations")
        environment = envelope.get("environment")
        if not isinstance(environment, dict) or set(environment) != {"cwd", "os_family", "python", "environment_variables_captured"}:
            raise ShipProofError("Observed Evidence Envelope environment fields are invalid")
        if environment.get("cwd") != "." or environment.get("os_family") not in {"nt", "posix"} or re.fullmatch(r"\d+\.\d+", str(environment.get("python", ""))) is None or environment.get("environment_variables_captured") is not False:
            raise ShipProofError("Observed Evidence Envelope environment evidence is invalid")
        omissions = envelope.get("omissions")
        if not isinstance(omissions, list) or omissions != sorted(omissions) or not omissions or not all(isinstance(item, str) and item for item in omissions):
            raise ShipProofError("Observed Evidence Envelope omissions are invalid")
        provenance = envelope.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != {"root", "selection_sha256", "artifact_manifest_sha256", "git_observation_sha256"}:
            raise ShipProofError("Observed Evidence Envelope provenance fields are invalid")
        if provenance != {
            "root": ".",
            "selection_sha256": sha256_bytes(canonical_bytes(selection)),
            "artifact_manifest_sha256": sha256_bytes(canonical_bytes(artifacts)),
            "git_observation_sha256": sha256_bytes(canonical_bytes(git)),
        }:
            raise ShipProofError("Observed Evidence Envelope provenance does not match receipt evidence")
        if envelope.get("claim_boundary") != "Records selected observations and explicit omissions only; it does not prove correctness, security, identity, authorization, certification, or sandboxing.":
            raise ShipProofError("Observed Evidence Envelope claim boundary is invalid")


def verify_receipt(root: Path, receipt: dict[str, Any], hmac_key: bytes | None = None) -> dict[str, Any]:
    """Verify receipt integrity and report file/Git drift without revealing file contents."""

    integrity = receipt.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256", "authentication"}:
        raise ShipProofError("Completion Receipt integrity block is invalid")
    body = {key: value for key, value in receipt.items() if key != "integrity"}
    payload = canonical_bytes(body)
    expected_digest = sha256_bytes(payload)
    integrity_ok = hmac.compare_digest(str(integrity.get("payload_sha256", "")), expected_digest)
    authentication = integrity.get("authentication")
    authentication_result: dict[str, Any] = {"present": authentication is not None, "status": "not_present"}
    if authentication is not None:
        expected_auth_keys = {"type", "key_id", "tag", "claim_boundary"}
        if not isinstance(authentication, dict) or set(authentication) != expected_auth_keys or authentication.get("type") != "pilot_hmac_sha256":
            raise ShipProofError("unsupported authentication block")
        if hmac_key is None:
            raise ShipProofError("receipt has pilot HMAC authentication; provide --hmac-key-env")
        key_id = authentication.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ShipProofError("pilot HMAC key_id is invalid")
        if authentication.get("claim_boundary") != HMAC_BOUNDARY:
            raise ShipProofError("pilot HMAC claim boundary is invalid")
        if not _is_sha256(authentication.get("tag")):
            raise ShipProofError("pilot HMAC tag is invalid")
        authentication_material = b"agent-shipproof-pilot-hmac-v1\x00" + key_id.encode("utf-8") + b"\x00" + payload
        expected_tag = hmac.new(hmac_key, authentication_material, hashlib.sha256).hexdigest()
        authentication_result = {
            "present": True,
            "status": "pass" if hmac.compare_digest(str(authentication.get("tag", "")), expected_tag) else "fail",
            "key_id": key_id,
            "claim_boundary": authentication.get("claim_boundary"),
        }
    elif hmac_key is not None:
        raise ShipProofError("an HMAC key was supplied but the receipt is unsigned; refusing authentication downgrade")
    if not integrity_ok or authentication_result["status"] == "fail":
        return {
            "status": "drift",
            "claim_boundary": body.get("claim_boundary"),
            "receipt_integrity": "pass" if integrity_ok else "fail",
            "authentication": authentication_result,
            "artifacts": {"status": "not_checked_untrusted_receipt", "added": [], "removed": [], "changed": []},
            "git": {"status": "not_checked_untrusted_receipt"},
        }
    validate_receipt_body(body)
    selection = body.get("selection")
    if not isinstance(selection, dict) or set(selection) != {"includes", "excludes", "symlinks_followed"} or selection.get("symlinks_followed") is not False:
        raise ShipProofError("Completion Receipt selection contract is invalid")
    stored_list = body.get("artifacts")
    if not isinstance(stored_list, list):
        raise ShipProofError("Completion Receipt artifact manifest is invalid")
    stored = {str(item["path"]): item for item in stored_list if isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}}
    if len(stored) != len(stored_list):
        raise ShipProofError("Completion Receipt artifact entries are invalid or duplicated")
    current_list = collect_artifacts(root, selection["includes"], selection["excludes"])
    current = {item.path: asdict(item) for item in current_list}
    added = sorted(set(current) - set(stored))
    removed = sorted(set(stored) - set(current))
    changed = sorted(path for path in set(stored) & set(current) if stored[path] != current[path])
    artifact_status = "pass" if not added and not removed and not changed else "drift"
    stored_git = body.get("git")
    if not isinstance(stored_git, dict) or "available" not in stored_git:
        raise ShipProofError("Completion Receipt Git state is invalid")
    ignored = [item for item in selection["excludes"] if "*" not in item and "?" not in item and "[" not in item]
    current_git = git_state(root, ignored)
    git_changes: list[str] = []
    for field in ("available", "head", "branch", "status_sha256", "dirty_entry_count"):
        if stored_git.get(field) != current_git.get(field):
            git_changes.append(field)
    git_status = "pass" if not git_changes else "drift"
    overall = "pass" if artifact_status == "pass" and git_status == "pass" else "drift"
    return {
        "status": overall,
        "claim_boundary": body.get("claim_boundary"),
        "receipt_integrity": "pass",
        "authentication": authentication_result,
        "artifacts": {"status": artifact_status, "added": added, "removed": removed, "changed": changed},
        "git": {"status": git_status, "changed_fields": git_changes},
    }


def read_hmac_key(env_name: str | None) -> bytes | None:
    if not env_name:
        return None
    value = os.environ.get(env_name)
    if value is None or not value:
        raise ShipProofError(f"HMAC environment variable is missing or empty: {env_name}")
    return value.encode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"agent-shipproof {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run an explicit command and create a new Completion Receipt.")
    run.add_argument("--root", type=Path, default=Path("."))
    run.add_argument("--receipt", type=Path, required=True)
    run.add_argument("--claim", action="append", required=True)
    run.add_argument("--include", action="append", required=True)
    run.add_argument("--exclude", action="append", default=[])
    run.add_argument("--timeout", type=int, default=600, help="Seconds before the command is killed; timeout is recorded as 124 on every platform.")
    run.add_argument("--max-files", type=int, default=10000)
    run.add_argument("--max-bytes", type=int, default=100_000_000)
    run.add_argument("--max-output-bytes", type=int, default=10_000_000, help="Combined stdout/stderr capture ceiling; overage is recorded as exit 125.")
    run.add_argument("--hmac-key-env")
    run.add_argument("--hmac-key-id")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    verify = sub.add_parser("verify", help="Verify a Completion Receipt and report path-level drift.")
    verify.add_argument("receipt", type=Path)
    verify.add_argument("--root", type=Path, default=Path("."))
    verify.add_argument("--hmac-key-env")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        key = read_hmac_key(args.hmac_key_env)
        if args.command == "run":
            command = list(args.argv)
            if command and command[0] == "--":
                command = command[1:]
            receipt = create_receipt(
                args.root, args.receipt, args.claim, command, args.include, args.exclude,
                timeout_seconds=args.timeout, max_files=args.max_files, max_bytes=args.max_bytes,
                max_output_bytes=args.max_output_bytes,
                hmac_key=key, key_id=args.hmac_key_id,
            )
            print(json.dumps({
                "status": "captured",
                "artifact": "Completion Receipt",
                "receipt": args.receipt.as_posix(),
                "payload_sha256": receipt["integrity"]["payload_sha256"],
                "command_exit_code": receipt["command"]["exit_code"],
                "claim_boundary": receipt["claim_boundary"],
            }, indent=2))
            return EXIT_PASS if int(receipt["command"]["exit_code"]) == 0 else EXIT_DRIFT
        receipt = load_receipt(args.receipt)
        result = verify_receipt(args.root, receipt, key)
        print(json.dumps(result, indent=2))
        return EXIT_PASS if result["status"] == "pass" else EXIT_DRIFT
    except (ShipProofError, OSError, KeyError, TypeError) as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
