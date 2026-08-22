"""Compute the non-self-referential Agent ShipProof product revision."""
from __future__ import annotations

import hashlib
from pathlib import Path

EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "validation",
    "venv",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def product_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.suffix == ".pyc":
            continue
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def product_revision(root: Path) -> tuple[str, list[dict[str, object]]]:
    records = bytearray()
    manifest: list[dict[str, object]] = []
    for path in product_files(root):
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest = file_sha256(path)
        records.extend(f"{relative}\t{size}\t{digest}\n".encode())
        manifest.append({"path": relative, "bytes": size, "sha256": digest})
    return hashlib.sha256(records).hexdigest(), manifest
