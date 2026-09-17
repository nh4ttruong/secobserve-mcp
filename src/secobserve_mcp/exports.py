"""Write file-returning endpoints (Excel, CSV, JSON, YAML) to disk.

Callers supply a bare filename, never a path: the file always lands in the
configured export directory, so a crafted name cannot escape it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .config import get_config

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

EXTENSIONS = (
    ("excel", ".xlsx"),
    ("xlsx", ".xlsx"),
    ("csv", ".csv"),
    ("codecharta", ".csv"),
    ("yaml", ".yaml"),
    ("sbom_utility", ".json"),
    ("json", ".json"),
)


def extension_for(action: str) -> str:
    for marker, extension in EXTENSIONS:
        if marker in action:
            return extension
    return ".bin"


def safe_basename(name: str) -> str:
    """Reduce a caller-supplied name to a single safe path segment."""
    stem = SAFE_NAME.sub("-", os.path.basename(name)).strip("-.")
    return stem or "export"


def write_export(base_name: str, action: str, content: bytes) -> str:
    """Write export bytes into the export directory and describe where they went.

    Args:
        base_name: Caller-supplied name; directories and unsafe characters are stripped.
        action: Action name, used to pick the file extension.
        content: Raw response bytes.

    Returns:
        str: A one-line report with the absolute path and the number of bytes written.
    """
    directory = Path(get_config().export_dir)
    directory.mkdir(parents=True, exist_ok=True)

    stem = safe_basename(base_name)
    extension = extension_for(action)
    target = directory / (stem if stem.endswith(extension) else f"{stem}{extension}")
    target.write_bytes(content)

    if not content:
        return f"Wrote an empty file to {target} -- the export matched no records."
    return f"Wrote {len(content)} bytes to {target}"


MAX_UPLOAD_BYTES = 64 * 1024 * 1024


def read_upload(path: str) -> tuple[str, bytes]:
    """Read a local file for upload, confined to the configured import directory.

    Confinement matters because scan reports are third-party data: without it, a
    crafted instruction inside a report could talk an agent into uploading an
    unrelated local file to SecObserve.

    Args:
        path: Path to the file, absolute or relative to the import directory.

    Returns:
        tuple[str, bytes]: The file's base name and its contents.

    Raises:
        ValueError: if the file is outside the import directory, missing, not a
            regular file, empty, or larger than 64 MiB.
    """
    root = Path(get_config().import_dir).resolve()
    candidate = Path(path)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()

    if root != resolved and root not in resolved.parents:
        raise ValueError(
            f"Refusing to read {resolved}: uploads are confined to {root}. "
            "Move the file there, or set SECOBSERVE_IMPORT_DIR to the directory holding your scan reports."
        )
    if not resolved.exists():
        raise ValueError(f"No such file: {resolved}")
    if not resolved.is_file():
        raise ValueError(f"Not a regular file: {resolved}")

    size = resolved.stat().st_size
    if size == 0:
        raise ValueError(f"{resolved} is empty; there is nothing to import.")
    if size > MAX_UPLOAD_BYTES:
        raise ValueError(f"{resolved} is {size} bytes, over the {MAX_UPLOAD_BYTES} byte upload limit.")

    return resolved.name, resolved.read_bytes()
