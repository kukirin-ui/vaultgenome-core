# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The base model's identity: the SHA-256 of every file it loads from.

The genome names the base model by content, not by a hub name that can be
re-pointed. A destination refuses to load a base whose files do not hash to
the manifest.
"""

import hashlib
import os

# Files a model directory may hold that do not affect the model's
# behaviour; hub caches and editors leave them around.
_IGNORED = {".gitattributes", "README.md", "LICENSE", "LICENSE.txt", ".DS_Store"}


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def build(base_dir: str) -> dict:
    """Hash every regular file under base_dir (following the symlinks hub
    caches use for blobs), keyed by forward-slash relative path."""
    files = {}
    for root, dirs, names in os.walk(base_dir):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(names):
            if name in _IGNORED or name.startswith("."):
                continue
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            rel = os.path.relpath(path, base_dir).replace(os.sep, "/")
            files[rel] = _hash_file(path)
    if not files:
        raise ValueError(f"{base_dir} holds no model files")
    return {"files": files, "digest": tree_digest(files)}


def tree_digest(files: dict) -> str:
    """SHA-256 over the sorted "<path> <sha256 hex>" lines — the same shape
    as the Go side's tree digest."""
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(f"{path} {files[path].removeprefix('sha256:')}\n".encode())
    return "sha256:" + h.hexdigest()


def verify(base_dir: str, manifest: dict) -> None:
    """Refuse a base directory that is not exactly the manifest's files."""
    got = build(base_dir)["files"]
    want = manifest["files"]
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    changed = sorted(p for p in set(want) & set(got) if want[p] != got[p])
    if missing or extra or changed:
        raise ValueError(
            "base model does not match the genome's manifest"
            + (f"; missing {missing[:3]}" if missing else "")
            + (f"; unexpected {extra[:3]}" if extra else "")
            + (f"; different {changed[:3]}" if changed else "")
        )
    if tree_digest(got) != manifest["digest"]:  # pragma: no cover - implied by the above
        raise ValueError("base model digest mismatch")
