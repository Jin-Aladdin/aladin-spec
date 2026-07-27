#!/usr/bin/env python3
"""Deterministic artifact builder for Aladdin Knowledge Packs.

A published artifact must be reproducible: the same input tree must produce
the same bytes, so a consumer can verify a checksum independently. This
builder therefore fixes every source of nondeterminism a ZIP archive would
otherwise pick up: entry order, timestamps, permissions and compression
level.

The builder reads pack files. It never executes them.

Usage::

    python scripts/build_artifact.py --pack examples/minimal-pack --out dist
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

MANIFEST_FILENAME = "aladdin-pack.yml"
BUILDER_VERSION = "0.1.0"

#: Fixed archive timestamp. A build must not depend on when it ran.
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

#: Directories that belong to the source repository, not to the artifact.
#: Build tooling is permitted in a repository (ADR-0003) and must never reach
#: a consumer, so it is excluded here rather than forbidden there.
EXCLUDED_DIRECTORIES = {
    ".candidate",
    "quarantine",
    "upstream",
    "__pycache__",
    "scripts",
    "tools",
    ".github",
    ".git",
}

#: Repository scaffolding that configures the repository rather than
#: describing the pack. Licence and notice files are deliberately absent:
#: those state the terms the content is published under and belong in the
#: artifact.
EXCLUDED_FILES = {
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".editorconfig",
    ".mailmap",
    "CODEOWNERS",
}


@dataclass(frozen=True)
class BuildResult:
    pack_id: str
    version: str
    archive: Path
    checksum: str
    file_count: int
    provenance: Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_files(pack_dir: Path) -> list[Path]:
    """Return the artifact payload in a stable, platform-independent order."""
    files = []
    for path in pack_dir.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(pack_dir)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if relative.name in EXCLUDED_FILES:
            continue
        files.append(relative)
    return sorted(files, key=lambda p: p.as_posix())


def build(
    pack_dir: Path,
    out_dir: Path,
    *,
    source_commit: str = "",
    validator_version: str = "",
    built_at: str = "",
) -> BuildResult:
    """Build one immutable artifact plus its checksum and provenance files."""
    manifest_path = pack_dir / MANIFEST_FILENAME
    if not manifest_path.is_file():
        raise FileNotFoundError(f"no {MANIFEST_FILENAME} in {pack_dir}")

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    pack = manifest.get("pack") or {}
    pack_id = pack.get("id")
    version = pack.get("version")
    if not pack_id or not version:
        raise ValueError("manifest is missing pack.id or pack.version")

    files = collect_files(pack_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = out_dir / f"{pack_id}-{version}.zip"

    entries: list[dict] = []
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            data = (pack_dir / relative).read_bytes()
            info = zipfile.ZipInfo(relative.as_posix(), date_time=FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, data)
            entries.append(
                {
                    "path": relative.as_posix(),
                    "sha256": _sha256(data),
                    "size_bytes": len(data),
                }
            )

    archive_bytes = archive_path.read_bytes()
    checksum = _sha256(archive_bytes)

    checksum_path = out_dir / f"{archive_path.name}.sha256"
    checksum_path.write_text(f"{checksum}  {archive_path.name}\n", encoding="utf-8", newline="\n")

    build_record: dict = {
        "builder": f"build_artifact.py {BUILDER_VERSION}",
        # Reproducibility is only a verifiable claim when the source commit is
        # recorded: without it, nobody can rebuild the same tree and compare.
        "reproducible": bool(source_commit),
    }
    if source_commit:
        build_record["source_commit"] = source_commit
    if validator_version:
        build_record["validator_version"] = validator_version
    if built_at:
        build_record["built_at"] = built_at

    provenance = {
        "provenance_version": "0.1.0",
        "pack_id": pack_id,
        "version": version,
        "specification": manifest.get("specification", {}),
        "artifact": {
            "name": archive_path.name,
            "media_type": "application/zip",
            "sha256": checksum,
            "size_bytes": len(archive_bytes),
            "file_count": len(entries),
        },
        "files": entries,
        "build": build_record,
        "licenses": manifest.get("licenses", {}),
        "lifecycle": manifest.get("lifecycle", {}),
    }
    provenance_path = out_dir / f"{pack_id}-{version}.provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    return BuildResult(
        pack_id=pack_id,
        version=version,
        archive=archive_path,
        checksum=checksum,
        file_count=len(entries),
        provenance=provenance_path,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=REPOSITORY_ROOT / "dist")
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--validator-version", default="")
    parser.add_argument("--built-at", default="", help="build timestamp recorded in provenance")
    args = parser.parse_args(argv)

    try:
        result = build(
            args.pack,
            args.out,
            source_commit=args.source_commit,
            validator_version=args.validator_version,
            built_at=args.built_at,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1

    print(f"pack:       {result.pack_id} {result.version}")
    print(f"archive:    {result.archive}")
    print(f"sha256:     {result.checksum}")
    print(f"files:      {result.file_count}")
    print(f"provenance: {result.provenance}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
