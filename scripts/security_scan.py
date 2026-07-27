#!/usr/bin/env python3
"""Security gate for Aladdin Knowledge Pack content.

ADR-0003 makes a Knowledge Pack declarative data. This gate enforces that
property on the content side: a pack directory must not carry executable
files, undeclared binaries, symbolic links, oversized files or paths that
escape the pack boundary.

The scan reads files. It never executes them, never imports them and never
resolves a remote reference.

Usage::

    python scripts/security_scan.py
    python scripts/security_scan.py --pack examples/minimal-pack
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

MANIFEST_FILENAME = "aladdin-pack.yml"

#: File extensions that must never appear inside a pack directory.
EXECUTABLE_SUFFIXES = frozenset(
    {
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".com",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".py",
        ".pyc",
        ".pyo",
        ".rb",
        ".pl",
        ".php",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".jar",
        ".class",
        ".wasm",
        ".scpt",
        ".vbs",
        ".msi",
        ".apk",
        ".deb",
        ".rpm",
    }
)

#: Extensions a declarative pack may carry.
DECLARATIVE_SUFFIXES = frozenset(
    {".json", ".jsonl", ".yml", ".yaml", ".toml", ".csv", ".tsv", ".txt", ".adoc", ".md"}
)

#: Magic bytes that indicate an executable or archive payload.
BINARY_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows executable"),
    (b"\xca\xfe\xba\xbe", "Java class or Mach-O fat binary"),
    (b"\xfe\xed\xfa", "Mach-O binary"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"BZh", "bzip2 archive"),
    (b"\xfd7zXZ", "xz archive"),
    (b"\x00asm", "WebAssembly module"),
)

#: Content that must never be committed, checked as a coarse pre-filter.
SECRET_MARKERS: tuple[tuple[str, str], ...] = (
    ("-----BEGIN RSA PRIVATE KEY", "private key"),
    ("-----BEGIN OPENSSH PRIVATE KEY", "private key"),
    ("-----BEGIN PGP PRIVATE KEY", "private key"),
    ("-----BEGIN EC PRIVATE KEY", "private key"),
    ("ghp_", "GitHub personal access token"),
    ("github_pat_", "GitHub fine-grained token"),
    ("AKIA", "AWS access key id"),
    ("xoxb-", "Slack bot token"),
    ("sk-ant-", "Anthropic API key"),
)

DEFAULT_MAX_FILE_BYTES = 5_000_000
DEFAULT_MAX_FILES = 5_000

#: Directories that belong to the working copy or the build environment rather
#: than to the pack. They are never part of a published artifact, and scanning
#: them reports the tooling instead of the content: a git checkout alone
#: contributes hooks, packed objects and config files that are not knowledge
#: and were never claimed to be.
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".github",
        ".candidate",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        "dist",
        "quarantine",
    }
)


@dataclass(frozen=True)
class Finding:
    path: str
    message: str
    line: int | None = None

    def __str__(self) -> str:
        location = self.path if self.line is None else f"{self.path}:{self.line}"
        return f"{location}: {self.message}"


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def scan_pack(
    pack_dir: Path,
    root: Path = REPOSITORY_ROOT,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
) -> list[Finding]:
    """Scan one pack directory for content that violates ADR-0003."""
    findings: list[Finding] = []
    pack_root = pack_dir.resolve()
    file_count = 0

    for path in sorted(pack_dir.rglob("*")):
        try:
            relative_parts = path.relative_to(pack_dir).parts
        except ValueError:
            relative_parts = path.parts
        if any(part in IGNORED_DIRECTORIES for part in relative_parts):
            continue

        rel = _relative(path, root)

        if path.is_symlink():
            findings.append(Finding(rel, "symbolic links are not allowed inside a pack"))
            continue

        if not path.is_file():
            continue

        file_count += 1
        if not path.resolve().is_relative_to(pack_root):
            findings.append(Finding(rel, "file resolves outside the pack directory"))
            continue

        suffix = path.suffix.lower()
        if suffix in EXECUTABLE_SUFFIXES:
            findings.append(
                Finding(rel, f"executable file type {suffix!r} is not allowed inside a pack")
            )
        elif suffix not in DECLARATIVE_SUFFIXES:
            findings.append(
                Finding(rel, f"undeclared file type {suffix or '(none)'!r} inside a pack")
            )

        size = path.stat().st_size
        if size > max_file_bytes:
            findings.append(Finding(rel, f"file is {size} bytes, above the {max_file_bytes} limit"))

        head = path.open("rb").read(8)
        for signature, description in BINARY_SIGNATURES:
            if head.startswith(signature):
                findings.append(Finding(rel, f"binary content detected: {description}"))
                break

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(rel, "file is not valid UTF-8 text"))
            continue

        if "\x00" in text:
            findings.append(Finding(rel, "file contains NUL bytes"))

        for number, line in enumerate(text.splitlines(), start=1):
            for marker, description in SECRET_MARKERS:
                if marker in line:
                    findings.append(Finding(rel, f"possible {description} committed", line=number))

    if file_count > max_files:
        findings.append(
            Finding(_relative(pack_dir, root), f"pack contains {file_count} files, above the {max_files} limit")
        )

    return findings


def discover_packs(root: Path) -> list[Path]:
    examples = root / "examples"
    if not examples.is_dir():
        return []
    return sorted(p.parent for p in examples.glob(f"*/{MANIFEST_FILENAME}"))


def scan_repository(root: Path = REPOSITORY_ROOT, packs: list[Path] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for pack_dir in packs if packs is not None else discover_packs(root):
        findings.extend(scan_pack(pack_dir, root))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--pack", type=Path, action="append", dest="packs", default=None)
    args = parser.parse_args(argv)

    findings = scan_repository(args.root, args.packs)
    for finding in findings:
        print(finding, file=sys.stderr)

    if findings:
        print(f"\n{len(findings)} security problem(s) found.", file=sys.stderr)
        return 1

    print("Security scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
