#!/usr/bin/env python3
"""Documentation gate for the Aladdin specification repository.

The repository documents itself in AsciiDoc. Two defects have already
occurred in practice and both are silent: a listing block that lost its
``----`` delimiters renders as prose and destroys the indentation of the
code it contains, and a quote block written with ``---`` renders as a
horizontal rule.

This gate fails the build when either happens again, and when a
documentation file is added in a format the project does not use.

Usage::

    python scripts/check_docs.py
    python scripts/check_docs.py --root .
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRECTORIES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}

#: Documentation is written in AsciiDoc. Markdown files are only tolerated
#: where a platform requires them by filename.
ALLOWED_MARKDOWN = {
    ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/config.md",
}

BLOCK_DELIMITER = "----"
QUOTE_DELIMITER = "____"

#: Minimum delimiter length in AsciiDoc. A block ends at the first delimiter
#: of its own length, so a nested example must use a longer outer delimiter.
MINIMUM_DELIMITER_LENGTH = 4


def delimiter_kind(line: str) -> tuple[str, int] | None:
    """Return ``(kind, length)`` when ``line`` is a block delimiter."""
    stripped = line.rstrip()
    if len(stripped) < MINIMUM_DELIMITER_LENGTH:
        return None
    if stripped == "-" * len(stripped):
        return ("source", len(stripped))
    if stripped == "_" * len(stripped):
        return ("quote", len(stripped))
    return None


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


def iter_documents(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRECTORIES for part in path.parts):
            continue
        yield path


def check_asciidoc(path: Path, root: Path) -> list[Finding]:
    """Verify that every block attribute line opens and closes a real block."""
    rel = _relative(path, root)
    findings: list[Finding] = []
    lines = path.read_text(encoding="utf-8").splitlines()

    # The open block, as (kind, delimiter length). A block ends only at a
    # delimiter of its own length, so a longer outer delimiter can wrap an
    # example that itself contains a delimiter.
    open_block: tuple[str, int] | None = None
    pending: tuple[int, str] | None = None

    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        delimiter = delimiter_kind(line)

        if open_block is not None:
            if delimiter is not None and delimiter == open_block:
                open_block = None
            continue

        if pending is not None:
            opener, kind = pending
            pending = None
            expected = BLOCK_DELIMITER if kind == "source" else QUOTE_DELIMITER
            if delimiter is not None and delimiter[0] == kind:
                open_block = delimiter
                continue
            findings.append(
                Finding(
                    rel,
                    f"{kind} block is not delimited by {expected!r}; "
                    f"its content will render as prose",
                    line=opener,
                )
            )
            # fall through so this line is still examined below

        if line.startswith("[source") and line.endswith("]"):
            pending = (number, "source")
        elif line == "[quote]":
            pending = (number, "quote")
        elif delimiter is not None:
            open_block = delimiter

    if pending is not None:
        opener, kind = pending
        expected = BLOCK_DELIMITER if kind == "source" else QUOTE_DELIMITER
        findings.append(
            Finding(rel, f"{kind} block at end of file is not delimited by {expected!r}", line=opener)
        )
    if open_block is not None:
        findings.append(Finding(rel, f"unclosed {'-' if open_block[0] == 'source' else '_'} block"))

    if not lines:
        findings.append(Finding(rel, "documentation file is empty"))
    elif not lines[0].startswith("= "):
        findings.append(Finding(rel, "AsciiDoc file should start with a level 0 title", line=1))

    return findings


def check_format_policy(path: Path, root: Path) -> list[Finding]:
    rel = _relative(path, root)
    if path.suffix.lower() == ".md" and rel not in ALLOWED_MARKDOWN:
        return [
            Finding(
                rel,
                "documentation uses AsciiDoc; rename this file to .adoc or add it to "
                "the allowed platform templates",
            )
        ]
    return []


def check_documentation(root: Path = REPOSITORY_ROOT) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_documents(root):
        findings.extend(check_format_policy(path, root))
        if path.suffix.lower() == ".adoc":
            findings.extend(check_asciidoc(path, root))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    args = parser.parse_args(argv)

    findings = check_documentation(args.root)
    for finding in findings:
        print(finding, file=sys.stderr)

    if findings:
        print(f"\n{len(findings)} documentation problem(s) found.", file=sys.stderr)
        return 1

    print("Documentation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
