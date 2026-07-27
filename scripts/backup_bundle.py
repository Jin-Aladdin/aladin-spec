#!/usr/bin/env python3
"""Create and verify a self-contained git bundle of the repository.

A bundle is an entire repository in one file: history, branches and tags.
``git clone backup.bundle`` reconstructs the repository from it with no
network and no hosting provider, which is what makes it a usable backup
rather than a copy that only works while GitHub does (ADR-0005).

A backup nobody restored is a belief, not a backup, so this module always
verifies what it produced: the bundle is checked, cloned into a temporary
directory, and the restored refs are compared against the source.

Every git invocation uses a fixed argument list. Nothing here is derived
from repository content, and no shell is involved.

Usage::

    python scripts/backup_bundle.py --out dist/backup.bundle
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

BUNDLE_VERSION = "0.1.0"
GIT_TIMEOUT_SECONDS = 600


class BackupError(RuntimeError):
    """The backup could not be produced or could not be verified."""


@dataclass(frozen=True)
class BundleResult:
    path: Path
    sha256: str
    size_bytes: int
    ref_count: int
    tag_count: int
    commit_count: int

    def summary(self) -> str:
        return (
            f"{self.path.name}: {self.size_bytes} bytes, {self.ref_count} refs, "
            f"{self.tag_count} tags, {self.commit_count} commits"
        )


def _git(*arguments: str, cwd: Path) -> str:
    """Run one git command with a fixed argument list."""
    completed = subprocess.run(
        ["git", *arguments],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise BackupError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed.stdout


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _refs(repository: Path) -> dict[str, str]:
    """Return every ref and the object it points at."""
    output = _git("show-ref", "--head", cwd=repository)
    refs = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        object_id, _, name = line.partition(" ")
        refs[name.strip()] = object_id.strip()
    return refs


def create_bundle(out_path: Path, repository: Path = REPOSITORY_ROOT) -> BundleResult:
    """Bundle the whole repository, then prove the bundle is usable."""
    if not (repository / ".git").exists():
        raise BackupError(f"{repository} is not a git repository")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    # --all covers branches and remote-tracking refs; --tags is explicit
    # because a backup without tags cannot reproduce a release.
    _git("bundle", "create", str(out_path), "--all", "--tags", cwd=repository)

    if not out_path.is_file() or out_path.stat().st_size == 0:
        raise BackupError("git produced no bundle")

    verify_bundle(out_path, repository=repository)

    listing = _git("bundle", "list-heads", str(out_path), cwd=repository)
    refs = [line for line in listing.splitlines() if line.strip()]
    tags = [line for line in refs if "refs/tags/" in line]
    commits = _git("rev-list", "--all", "--count", cwd=repository).strip()

    return BundleResult(
        path=out_path,
        sha256=_sha256(out_path),
        size_bytes=out_path.stat().st_size,
        ref_count=len(refs),
        tag_count=len(tags),
        commit_count=int(commits or 0),
    )


def verify_bundle(bundle: Path, repository: Path = REPOSITORY_ROOT) -> None:
    """Check the bundle and confirm it restores.

    ``git bundle verify`` only checks that the prerequisites are satisfiable.
    Cloning is what proves the archive is actually usable, so both run.
    """
    if not bundle.is_file():
        raise BackupError(f"no bundle at {bundle}")

    _git("bundle", "verify", str(bundle), cwd=repository)

    restored = Path(tempfile.mkdtemp(prefix="aladdin-restore-"))
    try:
        target = restored / "clone"
        _git("clone", "--quiet", "--bare", str(bundle), str(target), cwd=repository)

        source_tags = {
            name for name in _refs(repository) if name.startswith("refs/tags/")
        }
        restored_tags = {
            name for name in _refs(target) if name.startswith("refs/tags/")
        }
        missing = source_tags - restored_tags
        if missing:
            raise BackupError(
                "restored clone is missing tags: " + ", ".join(sorted(missing))
            )

        head = _git("rev-parse", "HEAD", cwd=repository).strip()
        restored_head = _git("rev-parse", "HEAD", cwd=target).strip()
        if head != restored_head:
            raise BackupError(
                f"restored HEAD {restored_head} does not match source HEAD {head}"
            )
    finally:
        shutil.rmtree(restored, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--checksum-file",
        type=Path,
        default=None,
        help="write a sha256sum-compatible line for the bundle",
    )
    args = parser.parse_args(argv)

    try:
        result = create_bundle(args.out, repository=args.repository)
    except BackupError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1

    if args.checksum_file is not None:
        args.checksum_file.parent.mkdir(parents=True, exist_ok=True)
        args.checksum_file.write_text(
            f"{result.sha256}  {result.path.name}\n", encoding="utf-8", newline="\n"
        )

    print(result.summary())
    print(f"sha256: {result.sha256}")
    print("verified: the bundle was cloned and its tags and HEAD match the source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
