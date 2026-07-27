"""Tests for the repository backup bundle.

A backup nobody restored is a belief. Every test here restores something.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import backup_bundle  # noqa: E402


def git(*arguments: str, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=str(cwd), capture_output=True, text=True, check=True
    )
    return completed.stdout


@pytest.fixture(scope="module")
def source_repository(tmp_path_factory) -> Path:
    """A small repository with a branch and a tag, built from scratch.

    Using a purpose-built repository rather than this one keeps the test
    independent of the checkout depth CI happens to use.
    """
    repository = tmp_path_factory.mktemp("source")
    git("init", "--quiet", "--initial-branch", "main", cwd=repository)
    git("config", "user.email", "test@example.org", cwd=repository)
    git("config", "user.name", "Test", cwd=repository)

    (repository / "first.txt").write_text("one\n", encoding="utf-8")
    git("add", "first.txt", cwd=repository)
    git("commit", "--quiet", "-m", "first", cwd=repository)
    git("tag", "-a", "v0.1.0", "-m", "release", cwd=repository)

    git("checkout", "--quiet", "-b", "side", cwd=repository)
    (repository / "second.txt").write_text("two\n", encoding="utf-8")
    git("add", "second.txt", cwd=repository)
    git("commit", "--quiet", "-m", "second", cwd=repository)
    git("checkout", "--quiet", "main", cwd=repository)

    return repository


@pytest.fixture
def bundle(tmp_path, source_repository) -> backup_bundle.BundleResult:
    return backup_bundle.create_bundle(tmp_path / "backup.bundle", repository=source_repository)


def test_bundle_is_produced(bundle):
    assert bundle.path.is_file()
    assert bundle.size_bytes > 0
    assert len(bundle.sha256) == 64


def test_bundle_carries_tags(bundle):
    assert bundle.tag_count >= 1, "a backup without tags cannot reproduce a release"


def test_bundle_carries_every_commit(bundle):
    assert bundle.commit_count >= 2


def test_bundle_restores_into_a_working_repository(tmp_path, bundle):
    target = tmp_path / "restored"
    subprocess.run(
        ["git", "clone", "--quiet", str(bundle.path), str(target)],
        check=True,
        capture_output=True,
    )
    assert (target / "first.txt").read_text(encoding="utf-8") == "one\n"


def test_restored_repository_has_the_tag(tmp_path, bundle):
    target = tmp_path / "restored"
    subprocess.run(
        ["git", "clone", "--quiet", str(bundle.path), str(target)],
        check=True,
        capture_output=True,
    )
    assert "v0.1.0" in git("tag", "-l", cwd=target)


def test_restored_repository_has_every_branch(tmp_path, bundle):
    target = tmp_path / "restored"
    subprocess.run(
        ["git", "clone", "--quiet", str(bundle.path), str(target)],
        check=True,
        capture_output=True,
    )
    branches = git("branch", "-a", cwd=target)
    assert "side" in branches, "a backup missing a branch is an incomplete backup"


def test_restored_history_matches_the_source(tmp_path, bundle, source_repository):
    target = tmp_path / "restored"
    subprocess.run(
        ["git", "clone", "--quiet", str(bundle.path), str(target)],
        check=True,
        capture_output=True,
    )
    source_log = git("log", "--format=%H", cwd=source_repository)
    restored_log = git("log", "--format=%H", cwd=target)
    assert source_log == restored_log


def test_checksum_matches_the_file(bundle):
    import hashlib

    digest = hashlib.sha256(bundle.path.read_bytes()).hexdigest()
    assert digest == bundle.sha256


def test_verification_rejects_a_corrupted_bundle(tmp_path, bundle, source_repository):
    corrupted = tmp_path / "corrupted.bundle"
    data = bytearray(bundle.path.read_bytes())
    # Damage the payload, well past the header.
    for index in range(len(data) // 2, min(len(data) // 2 + 512, len(data))):
        data[index] ^= 0xFF
    corrupted.write_bytes(bytes(data))

    with pytest.raises(backup_bundle.BackupError):
        backup_bundle.verify_bundle(corrupted, repository=source_repository)


def test_verification_rejects_a_truncated_bundle(tmp_path, bundle, source_repository):
    truncated = tmp_path / "truncated.bundle"
    truncated.write_bytes(bundle.path.read_bytes()[: bundle.size_bytes // 3])

    with pytest.raises(backup_bundle.BackupError):
        backup_bundle.verify_bundle(truncated, repository=source_repository)


def test_verification_rejects_a_missing_bundle(tmp_path, source_repository):
    with pytest.raises(backup_bundle.BackupError, match="no bundle"):
        backup_bundle.verify_bundle(tmp_path / "absent.bundle", repository=source_repository)


def test_creating_a_bundle_outside_a_repository_fails(tmp_path):
    with pytest.raises(backup_bundle.BackupError, match="not a git repository"):
        backup_bundle.create_bundle(tmp_path / "x.bundle", repository=tmp_path)


def test_rebuilding_overwrites_a_previous_bundle(tmp_path, source_repository):
    path = tmp_path / "backup.bundle"
    first = backup_bundle.create_bundle(path, repository=source_repository)
    second = backup_bundle.create_bundle(path, repository=source_repository)
    assert second.commit_count == first.commit_count
    assert path.is_file()


def test_a_shallow_checkout_is_refused_with_a_clear_reason(tmp_path):
    """A shallow clone produces an archive that only fails on restore.

    CI checks out shallow by default, so this is the realistic way to end up
    with a backup that looks fine and is not.
    """
    origin = tmp_path / "origin"
    origin.mkdir()
    git("init", "--quiet", "--initial-branch", "main", cwd=origin)
    git("config", "user.email", "test@example.org", cwd=origin)
    git("config", "user.name", "Test", cwd=origin)
    for index in range(3):
        (origin / f"file{index}.txt").write_text(f"{index}\n", encoding="utf-8")
        git("add", ".", cwd=origin)
        git("commit", "--quiet", "-m", f"commit {index}", cwd=origin)

    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--quiet", "--depth", "1", f"file://{origin.as_posix()}", str(shallow)],
        check=True,
        capture_output=True,
    )
    assert backup_bundle.is_shallow(shallow) is True

    with pytest.raises(backup_bundle.BackupError, match="shallow checkout"):
        backup_bundle.create_bundle(tmp_path / "shallow.bundle", repository=shallow)


def test_a_full_checkout_is_not_reported_as_shallow(source_repository):
    assert backup_bundle.is_shallow(source_repository) is False


def test_this_repository_can_be_bundled(tmp_path):
    """The real repository, not a fixture: the backup must work here too."""
    if not (REPOSITORY_ROOT / ".git").exists():
        pytest.skip("not running from a git checkout")
    if backup_bundle.is_shallow(REPOSITORY_ROOT):
        pytest.skip(
            "shallow checkout: the backup workflow fetches full history, "
            "the validation workflow does not need to"
        )
    result = backup_bundle.create_bundle(tmp_path / "self.bundle", repository=REPOSITORY_ROOT)
    assert result.commit_count > 0
    assert result.ref_count > 0
