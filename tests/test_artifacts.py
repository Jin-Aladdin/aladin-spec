"""Tests for the deterministic artifact builder.

The provenance document the builder writes is what a consumer uses to verify
an artifact without trusting the publisher, so it must validate against
schemas/artifact.schema.json and the archive must be reproducible.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import build_artifact  # noqa: E402
from validate import _instance_findings, load_schemas  # noqa: E402

PACK = REPOSITORY_ROOT / "examples" / "minimal-pack"
COMMIT = "0" * 40


@pytest.fixture(scope="module")
def schemas() -> dict:
    loaded, findings = load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    assert findings == [], [str(f) for f in findings]
    return loaded


@pytest.fixture
def built(tmp_path: Path):
    return build_artifact.build(
        PACK,
        tmp_path / "dist",
        source_commit=COMMIT,
        validator_version="0.1.0",
        built_at="2026-07-27T00:00:00Z",
    )


def test_provenance_validates_against_the_artifact_schema(built, schemas):
    document = json.loads(built.provenance.read_text(encoding="utf-8"))
    findings = _instance_findings(
        schemas["artifact.schema.json"], document, str(built.provenance), None, None
    )
    assert findings == [], [str(f) for f in findings]


def test_archive_is_byte_identical_across_builds(tmp_path):
    first = build_artifact.build(PACK, tmp_path / "a", source_commit=COMMIT)
    second = build_artifact.build(PACK, tmp_path / "b", source_commit=COMMIT)
    assert first.checksum == second.checksum
    assert first.archive.read_bytes() == second.archive.read_bytes()


def test_recorded_checksum_matches_the_archive(built):
    digest = hashlib.sha256(built.archive.read_bytes()).hexdigest()
    assert digest == built.checksum


def test_every_payload_file_checksum_matches(built):
    document = json.loads(built.provenance.read_text(encoding="utf-8"))
    with zipfile.ZipFile(built.archive) as archive:
        names = set(archive.namelist())
        for entry in document["files"]:
            assert entry["path"] in names
            data = archive.read(entry["path"])
            assert hashlib.sha256(data).hexdigest() == entry["sha256"]
            assert len(data) == entry["size_bytes"]


def test_archive_entries_are_sorted_and_use_forward_slashes(built):
    with zipfile.ZipFile(built.archive) as archive:
        names = archive.namelist()
    assert names == sorted(names)
    assert all("\\" not in name for name in names)


def test_archive_timestamps_are_fixed(built):
    with zipfile.ZipFile(built.archive) as archive:
        for info in archive.infolist():
            assert info.date_time == build_artifact.FIXED_TIMESTAMP


def test_working_directories_are_excluded(tmp_path):
    """Candidates, quarantine and upstream fixtures are not artifact payload."""
    result = build_artifact.build(
        REPOSITORY_ROOT / "examples" / "automated-pack", tmp_path / "dist", source_commit=COMMIT
    )
    with zipfile.ZipFile(result.archive) as archive:
        names = archive.namelist()
    assert not any(name.startswith("upstream/") for name in names)
    assert not any(name.startswith(".candidate/") for name in names)
    assert not any("quarantine/" in name for name in names)


def test_build_without_a_commit_does_not_claim_reproducibility(tmp_path, schemas):
    result = build_artifact.build(PACK, tmp_path / "dist")
    document = json.loads(result.provenance.read_text(encoding="utf-8"))
    assert document["build"]["reproducible"] is False
    assert "source_commit" not in document["build"]

    findings = _instance_findings(
        schemas["artifact.schema.json"], document, str(result.provenance), None, None
    )
    assert findings == [], [str(f) for f in findings]


def test_reproducible_claim_requires_a_commit(schemas):
    """The schema must reject the combination the builder refuses to produce."""
    document = {
        "provenance_version": "0.1.0",
        "pack_id": "aladdin-kb-example",
        "version": "0.1.0",
        "artifact": {"name": "a.zip", "sha256": "0" * 64, "size_bytes": 1, "file_count": 1},
        "files": [{"path": "a.jsonl", "sha256": "0" * 64, "size_bytes": 1}],
        "build": {"builder": "x 0.1.0", "reproducible": True},
    }
    findings = _instance_findings(schemas["artifact.schema.json"], document, "inline", None, None)
    assert any("source_commit" in str(finding) for finding in findings)


def test_failed_validation_cannot_be_published_without_a_recall(schemas):
    document = {
        "provenance_version": "0.1.0",
        "pack_id": "aladdin-kb-example",
        "version": "0.1.0",
        "artifact": {"name": "a.zip", "sha256": "0" * 64, "size_bytes": 1, "file_count": 1},
        "files": [{"path": "a.jsonl", "sha256": "0" * 64, "size_bytes": 1}],
        "build": {"builder": "x 0.1.0", "reproducible": False},
        "validation": {"outcome": "fail"},
    }
    findings = _instance_findings(schemas["artifact.schema.json"], document, "inline", None, None)
    assert any("recall" in str(finding) for finding in findings)


def test_missing_manifest_is_reported(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_artifact.build(tmp_path, tmp_path / "dist")
