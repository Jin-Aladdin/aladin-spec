"""Test suite for the Aladdin Spec reference validator.

The suite covers three levels:

* the repository itself must validate cleanly,
* a known-good fixture pack must produce no findings,
* every fixture under ``tests/fixtures/invalid`` must produce the specific
  finding it was built to trigger.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from validate import (  # noqa: E402
    CONTENT_TYPES,
    check_relative_path,
    iter_references,
    load_schemas,
    validate_pack,
    validate_repository,
)

FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures"


@pytest.fixture(scope="session")
def schemas() -> dict:
    loaded, findings = load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    assert findings == [], f"schema directory is not clean: {[str(f) for f in findings]}"
    return loaded


def messages(findings) -> str:
    return "\n".join(str(finding) for finding in findings)


# ---------------------------------------------------------------------------
# Schema level
# ---------------------------------------------------------------------------


def test_every_schema_is_draft_2020_12(schemas):
    assert schemas, "no schema files were loaded"
    for name, schema in schemas.items():
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema", name


def test_every_schema_has_a_unique_id(schemas):
    ids = [schema["$id"] for schema in schemas.values()]
    assert len(ids) == len(set(ids))


def test_every_known_content_type_schema_is_declared():
    """Every content type must map to a schema file name."""
    for content_type, spec in CONTENT_TYPES.items():
        assert spec["schema"].endswith(".schema.json"), content_type
        assert spec["prefix"], content_type


# ---------------------------------------------------------------------------
# Repository level
# ---------------------------------------------------------------------------


def test_repository_validates_cleanly():
    findings = validate_repository(REPOSITORY_ROOT)
    assert findings == [], messages(findings)


def test_valid_fixture_pack(schemas):
    findings = validate_pack(FIXTURES / "valid" / "minimal-pack", schemas, REPOSITORY_ROOT)
    assert findings == [], messages(findings)


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

INVALID_CASES = [
    ("broken-yaml-indentation", "invalid YAML"),
    ("missing-source", "source:fixture.absent does not exist in sources"),
    ("unknown-evidence", "evidence:fixture.absent.001 does not exist in evidence"),
    ("invalid-claim-id", "does not match"),
    ("confidence-out-of-range", "greater than the maximum of 1"),
    ("source-backed-without-support", "is not valid under any of the given schemas"),
    ("merged-entity-without-target", "'merged_into' is a required property"),
    ("missing-entry-point", "declared path does not exist"),
    ("unknown-core-field", "Additional properties are not allowed"),
    ("unsafe-relative-path", "traverse outside the pack directory"),
]


@pytest.mark.parametrize("fixture_name,expected", INVALID_CASES, ids=[c[0] for c in INVALID_CASES])
def test_invalid_fixture_is_rejected(fixture_name, expected, schemas):
    findings = validate_pack(FIXTURES / "invalid" / fixture_name, schemas, REPOSITORY_ROOT)
    assert findings, f"{fixture_name} produced no findings"
    assert expected in messages(findings), (
        f"{fixture_name}: expected {expected!r}, got:\n{messages(findings)}"
    )


def test_every_invalid_fixture_has_a_test_case():
    """A new fixture directory must not be silently ignored by the suite."""
    on_disk = {path.name for path in (FIXTURES / "invalid").iterdir() if path.is_dir()}
    covered = {name for name, _ in INVALID_CASES}
    assert on_disk == covered


def test_broken_yaml_reports_a_line_number(schemas):
    findings = validate_pack(
        FIXTURES / "invalid" / "broken-yaml-indentation", schemas, REPOSITORY_ROOT
    )
    assert any(finding.line is not None for finding in findings), messages(findings)


def test_findings_name_the_offending_file_and_line(schemas):
    findings = validate_pack(
        FIXTURES / "invalid" / "confidence-out-of-range", schemas, REPOSITORY_ROOT
    )
    offending = [f for f in findings if "maximum" in f.message]
    assert offending, messages(findings)
    assert offending[0].path.endswith("claims/claims.jsonl")
    assert offending[0].line == 1
    assert offending[0].record_id == "claim:fixture.definition.001"


# ---------------------------------------------------------------------------
# Unit level
# ---------------------------------------------------------------------------


def test_reference_scanner_finds_nested_references():
    record = {
        "id": "claim:example.001",
        "source_ids": ["source:example.doc"],
        "nested": {"deep": ["entity:example.thing"]},
    }
    assert set(iter_references(record)) == {"source:example.doc", "entity:example.thing"}


def test_reference_scanner_ignores_own_id_and_extensions():
    record = {
        "id": "claim:example.001",
        "extensions": {"org.example.private": {"linked": "claim:example.999"}},
    }
    assert set(iter_references(record)) == set()


@pytest.mark.parametrize(
    "value,expected_fragment",
    [
        ("../outside.jsonl", "traverse outside"),
        ("/absolute/path.jsonl", "relative to the pack directory"),
        ("claims\\claims.jsonl", "forward slashes"),
        ("", "must not be empty"),
        ("does/not/exist.jsonl", "does not exist"),
    ],
)
def test_unsafe_paths_are_rejected(value, expected_fragment):
    pack = FIXTURES / "valid" / "minimal-pack"
    problem = check_relative_path(value, pack)
    assert problem is not None and expected_fragment in problem


def test_safe_path_is_accepted():
    pack = FIXTURES / "valid" / "minimal-pack"
    assert check_relative_path("claims/claims.jsonl", pack) is None
