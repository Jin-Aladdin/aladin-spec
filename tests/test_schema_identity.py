"""Tests for the schema identifier strategy of ADR-0006.

An identifier names one immutable document at one specification version and
can be fetched. Drift between the identifier and the version is silent and
inherited by every implementation, so it is enforced here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = REPOSITORY_ROOT / "schemas"

#: The specification version these schemas belong to.
SPECIFICATION_VERSION = "0.3.0"

ID_PATTERN = re.compile(
    r"^https://raw\.githubusercontent\.com/Jin-Aladdin/aladdin-spec/"
    r"v(?P<version>\d+\.\d+\.\d+)/schemas/(?P<filename>[a-z0-9-]+\.schema\.json)$"
)

#: Hosts that must never appear in an identifier. github.com serves an HTML
#: page rather than the schema; the others are namespaces the project does not
#: control and must not claim.
FORBIDDEN_HOSTS = ("github.com/", "aladdin.dev", "aladdin.org", "aladin.")


def schema_files() -> list[Path]:
    return sorted(SCHEMAS.glob("*.schema.json"))


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_identifier_follows_the_versioned_pattern(path):
    schema = load(path)
    identifier = schema.get("$id")
    assert identifier, f"{path.name} has no $id"
    assert ID_PATTERN.match(identifier), (
        f"{path.name} has $id {identifier!r}, which is not a versioned "
        f"dereferenceable identifier as required by ADR-0006"
    )


@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_identifier_matches_the_current_specification_version(path):
    match = ID_PATTERN.match(load(path)["$id"])
    assert match.group("version") == SPECIFICATION_VERSION, (
        f"{path.name} claims version {match.group('version')} but the "
        f"specification is at {SPECIFICATION_VERSION}. Identifier and version "
        f"must move together."
    )


@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_identifier_matches_the_filename(path):
    match = ID_PATTERN.match(load(path)["$id"])
    assert match.group("filename") == path.name, (
        f"{path.name} carries the identifier of {match.group('filename')}"
    )


@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_identifier_avoids_forbidden_hosts(path):
    identifier = load(path)["$id"]
    for host in FORBIDDEN_HOSTS:
        assert host not in identifier, (
            f"{path.name} uses {host!r}: either not dereferenceable, or a "
            f"namespace the project does not control"
        )


@pytest.mark.parametrize("path", schema_files(), ids=lambda p: p.name)
def test_identifier_is_not_bound_to_a_moving_branch(path):
    identifier = load(path)["$id"]
    for branch in ("/main/", "/master/", "/HEAD/"):
        assert branch not in identifier, (
            f"{path.name} points at {branch!r}. A branch names different "
            f"documents over time and cannot serve as an identifier."
        )


def test_all_identifiers_are_unique():
    identifiers = [load(path)["$id"] for path in schema_files()]
    assert len(identifiers) == len(set(identifiers))


def test_every_schema_file_is_covered():
    """Guards against a schema being added without an identifier check."""
    assert len(schema_files()) >= 13, "expected at least the 13 known schemas"
