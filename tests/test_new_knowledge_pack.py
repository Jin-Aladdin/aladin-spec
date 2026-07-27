"""Tests for the Knowledge Pack bootstrap.

A generator that emits an invalid pack is worse than no generator: it hands
someone a starting point that was broken before they touched it. Every test
here checks the generated result, not the generator's intentions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import new_knowledge_pack as bootstrap  # noqa: E402
import validate  # noqa: E402
from security_scan import scan_pack  # noqa: E402

DESCRIPTION = "Structured, source-backed knowledge about container tooling and its behaviour."


@pytest.fixture(scope="module")
def schemas() -> dict:
    loaded, findings = validate.load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    assert findings == [], [str(f) for f in findings]
    return loaded


@pytest.fixture
def pack(tmp_path) -> bootstrap.BootstrapResult:
    return bootstrap.create_pack(
        tmp_path / "aladdin-kb-docker",
        pack_id="aladdin-kb-docker",
        name="Aladdin Docker Knowledge Pack",
        description=DESCRIPTION,
        domain="docker",
    )


def records(pack_dir: Path, collection: str) -> list[dict]:
    path = pack_dir / collection / f"{collection}.jsonl"
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def manifest_of(pack_dir: Path) -> dict:
    return yaml.safe_load((pack_dir / "aladdin-pack.yml").read_text(encoding="utf-8"))


def policy_of(pack_dir: Path) -> dict:
    return yaml.safe_load(
        (pack_dir / "automation" / "update-policy.yml").read_text(encoding="utf-8")
    )


# ---------------------------------------------------------------------------
# The generated pack must pass the same gates as a real one
# ---------------------------------------------------------------------------


def test_generated_pack_validates(pack, schemas):
    findings = validate.validate_pack(pack.path, schemas, pack.path)
    assert findings == [], [str(f) for f in findings]


def test_generated_pack_passes_the_security_gate(pack):
    findings = scan_pack(pack.path, pack.path)
    assert findings == [], [str(f) for f in findings]


# ---------------------------------------------------------------------------
# Identity substitution
# ---------------------------------------------------------------------------


def test_manifest_carries_the_requested_identity(pack):
    manifest = manifest_of(pack.path)
    assert manifest["pack"]["id"] == "aladdin-kb-docker"
    assert manifest["pack"]["name"] == "Aladdin Docker Knowledge Pack"
    assert manifest["pack"]["description"].startswith("Structured")


def test_policy_targets_the_generated_pack(pack):
    assert policy_of(pack.path)["pack"]["id"] == "aladdin-kb-docker"


def test_domain_is_replaced(pack):
    assert manifest_of(pack.path)["content"]["domains"] == ["docker"]


@pytest.mark.parametrize("collection,prefix", [("claims", "claim"), ("sources", "source"), ("evidence", "evidence")])
def test_record_identifiers_use_the_new_namespace(pack, collection, prefix):
    for record in records(pack.path, collection):
        assert record["id"].startswith(f"{prefix}:docker."), record["id"]


def test_no_template_identifier_survives(pack):
    """A surviving placeholder is how a template value reaches a published pack."""
    for path in sorted(pack.path.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".yml", ".json", ".jsonl"}:
            continue
        text = path.read_text(encoding="utf-8")
        assert "aladdin-kb-template" not in text, path.name
        assert ":template." not in text, path.name


def test_cross_references_still_resolve_after_renaming(pack, schemas):
    """Renaming a namespace piecemeal is how a pack ends up internally broken."""
    claim = records(pack.path, "claims")[0]
    source_ids = {r["id"] for r in records(pack.path, "sources")}
    evidence_ids = {r["id"] for r in records(pack.path, "evidence")}
    assert set(claim["source_ids"]) <= source_ids
    assert set(claim["evidence_ids"]) <= evidence_ids


# ---------------------------------------------------------------------------
# Namespace derivation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pack_id,expected",
    [
        ("aladdin-kb-docker", "docker"),
        ("aladdin-kb-postgresql", "postgresql"),
        ("aladdin-kb-ai-engineering", "ai.engineering"),
        ("aladdin-linux", "linux"),
        ("something-else", "something.else"),
    ],
)
def test_namespace_derivation(pack_id, expected):
    assert bootstrap.derive_namespace(pack_id) == expected


def test_explicit_namespace_overrides_derivation(tmp_path):
    result = bootstrap.create_pack(
        tmp_path / "pack",
        pack_id="aladdin-kb-docker",
        name="Docker",
        description=DESCRIPTION,
        domain="docker",
        namespace="container.docker",
    )
    assert result.namespace == "container.docker"
    assert records(result.path, "claims")[0]["id"].startswith("claim:container.docker.")


# ---------------------------------------------------------------------------
# Safe defaults survive generation
# ---------------------------------------------------------------------------


def test_generated_automation_starts_disabled(pack):
    automation = policy_of(pack.path)["automation"]
    assert automation["enabled"] is False
    assert automation["level"] == "detect"
    assert automation["failure_mode"] == "keep-last-valid"


def test_generated_source_starts_untrusted(pack):
    source = policy_of(pack.path)["sources"][0]
    assert source["enabled"] is False
    assert source["risk_class"] == "high"
    assert source["license"]["policy"] == "unclear"


def test_generated_pack_is_not_marked_as_reviewed(pack):
    """Nobody has reviewed a freshly generated pack for injected instructions."""
    assert manifest_of(pack.path)["security"]["prompt_injection_reviewed"] is False


def test_generated_workflows_are_pinned(pack):
    """A pack must not take its gates from a moving branch."""
    import re

    for path in sorted((pack.path / ".github" / "workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for ref in re.findall(r"^\s*ref:\s*(\S+)\s*$", text, flags=re.MULTILINE):
            assert re.fullmatch(r"v\d+\.\d+\.\d+", ref) or re.fullmatch(r"[0-9a-f]{40}", ref), (
                f"{path.name} pins to {ref!r}, which is not immutable"
            )


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pack_id", ["Aladdin-KB", "aladdin_kb", "aladdin kb", "", "AL"])
def test_invalid_pack_id_is_refused(tmp_path, pack_id):
    with pytest.raises(bootstrap.BootstrapError, match="pack id"):
        bootstrap.create_pack(
            tmp_path / "pack",
            pack_id=pack_id,
            name="X",
            description=DESCRIPTION,
            domain="docker",
        )


def test_short_description_is_refused(tmp_path):
    """The manifest schema rejects it, so refuse before writing anything."""
    with pytest.raises(bootstrap.BootstrapError, match="at least 20"):
        bootstrap.create_pack(
            tmp_path / "pack",
            pack_id="aladdin-kb-docker",
            name="Docker",
            description="too short",
            domain="docker",
        )


def test_invalid_domain_is_refused(tmp_path):
    with pytest.raises(bootstrap.BootstrapError, match="domain"):
        bootstrap.create_pack(
            tmp_path / "pack",
            pack_id="aladdin-kb-docker",
            name="Docker",
            description=DESCRIPTION,
            domain="Docker Containers",
        )


def test_existing_target_is_refused_without_force(tmp_path):
    target = tmp_path / "pack"
    target.mkdir()
    (target / "keep.txt").write_text("existing work\n", encoding="utf-8")

    with pytest.raises(bootstrap.BootstrapError, match="already exists"):
        bootstrap.create_pack(
            target,
            pack_id="aladdin-kb-docker",
            name="Docker",
            description=DESCRIPTION,
            domain="docker",
        )
    assert (target / "keep.txt").exists(), "a refusal must not delete anything"


def test_force_replaces_an_existing_target(tmp_path):
    target = tmp_path / "pack"
    target.mkdir()
    (target / "stale.txt").write_text("old\n", encoding="utf-8")

    bootstrap.create_pack(
        target,
        pack_id="aladdin-kb-docker",
        name="Docker",
        description=DESCRIPTION,
        domain="docker",
        force=True,
    )
    assert not (target / "stale.txt").exists()
    assert (target / "aladdin-pack.yml").is_file()
