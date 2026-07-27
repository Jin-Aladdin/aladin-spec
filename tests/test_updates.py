"""Safety tests for the deterministic update engine.

Every test asserts one property from ADR-0005: a retrieval is not an
accepted update, a failing gate keeps the last valid version active, the
risk class caps automated authority, and the working pack is never modified
in place.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import source_adapters  # noqa: E402
import update_engine  # noqa: E402
import validate  # noqa: E402

EXAMPLE_PACK = REPOSITORY_ROOT / "examples" / "automated-pack"
NOW = "2026-07-27T12:00:00Z"


@pytest.fixture(scope="session")
def schemas() -> dict:
    loaded, findings = validate.load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    assert findings == [], [str(f) for f in findings]
    return loaded


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """An isolated copy of the repository parts the engine touches."""
    root = tmp_path / "repo"
    (root / "examples").mkdir(parents=True)
    shutil.copytree(EXAMPLE_PACK, root / "examples" / "automated-pack")
    shutil.copytree(REPOSITORY_ROOT / "schemas", root / "schemas")
    return root


def pack_of(workspace: Path) -> Path:
    return workspace / "examples" / "automated-pack"


def read_policy(pack: Path) -> dict:
    return yaml.safe_load((pack / "automation" / "update-policy.yml").read_text(encoding="utf-8"))


def write_policy(pack: Path, policy: dict) -> None:
    (pack / "automation" / "update-policy.yml").write_text(
        yaml.safe_dump(policy, sort_keys=False), encoding="utf-8", newline="\n"
    )


def read_state(pack: Path) -> dict:
    return json.loads((pack / "automation" / "state.json").read_text(encoding="utf-8"))


def write_upstream(workspace: Path, payload: dict) -> None:
    path = workspace / "examples" / "automated-pack" / "upstream" / "release-notes.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def upstream(workspace: Path) -> dict:
    path = workspace / "examples" / "automated-pack" / "upstream" / "release-notes.json"
    return json.loads(path.read_text(encoding="utf-8"))


def run(workspace: Path, schemas: dict, **kwargs):
    return update_engine.run_update(
        pack_of(workspace), root=workspace, schemas=schemas, now=NOW, **kwargs
    )


def claims_of(pack: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (pack / "claims" / "claims.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


def test_unchanged_source_produces_no_candidate(workspace, schemas):
    result = run(workspace, schemas)
    assert result.outcome == "no-change"
    assert result.changed_sources == []
    assert result.candidate_path is None or not result.candidate_path.exists()


def test_unchanged_source_is_idempotent(workspace, schemas):
    first = run(workspace, schemas)
    second = run(workspace, schemas)
    assert first.outcome == second.outcome == "no-change"
    assert first.retrievals[0]["content_hash"] == second.retrievals[0]["content_hash"]


def test_valid_source_change_produces_a_candidate(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas)

    assert result.outcome == "candidate-ready"
    assert result.changed_sources == ["source:example.runtime.release-notes"]
    assert all(gate.outcome in {"pass", "skipped"} for gate in result.gates)
    assert result.proposed_version == "1.0.0", "a changed statement is a major increment"


def test_candidate_does_not_modify_the_working_pack(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    before = claims_of(pack_of(workspace))
    run(workspace, schemas)
    after = claims_of(pack_of(workspace))

    assert before == after, "the working pack must stay untouched until promotion"


def test_repeated_run_on_same_input_is_deterministic(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    first = run(workspace, schemas)
    second = run(workspace, schemas)

    assert first.proposed_version == second.proposed_version
    assert first.outcome == second.outcome


# ---------------------------------------------------------------------------
# Adapter failures
# ---------------------------------------------------------------------------


def test_missing_source_file_is_a_recorded_failure(workspace, schemas):
    (workspace / "examples" / "automated-pack" / "upstream" / "release-notes.json").unlink()
    result = run(workspace, schemas)
    assert result.outcome == "failed"
    assert any("does not exist" in message for message in result.messages)


def test_oversized_source_is_rejected(workspace, schemas):
    policy = read_policy(pack_of(workspace))
    policy["sources"][0]["limits"]["max_download_bytes"] = 10
    write_policy(pack_of(workspace), policy)

    result = run(workspace, schemas)
    assert result.outcome == "failed"
    assert any("above the declared limit" in message for message in result.messages)


def test_disallowed_media_type_is_rejected(workspace, schemas):
    policy = read_policy(pack_of(workspace))
    policy["sources"][0]["allowed_media_types"] = ["text/csv"]
    write_policy(pack_of(workspace), policy)

    result = run(workspace, schemas)
    assert result.outcome == "failed"
    assert any("media type" in message for message in result.messages)


def test_path_traversal_in_a_source_is_refused():
    with pytest.raises(source_adapters.AdapterError, match="unsafe source path"):
        source_adapters.fetch(
            {"id": "source:evil", "adapter": "static-file", "path": "../../etc/passwd"},
            repository_root=REPOSITORY_ROOT,
        )


def test_unknown_adapter_is_refused():
    with pytest.raises(source_adapters.AdapterError, match="unknown adapter"):
        source_adapters.fetch(
            {"id": "source:x", "adapter": "run-my-script"}, repository_root=REPOSITORY_ROOT
        )


def test_unimplemented_adapters_fail_closed():
    """Declared but unimplemented adapters refuse rather than degrade."""
    for name in ("html-documentation", "git-repository", "github-release", "feed"):
        with pytest.raises(source_adapters.AdapterError, match="not implemented"):
            source_adapters.fetch(
                {"id": "source:x", "adapter": name, "url": "https://example.org/"},
                repository_root=REPOSITORY_ROOT,
            )


def test_implemented_adapters_are_the_declared_ones():
    """The registry never gains an adapter that is not declared."""
    assert set(source_adapters.IMPLEMENTED_ADAPTERS) <= set(source_adapters.DECLARED_ADAPTERS)
    assert set(source_adapters.ADAPTERS) == set(source_adapters.DECLARED_ADAPTERS)


# ---------------------------------------------------------------------------
# Gates and quarantine
# ---------------------------------------------------------------------------


def test_invalid_candidate_is_quarantined_and_pack_survives(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    # Break a record so the schema gate must fail on the candidate.
    pack = pack_of(workspace)
    sources_path = pack / "sources" / "sources.jsonl"
    record = json.loads(sources_path.read_text(encoding="utf-8").splitlines()[0])
    record["trust_score"] = 1
    sources_path.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    before = claims_of(pack)

    result = run(workspace, schemas)

    assert result.outcome == "quarantined"
    assert result.quarantine_path is not None and result.quarantine_path.is_dir()
    assert (result.quarantine_path / "quarantine.json").is_file()
    assert claims_of(pack) == before, "quarantine must not touch the working pack"


def test_unparseable_source_is_quarantined(workspace, schemas):
    path = workspace / "examples" / "automated-pack" / "upstream" / "release-notes.json"
    path.write_text("{not json", encoding="utf-8", newline="\n")

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"
    assert any("candidate generation failed" in message for message in result.messages)


def test_source_without_version_field_is_quarantined(workspace, schemas):
    payload = upstream(workspace)
    del payload["latest_release"]["version"]
    write_upstream(workspace, payload)

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"


def test_license_contradiction_fails_the_license_gate(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    pack = pack_of(workspace)
    sources_path = pack / "sources" / "sources.jsonl"
    record = json.loads(sources_path.read_text(encoding="utf-8").splitlines()[0])
    record["license"] = "GPL-3.0-only"
    sources_path.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"
    license_gate = next(gate for gate in result.gates if gate.name == "license_check")
    assert license_gate.outcome == "fail"
    assert "contradicts policy" in license_gate.detail


def test_evaluation_gate_rejects_unsupported_confidence(workspace, schemas):
    pack = pack_of(workspace)
    claims_path = pack / "claims" / "claims.jsonl"
    record = json.loads(claims_path.read_text(encoding="utf-8").splitlines()[0])
    record["confidence"] = 1.0
    record["status"] = "unreviewed"
    del record["source_ids"]
    del record["evidence_ids"]
    claims_path.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"
    problems = [gate for gate in result.gates if gate.outcome == "fail"]
    assert any("near-certain confidence" in gate.detail for gate in problems)


def test_dangling_evidence_reference_fails_the_reference_gate(workspace, schemas):
    pack = pack_of(workspace)
    claims_path = pack / "claims" / "claims.jsonl"
    record = json.loads(claims_path.read_text(encoding="utf-8").splitlines()[0])
    record["evidence_ids"] = ["evidence:invented.by.a.model.001"]
    claims_path.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"
    gate = next(gate for gate in result.gates if gate.name == "reference_validation")
    assert gate.outcome == "fail"


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------


def test_disabled_automation_does_nothing(workspace, schemas):
    policy = read_policy(pack_of(workspace))
    policy["automation"]["enabled"] = False
    write_policy(pack_of(workspace), policy)

    result = run(workspace, schemas)
    assert result.outcome == "disabled"
    assert result.retrievals == []


def test_invalid_policy_fails_closed(workspace, schemas):
    policy = read_policy(pack_of(workspace))
    policy["automation"]["failure_mode"] = "publish-anyway"
    write_policy(pack_of(workspace), policy)

    with pytest.raises(update_engine.UpdateError, match="update policy is invalid"):
        run(workspace, schemas)


def test_missing_policy_fails_closed(workspace, schemas):
    (pack_of(workspace) / "automation" / "update-policy.yml").unlink()
    with pytest.raises(update_engine.UpdateError, match="no update policy"):
        run(workspace, schemas)


def test_high_risk_source_is_capped_at_detect(workspace, schemas):
    policy = read_policy(pack_of(workspace))
    policy["sources"][0]["risk_class"] = "high"
    policy["sources"][0]["automation_level"] = "detect"
    write_policy(pack_of(workspace), policy)

    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas)
    assert result.effective_level == "detect"
    assert result.outcome == "change-detected"
    assert result.candidate_path is None, "detect level must leave no candidate behind"


def test_policy_level_cannot_exceed_risk_ceiling(workspace, schemas):
    policy = read_policy(pack_of(workspace))
    policy["automation"]["level"] = "registry"
    policy["automation"]["release_mode"] = "after-validation"
    policy["release"]["registry"] = {"propagate": True}
    policy["sources"][0]["risk_class"] = "medium"
    policy["sources"][0]["automation_level"] = "propose"
    write_policy(pack_of(workspace), policy)

    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas)
    assert result.effective_level == "propose"


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "current,increment,expected",
    [
        ("0.1.0", "patch", "0.1.1"),
        ("0.1.0", "minor", "0.2.0"),
        ("0.1.0", "major", "1.0.0"),
        ("1.4.9", "patch", "1.4.10"),
        ("2.0.0", "major", "3.0.0"),
    ],
)
def test_version_bump_is_deterministic(current, increment, expected):
    assert update_engine.bump(current, increment) == expected


def test_changed_statement_is_a_major_increment(workspace, schemas, tmp_path):
    pack = pack_of(workspace)
    candidate = tmp_path / "candidate"
    shutil.copytree(pack, candidate)

    claims_path = candidate / "claims" / "claims.jsonl"
    record = json.loads(claims_path.read_text(encoding="utf-8").splitlines()[0])
    record["statement"] = "A different statement about the runtime."
    claims_path.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    assert update_engine.compute_increment(pack, candidate) == "major"


def test_new_record_is_a_minor_increment(workspace, schemas, tmp_path):
    pack = pack_of(workspace)
    candidate = tmp_path / "candidate"
    shutil.copytree(pack, candidate)

    claims_path = candidate / "claims" / "claims.jsonl"
    lines = claims_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    added = dict(record)
    added["id"] = "claim:example.runtime.latest-release.002"
    claims_path.write_text(
        "\n".join(lines + [json.dumps(added, ensure_ascii=False, separators=(",", ":"))]) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    assert update_engine.compute_increment(pack, candidate) == "minor"


def test_provenance_only_change_is_a_patch(workspace, schemas, tmp_path):
    pack = pack_of(workspace)
    candidate = tmp_path / "candidate"
    shutil.copytree(pack, candidate)

    claims_path = candidate / "claims" / "claims.jsonl"
    record = json.loads(claims_path.read_text(encoding="utf-8").splitlines()[0])
    record["last_verified_at"] = "2026-08-01T00:00:00Z"
    claims_path.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    assert update_engine.compute_increment(pack, candidate) == "patch"


def test_removed_record_is_a_major_increment(workspace, schemas, tmp_path):
    pack = pack_of(workspace)
    candidate = tmp_path / "candidate"
    shutil.copytree(pack, candidate)
    (candidate / "claims" / "claims.jsonl").write_text("", encoding="utf-8", newline="\n")

    assert update_engine.compute_increment(pack, candidate) == "major"


# ---------------------------------------------------------------------------
# Rollback, state and audit
# ---------------------------------------------------------------------------


def test_rollback_discards_the_candidate(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas)
    assert result.candidate_path is not None and result.candidate_path.exists()

    update_engine.rollback(pack_of(workspace), result.candidate_path)
    assert not result.candidate_path.exists()
    assert read_state(pack_of(workspace))["last_valid_version"] == "0.1.0"


def test_dry_run_does_not_write_state(workspace, schemas):
    before = read_state(pack_of(workspace))
    run(workspace, schemas)
    assert read_state(pack_of(workspace)) == before


def test_apply_writes_state_and_audit(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    result = run(workspace, schemas, apply_state=True, run_id="test")

    state = read_state(pack_of(workspace))
    assert state["last_run"]["outcome"] == result.outcome
    assert state["counters"]["runs"] == 1

    audit_dir = pack_of(workspace) / "automation" / "audit"
    files = list(audit_dir.glob("*.jsonl"))
    assert files, "an audit file must be written"
    entries = [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]
    assert any(entry["phase"] == "change-detection" for entry in entries)
    assert any(entry["phase"] == "gate" for entry in entries)


def test_audit_is_append_only(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)
    run(workspace, schemas, apply_state=True, run_id="first")

    audit_file = next((pack_of(workspace) / "automation" / "audit").glob("*.jsonl"))
    first_count = len(audit_file.read_text(encoding="utf-8").splitlines())

    payload["latest_release"]["version"] = "2.6.0"
    write_upstream(workspace, payload)
    run(workspace, schemas, apply_state=True, run_id="second")

    second_count = len(audit_file.read_text(encoding="utf-8").splitlines())
    assert second_count > first_count


def test_applied_run_records_the_new_hash_so_the_next_run_is_quiet(workspace, schemas):
    payload = upstream(workspace)
    payload["latest_release"]["version"] = "2.5.0"
    write_upstream(workspace, payload)

    run(workspace, schemas, apply_state=True)
    second = run(workspace, schemas)

    assert second.outcome == "no-change"


def test_failure_counter_increases_on_adapter_error(workspace, schemas):
    (workspace / "examples" / "automated-pack" / "upstream" / "release-notes.json").unlink()
    run(workspace, schemas, apply_state=True)
    assert read_state(pack_of(workspace))["counters"]["failures"] == 1
