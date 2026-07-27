"""End-to-end tests of the update engine driving the json-api adapter.

The adapter is exercised through the full pipeline against a local mock
server, so these assert the properties that matter operationally: an
unchanged source produces nothing, a 304 produces nothing, a failure leaves
the pack untouched, and a bad candidate is quarantined.
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
SOURCE_ID = "source:github.api.curl.releases.latest"
CLAIM_ID = "claim:github.curl.latest-release.001"


@pytest.fixture(scope="module")
def schemas() -> dict:
    loaded, findings = validate.load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    assert findings == [], [str(f) for f in findings]
    return loaded


@pytest.fixture
def route_to_mock(monkeypatch, mock_server):
    """Send the adapter to the mock server without weakening the policy.

    The policy keeps its real https URL, so the schema rule that a json-api
    source must use TLS stays enforced exactly as in production. Only the
    destination is rewritten here, and the full adapter still runs: screening,
    redirects, content type, streaming limits and conditional requests.
    """
    real = source_adapters.fetch_json_api

    def routed(source, **kwargs):
        rewritten = dict(source)
        rewritten["url"] = mock_server.url("/release")
        rewritten["allowed_domains"] = ["127.0.0.1"]
        kwargs.setdefault("allow_plain_http", True)
        kwargs.setdefault("allow_private_addresses", True)
        return real(rewritten, **kwargs)

    monkeypatch.setitem(source_adapters.ADAPTERS, "json-api", routed)
    return mock_server


@pytest.fixture
def workspace(tmp_path: Path, route_to_mock, mock_server, release_document) -> Path:
    """A copy of the demonstration pack with only the json-api source active."""
    root = tmp_path / "repo"
    (root / "examples").mkdir(parents=True)
    shutil.copytree(EXAMPLE_PACK, root / "examples" / "automated-pack")
    shutil.copytree(REPOSITORY_ROOT / "schemas", root / "schemas")

    pack = root / "examples" / "automated-pack"
    policy_path = pack / "automation" / "update-policy.yml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))

    for source in policy["sources"]:
        if source["id"] != SOURCE_ID:
            source["enabled"] = False

    policy_path.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8", newline="\n")

    mock_server.add_json("/release", release_document, headers={"ETag": '"v1"'})
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


def write_state(pack: Path, state: dict) -> None:
    (pack / "automation" / "state.json").write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8", newline="\n"
    )


def seed_state(pack: Path, **fields) -> None:
    """Set the recorded validators for the demonstration source."""
    state = read_state(pack)
    for entry in state["sources"]:
        if entry["source_id"] == SOURCE_ID:
            entry.update(fields)
    write_state(pack, state)


def claims_of(pack: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in (pack / "claims" / "claims.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def run(workspace, schemas, **kwargs):
    return update_engine.run_update(
        pack_of(workspace), root=workspace, schemas=schemas, now=NOW, **kwargs
    )


# ---------------------------------------------------------------------------
# No-change behaviour
# ---------------------------------------------------------------------------


def test_matching_hash_produces_no_candidate(workspace, schemas, mock_server, release_document):
    body = json.dumps(release_document, ensure_ascii=False).encode("utf-8")
    seed_state(pack_of(workspace), content_hash=source_adapters.content_hash(body), etag="", last_modified="")

    result = run(workspace, schemas)

    assert result.outcome == "no-change"
    assert result.candidate_path is None or not result.candidate_path.exists()


def test_not_modified_produces_no_candidate(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add("/release", status=304, body=b"", content_type=None)
    seed_state(pack_of(workspace), etag='"v1"')

    result = run(workspace, schemas)

    assert result.outcome == "no-change"
    assert result.retrievals[0]["not_modified"] is True
    assert result.changed_sources == []


def test_not_modified_is_recorded_in_the_audit_trail(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add("/release", status=304, body=b"", content_type=None)
    seed_state(pack_of(workspace), etag='"v1"')

    result = run(workspace, schemas)

    decisions = [entry["decision"] for entry in result.audit]
    assert "not-modified" in decisions


def test_two_consecutive_runs_leave_the_pack_untouched(workspace, schemas, release_document):
    body = json.dumps(release_document, ensure_ascii=False).encode("utf-8")
    seed_state(pack_of(workspace), content_hash=source_adapters.content_hash(body))

    before = claims_of(pack_of(workspace))
    run(workspace, schemas)
    run(workspace, schemas)

    assert claims_of(pack_of(workspace)) == before


# ---------------------------------------------------------------------------
# Change handling
# ---------------------------------------------------------------------------


def test_changed_source_produces_a_candidate_through_the_mapping(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add_json(
        "/release",
        {
            "tag_name": "curl-9_0_0",
            "name": "curl 9.0.0",
            "published_at": "2026-08-01T10:00:00Z",
            "html_url": "https://github.com/curl/curl/releases/tag/curl-9_0_0",
            "draft": False,
        },
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="", last_modified="")

    result = run(workspace, schemas)

    assert result.outcome == "candidate-ready"
    assert result.effective_level == "propose"
    assert all(gate.outcome in {"pass", "skipped"} for gate in result.gates), [
        (g.name, g.outcome, g.detail) for g in result.gates
    ]

    candidate_claims = [
        json.loads(line)
        for line in (result.candidate_path / "claims" / "claims.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    statement = next(c["statement"] for c in candidate_claims if c["id"] == CLAIM_ID)
    assert "curl-9_0_0" in statement
    assert "2026-08-01T10:00:00Z" in statement


def test_candidate_statement_carries_no_retrieval_timestamp(workspace, schemas, mock_server):
    """A statement containing the clock would produce a commit on every run."""
    mock_server.routes.clear()
    mock_server.add_json(
        "/release",
        {
            "tag_name": "curl-9_0_0",
            "published_at": "2026-08-01T10:00:00Z",
            "html_url": "https://github.com/curl/curl/releases/tag/curl-9_0_0",
        },
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="")

    result = run(workspace, schemas)
    candidate_claims = [
        json.loads(line)
        for line in (result.candidate_path / "claims" / "claims.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    statement = next(c["statement"] for c in candidate_claims if c["id"] == CLAIM_ID)
    assert NOW not in statement


def test_evidence_points_at_the_mapped_location(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add_json(
        "/release",
        {
            "tag_name": "curl-9_0_0",
            "published_at": "2026-08-01T10:00:00Z",
            "html_url": "https://github.com/curl/curl/releases/tag/curl-9_0_0",
        },
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="")

    result = run(workspace, schemas)
    evidence = [
        json.loads(line)
        for line in (result.candidate_path / "evidence" / "evidence.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    record = next(e for e in evidence if e["id"].startswith("evidence:github.api.curl"))
    assert record["locator"]["type"] == "json-pointer"
    assert record["locator"]["pointer"] == "/tag_name"


def test_applied_run_records_the_validators(workspace, schemas, mock_server, release_document):
    mock_server.routes.clear()
    mock_server.add_json(
        "/release", release_document, headers={"ETag": '"v2"', "Last-Modified": "Wed, 24 Jun 2026 06:03:04 GMT"}
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="", last_modified="")

    run(workspace, schemas, apply_state=True)

    entry = next(s for s in read_state(pack_of(workspace))["sources"] if s["source_id"] == SOURCE_ID)
    assert entry["etag"] == '"v2"'
    assert entry["last_modified"] == "Wed, 24 Jun 2026 06:03:04 GMT"


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


def test_missing_required_field_quarantines_and_preserves_the_pack(
    workspace, schemas, mock_server
):
    mock_server.routes.clear()
    mock_server.add_json("/release", {"name": "no tag here"})
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="")
    before = claims_of(pack_of(workspace))

    result = run(workspace, schemas)

    assert result.outcome == "quarantined"
    assert result.quarantine_path is not None and result.quarantine_path.is_dir()
    assert claims_of(pack_of(workspace)) == before


def test_wrong_field_type_quarantines(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add_json(
        "/release",
        {"tag_name": 42, "published_at": "2026-08-01T10:00:00Z", "html_url": "https://example.org/"},
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="")

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"


def test_invalid_date_format_quarantines(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add_json(
        "/release",
        {"tag_name": "curl-9", "published_at": "not-a-date", "html_url": "https://example.org/"},
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="")

    result = run(workspace, schemas)
    assert result.outcome == "quarantined"


def test_html_response_fails_the_run_without_touching_the_pack(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add("/release", body=b"<html>login</html>", content_type="text/html")
    before = claims_of(pack_of(workspace))

    result = run(workspace, schemas)

    assert result.outcome == "failed"
    assert claims_of(pack_of(workspace)) == before


def test_server_error_fails_the_run(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add("/release", status=500, body=b"{}")

    result = run(workspace, schemas)

    assert result.outcome == "failed"
    assert any("HTTP 500" in message for message in result.messages)


def test_rate_limit_is_reported_separately_from_failure(workspace, schemas, mock_server):
    mock_server.routes.clear()
    mock_server.add("/release", status=429, body=b"{}", headers={"Retry-After": "1"})
    before = claims_of(pack_of(workspace))

    result = run(workspace, schemas)

    assert result.outcome == "rate-limited"
    assert claims_of(pack_of(workspace)) == before
    assert any(entry["decision"] == "rate-limited" for entry in result.audit)


def test_blocked_target_fails_without_a_candidate(workspace, schemas, monkeypatch):
    """A metadata endpoint behind an allowlisted name still fails the run."""
    real = source_adapters.fetch_json_api

    def to_metadata(source, **kwargs):
        rewritten = dict(source)
        rewritten["url"] = "https://169.254.169.254/latest/meta-data/"
        rewritten["allowed_domains"] = ["169.254.169.254"]
        return real(rewritten, **kwargs)

    monkeypatch.setitem(source_adapters.ADAPTERS, "json-api", to_metadata)
    before = claims_of(pack_of(workspace))

    result = run(workspace, schemas)

    assert result.outcome == "failed"
    assert any("metadata" in message or "blocked" in message for message in result.messages)
    assert claims_of(pack_of(workspace)) == before


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


def test_transient_error_is_retried_up_to_the_limit(monkeypatch):
    attempts = {"count": 0}

    def flaky(source, **kwargs):
        attempts["count"] += 1
        raise source_adapters.AdapterError("boom", source_id="source:x", retryable=True)

    monkeypatch.setattr(source_adapters, "fetch", flaky)
    with pytest.raises(source_adapters.AdapterError):
        update_engine._fetch_with_retry(
            {"id": "source:x", "retry": {"max_attempts": 3, "backoff_seconds": 0}},
            root=REPOSITORY_ROOT,
            now=NOW,
            state={},
            options={},
            sleep=lambda seconds: None,
        )
    assert attempts["count"] == 3


def test_permanent_error_is_not_retried(monkeypatch):
    attempts = {"count": 0}

    def refused(source, **kwargs):
        attempts["count"] += 1
        raise source_adapters.AdapterError("refused", source_id="source:x", retryable=False)

    monkeypatch.setattr(source_adapters, "fetch", refused)
    with pytest.raises(source_adapters.AdapterError):
        update_engine._fetch_with_retry(
            {"id": "source:x", "retry": {"max_attempts": 5, "backoff_seconds": 0}},
            root=REPOSITORY_ROOT,
            now=NOW,
            state={},
            options={},
            sleep=lambda seconds: None,
        )
    assert attempts["count"] == 1, "a refusal must not be retried"


def test_rate_limit_is_not_retried(monkeypatch):
    attempts = {"count": 0}

    def limited(source, **kwargs):
        attempts["count"] += 1
        raise source_adapters.AdapterError(
            "rate limited", source_id="source:x", rate_limited=True
        )

    monkeypatch.setattr(source_adapters, "fetch", limited)
    with pytest.raises(source_adapters.AdapterError):
        update_engine._fetch_with_retry(
            {"id": "source:x", "retry": {"max_attempts": 5, "backoff_seconds": 0}},
            root=REPOSITORY_ROOT,
            now=NOW,
            state={},
            options={},
            sleep=lambda seconds: None,
        )
    assert attempts["count"] == 1, "hammering a rate limit makes it worse"


def test_retry_succeeds_after_a_transient_failure(monkeypatch):
    attempts = {"count": 0}
    expected = source_adapters.Retrieval(
        source_id="source:x",
        adapter="json-api",
        adapter_version="0.1.0",
        requested="https://example.org/",
        final="https://example.org/",
        retrieved_at=NOW,
        status="ok",
        media_type="application/json",
        size_bytes=2,
        content_hash="sha256:" + "0" * 64,
    )

    def flaky(source, **kwargs):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise source_adapters.AdapterError("boom", source_id="source:x", retryable=True)
        return expected

    monkeypatch.setattr(source_adapters, "fetch", flaky)
    result = update_engine._fetch_with_retry(
        {"id": "source:x", "retry": {"max_attempts": 3, "backoff_seconds": 0}},
        root=REPOSITORY_ROOT,
        now=NOW,
        state={},
        options={},
        sleep=lambda seconds: None,
    )
    assert result is expected
    assert attempts["count"] == 3


def test_retry_after_overrides_the_configured_backoff(monkeypatch):
    delays: list[int] = []

    def flaky(source, **kwargs):
        raise source_adapters.AdapterError(
            "busy", source_id="source:x", retryable=True, retry_after_seconds=7
        )

    monkeypatch.setattr(source_adapters, "fetch", flaky)
    with pytest.raises(source_adapters.AdapterError):
        update_engine._fetch_with_retry(
            {"id": "source:x", "retry": {"max_attempts": 2, "backoff_seconds": 1}},
            root=REPOSITORY_ROOT,
            now=NOW,
            state={},
            options={},
            sleep=delays.append,
        )
    assert delays == [7]


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def test_rollback_discards_the_candidate_and_keeps_the_valid_version(
    workspace, schemas, mock_server
):
    mock_server.routes.clear()
    mock_server.add_json(
        "/release",
        {
            "tag_name": "curl-9_0_0",
            "published_at": "2026-08-01T10:00:00Z",
            "html_url": "https://github.com/curl/curl/releases/tag/curl-9_0_0",
        },
    )
    seed_state(pack_of(workspace), content_hash="sha256:" + "0" * 64, etag="")

    before = claims_of(pack_of(workspace))
    result = run(workspace, schemas)
    assert result.candidate_path is not None and result.candidate_path.exists()

    update_engine.rollback(pack_of(workspace), result.candidate_path)

    assert not result.candidate_path.exists()
    assert claims_of(pack_of(workspace)) == before
    assert read_state(pack_of(workspace))["last_valid_version"] == "0.1.0"
