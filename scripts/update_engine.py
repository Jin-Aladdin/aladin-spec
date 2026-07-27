#!/usr/bin/env python3
"""Deterministic update engine for Aladdin Knowledge Packs.

This is the reference implementation of the pipeline in
``specifications/automation-v1.adoc``. It is deliberately small and offline:
it demonstrates the safety properties rather than the breadth of a
production updater.

Pipeline::

    load policy -> retrieve -> detect change -> build candidate
                -> run gates -> promote or quarantine

Safety properties this implementation is built to guarantee:

* the working pack is never modified in place; candidates live in a
  separate directory
* a retrieval that succeeds is not an accepted update
* any failing gate quarantines the candidate and keeps the last valid
  version active
* the risk class of a source caps what automation may do with its change
* the version increment is computed from the record diff, never guessed
* every decision appends an audit record

Nothing retrieved is ever executed, imported or evaluated.

Usage::

    python scripts/update_engine.py --pack examples/automated-pack
    python scripts/update_engine.py --pack examples/automated-pack --apply
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import json_mapping  # noqa: E402
import source_adapters  # noqa: E402
import validate  # noqa: E402
from security_scan import scan_pack  # noqa: E402

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

STATE_FILENAME = "state.json"
HEALTH_FILENAME = "health.json"
QUARANTINE_DIRECTORY = "quarantine"
AUDIT_DIRECTORY = "audit"
CANDIDATE_DIRECTORY = ".candidate"

ENGINE_VERSION = "0.1.0"

#: How far automation may go for a given risk class, regardless of policy.
RISK_CEILING = {"low": "registry", "medium": "propose", "high": "detect"}

LEVEL_ORDER = ["detect", "propose", "auto-merge", "release", "registry"]

#: Fields whose change alters what a record means. A change here is a major
#: increment; a change to provenance or verification metadata is a patch.
SEMANTIC_FIELDS = {
    "claims": {"statement", "kind", "language", "jurisdictions"},
    "sources": {"title", "publisher", "license", "type"},
    "evidence": {"locator", "excerpt", "source_id"},
    "entities": {"name", "type", "language"},
}


class UpdateError(RuntimeError):
    """A failure that must stop promotion and keep the last valid version."""


@dataclass
class GateResult:
    name: str
    outcome: str
    detail: str = ""

    @property
    def passed(self) -> bool:
        return self.outcome == "pass"


@dataclass
class RunResult:
    """The outcome of one update run."""

    pack_id: str
    outcome: str
    trigger: str
    started_at: str
    finished_at: str = ""
    retrievals: list[dict] = field(default_factory=list)
    gates: list[GateResult] = field(default_factory=list)
    changed_sources: list[str] = field(default_factory=list)
    candidate_path: Path | None = None
    quarantine_path: Path | None = None
    current_version: str = ""
    proposed_version: str = ""
    effective_level: str = "detect"
    audit: list[dict] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.outcome in {"quarantined", "failed"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n" for record in records
    )
    path.write_text(body, encoding="utf-8", newline="\n")


def _min_level(a: str, b: str) -> str:
    return a if LEVEL_ORDER.index(a) <= LEVEL_ORDER.index(b) else b


# ---------------------------------------------------------------------------
# Policy and state
# ---------------------------------------------------------------------------


def load_policy(pack_dir: Path, schemas: dict, root: Path) -> dict:
    """Load and validate the update policy. A broken policy fails closed."""
    policy_path = pack_dir / validate.AUTOMATION_DIRECTORY / validate.POLICY_FILENAME
    if not policy_path.is_file():
        raise UpdateError(f"no update policy at {validate._relative(policy_path, root)}")

    # A source file that vanished is a retrieval failure, not an invalid
    # policy: the engine records it, counts it and retries under the retry
    # policy. Static validation in CI still requires the file to be present.
    findings = validate.validate_policy(policy_path, schemas, root, require_source_paths=False)
    if findings:
        raise UpdateError(
            "update policy is invalid: " + "; ".join(str(f) for f in findings[:5])
        )

    policy, load_findings = validate.load_yaml_mapping(policy_path, root)
    if policy is None:
        raise UpdateError("; ".join(str(f) for f in load_findings))
    return policy


def load_state(pack_dir: Path) -> dict:
    path = pack_dir / validate.AUTOMATION_DIRECTORY / STATE_FILENAME
    if not path.is_file():
        return {
            "state_version": "0.1.0",
            "pack_id": "",
            "last_valid_version": "",
            "last_run": {},
            "sources": [],
            "quarantine": [],
            "counters": {"runs": 0, "candidates": 0, "releases": 0, "failures": 0},
        }
    return _read_json(path)


def save_state(pack_dir: Path, state: dict) -> None:
    _write_json(pack_dir / validate.AUTOMATION_DIRECTORY / STATE_FILENAME, state)


def _state_source(state: dict, source_id: str) -> dict:
    for entry in state.get("sources", []):
        if entry.get("source_id") == source_id:
            return entry
    entry = {
        "source_id": source_id,
        "last_checked_at": "",
        "last_change_at": "",
        "content_hash": "",
        "consecutive_failures": 0,
    }
    state.setdefault("sources", []).append(entry)
    return entry


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def audit_record(
    *,
    run_id: str,
    trigger: str,
    phase: str,
    subject: str,
    decision: str,
    reason: str,
    policy_version: str,
    now: str,
    inputs: list[str] | None = None,
) -> dict:
    return {
        "audit_version": "0.1.0",
        "recorded_at": now,
        "run_id": run_id,
        "trigger": trigger,
        "phase": phase,
        "subject": subject,
        "decision": decision,
        "reason": reason,
        "policy_version": policy_version,
        "tool": {"name": "update_engine.py", "version": ENGINE_VERSION},
        "inputs": inputs or [],
    }


def append_audit(pack_dir: Path, records: list[dict], now: str) -> Path:
    """Append audit records to the month file. Records are never rewritten."""
    month = now[:7]
    path = pack_dir / validate.AUTOMATION_DIRECTORY / AUDIT_DIRECTORY / f"{month}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    return path


# ---------------------------------------------------------------------------
# Candidate construction
# ---------------------------------------------------------------------------


def build_candidate(pack_dir: Path, candidate_dir: Path) -> Path:
    """Copy the pack into an isolated candidate directory.

    The working pack is never modified in place. If a later phase fails, the
    candidate is discarded or quarantined and the pack is untouched.
    """
    if candidate_dir.exists():
        shutil.rmtree(candidate_dir)
    shutil.copytree(
        pack_dir,
        candidate_dir,
        ignore=shutil.ignore_patterns(CANDIDATE_DIRECTORY, QUARANTINE_DIRECTORY),
    )
    return candidate_dir


def normalize_release_notes(payload: dict) -> dict:
    """Normalize the static-file demonstration source into a flat shape.

    Kept for the offline example, which predates the declarative mapping.
    Normalization is pure: same input, same output, no clock, no network.
    """
    release = payload.get("latest_release") or {}
    return {
        "product": payload.get("product"),
        "version": release.get("version"),
        "released_at": release.get("released_at"),
        "documentation_url": payload.get("documentation_url"),
        "license": payload.get("license"),
    }


def apply_release_note_candidate(
    candidate_dir: Path,
    normalized: dict,
    retrieval: source_adapters.Retrieval,
) -> list[str]:
    """Apply the normalized static-file source to the candidate.

    Only declarative record fields are touched. Confidence is not raised, no
    source or evidence is invented, and superseded content is rewritten only
    when the underlying statement actually changed.
    """
    changed: list[str] = []
    version = normalized.get("version")
    if not version:
        raise UpdateError("normalized source carries no version field")

    claims_path = candidate_dir / "claims" / "claims.jsonl"
    claims = _read_jsonl(claims_path)
    for claim in claims:
        if claim.get("id") != "claim:example.runtime.latest-release.001":
            continue
        statement = f"The latest documented release of Example Runtime is version {version}."
        if claim.get("statement") != statement:
            claim["statement"] = statement
            changed.append(claim["id"])
        claim["last_verified_at"] = retrieval.retrieved_at
        if normalized.get("released_at"):
            claim["valid_from"] = normalized["released_at"]
    _write_jsonl(claims_path, claims)

    evidence_path = candidate_dir / "evidence" / "evidence.jsonl"
    evidence = _read_jsonl(evidence_path)
    for record in evidence:
        if record.get("id") != "evidence:example.runtime.release-notes.version.001":
            continue
        if record.get("excerpt") != version:
            record["excerpt"] = version
            changed.append(record["id"])
        record["captured_at"] = retrieval.retrieved_at
        verification = record.setdefault("verification", {})
        verification["verified_at"] = retrieval.retrieved_at
    _write_jsonl(evidence_path, evidence)

    sources_path = candidate_dir / "sources" / "sources.jsonl"
    sources = _read_jsonl(sources_path)
    for record in sources:
        if record.get("id") != retrieval.source_id:
            continue
        record["retrieved_at"] = retrieval.retrieved_at
        record["content_hash"] = retrieval.content_hash
    _write_jsonl(sources_path, sources)

    return changed


def apply_mapped_candidate(
    candidate_dir: Path,
    source: dict,
    retrieval: source_adapters.Retrieval,
) -> list[str]:
    """Apply a declaratively mapped source to the candidate.

    The statement is rendered from mapped values only. Retrieval time is
    deliberately kept out of it: a statement containing the clock would differ
    on every run and produce a commit on every run, which is the opposite of
    what a change-detecting pipeline is for. The retrieval time belongs to
    provenance fields instead, where it can move without changing meaning.
    """
    mapping = source.get("mapping") or {}
    transformation = source.get("transformation") or {}
    limits = source.get("limits") or {}

    try:
        document = json.loads(retrieval.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"retrieved document is not usable JSON: {exc}") from exc

    values = json_mapping.apply_mapping(
        document,
        mapping,
        max_depth=limits.get("max_json_depth", json_mapping.DEFAULT_MAX_DEPTH),
    )
    pointers = json_mapping.mapped_pointers(mapping)

    changed: list[str] = []
    claim_rule = transformation.get("claim") or {}
    claim_id = claim_rule.get("id")
    statement = json_mapping.render_template(claim_rule.get("statement_template", ""), values)

    claims_path = candidate_dir / "claims" / "claims.jsonl"
    claims = _read_jsonl(claims_path)
    for claim in claims:
        if claim.get("id") != claim_id:
            continue
        if claim.get("statement") != statement:
            claim["statement"] = statement
            changed.append(claim["id"])
        claim["last_verified_at"] = retrieval.retrieved_at
        valid_from_field = claim_rule.get("valid_from_field")
        if valid_from_field and valid_from_field in values:
            claim["valid_from"] = values[valid_from_field]
    _write_jsonl(claims_path, claims)

    evidence_rule = transformation.get("evidence") or {}
    evidence_id = evidence_rule.get("id")
    if evidence_id:
        fields = [f for f in evidence_rule.get("fields", []) if f in pointers]
        evidence_path = candidate_dir / "evidence" / "evidence.jsonl"
        evidence = _read_jsonl(evidence_path)
        for record in evidence:
            if record.get("id") != evidence_id:
                continue
            if fields:
                # The locator points at the exact field the claim rests on, so
                # a reader can check the source without re-deriving anything.
                record["locator"] = {"type": "json-pointer", "pointer": pointers[fields[0]]}
                excerpt = " ".join(str(values[f]) for f in fields if f in values)
                if excerpt and record.get("excerpt") != excerpt:
                    record["excerpt"] = excerpt
                    changed.append(record["id"])
            record["captured_at"] = retrieval.retrieved_at
            verification = record.setdefault("verification", {})
            verification["verified_at"] = retrieval.retrieved_at
        _write_jsonl(evidence_path, evidence)

    sources_path = candidate_dir / "sources" / "sources.jsonl"
    sources = _read_jsonl(sources_path)
    for record in sources:
        if record.get("id") != retrieval.source_id:
            continue
        record["retrieved_at"] = retrieval.retrieved_at
        record["content_hash"] = retrieval.content_hash
        if retrieval.final and retrieval.final != record.get("url"):
            record["canonical_url"] = retrieval.final
    _write_jsonl(sources_path, sources)

    return changed


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------


def _index(records: list[dict]) -> dict[str, dict]:
    return {r["id"]: r for r in records if isinstance(r.get("id"), str)}


def compute_increment(pack_dir: Path, candidate_dir: Path) -> str:
    """Compute the version increment from the record diff.

    Deterministic by construction: removals and changed meaning are major,
    new records are minor, everything else is patch.
    """
    increment = "patch"
    for collection, semantic_fields in SEMANTIC_FIELDS.items():
        before = _index(_read_jsonl(pack_dir / collection / f"{collection}.jsonl"))
        after = _index(_read_jsonl(candidate_dir / collection / f"{collection}.jsonl"))

        if set(before) - set(after):
            return "major"
        for record_id, new_record in after.items():
            old_record = before.get(record_id)
            if old_record is None:
                increment = "minor" if increment == "patch" else increment
                continue
            for field_name in semantic_fields:
                if old_record.get(field_name) != new_record.get(field_name):
                    return "major"
    return increment


def bump(version: str, increment: str) -> str:
    major, minor, patch = (int(part) for part in version.split("-")[0].split("+")[0].split("."))
    if increment == "major":
        return f"{major + 1}.0.0"
    if increment == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def run_gates(candidate_dir: Path, policy: dict, schemas: dict, root: Path) -> list[GateResult]:
    """Run every configured gate. A required gate can fail the pipeline."""
    configured = policy.get("gates") or {}
    results: list[GateResult] = []

    def record(name: str, ok: bool, detail: str) -> None:
        mode = configured.get(name, "disabled")
        if mode == "disabled":
            results.append(GateResult(name, "skipped", "disabled by policy"))
        elif ok:
            results.append(GateResult(name, "pass", detail))
        elif mode == "advisory":
            results.append(GateResult(name, "advisory-fail", detail))
        else:
            results.append(GateResult(name, "fail", detail))

    findings = validate.validate_pack(candidate_dir, schemas, root)
    schema_findings = [f for f in findings if "reference" not in f.message]
    reference_findings = [f for f in findings if "reference" in f.message]
    record("schema_validation", not schema_findings, _summarize(schema_findings))
    record("reference_validation", not reference_findings, _summarize(reference_findings))

    security_findings = scan_pack(candidate_dir, root)
    record("security_scan", not security_findings, _summarize(security_findings))

    license_problems = check_licenses(candidate_dir, policy)
    record("license_check", not license_problems, "; ".join(license_problems[:3]))

    evaluation_problems = run_evaluations(candidate_dir)
    record("evaluation_suite", not evaluation_problems, "; ".join(evaluation_problems[:3]))

    return results


def _summarize(findings: list) -> str:
    return "; ".join(str(f) for f in findings[:3])


def check_licenses(candidate_dir: Path, policy: dict) -> list[str]:
    """Every source touched by automation must carry a usable license."""
    problems: list[str] = []
    declared = {
        entry.get("id"): entry
        for entry in policy.get("sources", [])
        if isinstance(entry, dict)
    }
    for record in _read_jsonl(candidate_dir / "sources" / "sources.jsonl"):
        source_id = record.get("id")
        if not record.get("license"):
            problems.append(f"{source_id}: record carries no license")
        entry = declared.get(source_id)
        if entry is None:
            continue
        license_policy = (entry.get("license") or {}).get("policy")
        if license_policy == "unclear":
            problems.append(f"{source_id}: licensing is unclear, automatic publication is forbidden")
        expression = (entry.get("license") or {}).get("expression")
        if expression and record.get("license") != expression:
            problems.append(
                f"{source_id}: record license {record.get('license')!r} contradicts policy {expression!r}"
            )
    return problems


def run_evaluations(candidate_dir: Path) -> list[str]:
    """Minimal quality evaluations that must hold for any candidate."""
    problems: list[str] = []
    claims = _read_jsonl(candidate_dir / "claims" / "claims.jsonl")
    if not claims:
        problems.append("candidate contains no claims")
    for claim in claims:
        confidence = claim.get("confidence")
        if isinstance(confidence, (int, float)) and confidence > 0.99 and claim.get(
            "status"
        ) not in {"human-reviewed", "source-backed"}:
            problems.append(f"{claim.get('id')}: near-certain confidence without supporting status")
        if claim.get("status") in {"source-backed", "human-reviewed"} and not (
            claim.get("source_ids") or claim.get("evidence_ids")
        ):
            problems.append(f"{claim.get('id')}: supported status without supporting material")
    return problems


# ---------------------------------------------------------------------------
# Quarantine and rollback
# ---------------------------------------------------------------------------


def quarantine(pack_dir: Path, candidate_dir: Path, candidate_id: str, reason: str, now: str) -> Path:
    """Move a failing candidate out of the way without touching the pack."""
    target = pack_dir / validate.AUTOMATION_DIRECTORY / QUARANTINE_DIRECTORY / candidate_id
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(candidate_dir), str(target))
    _write_json(
        target / "quarantine.json",
        {
            "candidate_id": candidate_id,
            "quarantined_at": now,
            "reason": reason,
            "engine_version": ENGINE_VERSION,
        },
    )
    return target


def rollback(pack_dir: Path, candidate_dir: Path | None = None) -> None:
    """Discard the candidate. The last valid pack version stays active."""
    if candidate_dir is not None and candidate_dir.exists():
        shutil.rmtree(candidate_dir)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _fetch_with_retry(
    source: dict,
    *,
    root: Path,
    now: str,
    state: dict,
    options: dict,
    sleep=time.sleep,
) -> source_adapters.Retrieval:
    """Retrieve one source, retrying only what is worth retrying.

    A refused target, a wrong content type, an oversized response, invalid
    JSON or a policy violation is a decision: repeating the request produces
    the same answer and only adds load. Transport failures and selected server
    errors are transient and get a bounded number of attempts.
    """
    retry = source.get("retry") or {}
    max_attempts = max(1, int(retry.get("max_attempts", 1)))
    backoff = int(retry.get("backoff_seconds", 0))
    respect_retry_after = retry.get("respect_retry_after", True)

    last_error: source_adapters.AdapterError | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return source_adapters.fetch(
                source, repository_root=root, now=now, state=state, **options
            )
        except source_adapters.AdapterError as exc:
            last_error = exc
            if exc.rate_limited or not exc.retryable or attempt == max_attempts:
                raise
            delay = backoff
            if respect_retry_after and exc.retry_after_seconds is not None:
                delay = exc.retry_after_seconds
            if delay > 0:
                sleep(delay)

    assert last_error is not None
    raise last_error


def run_update(
    pack_dir: Path,
    *,
    root: Path = REPOSITORY_ROOT,
    schemas: dict | None = None,
    trigger: str = "manual",
    now: str | None = None,
    run_id: str = "local",
    apply_state: bool = False,
    adapter_options: dict | None = None,
) -> RunResult:
    """Execute one update run for one pack.

    ``adapter_options`` is passed straight to the adapter and exists so tests
    can point a network adapter at a local mock server. It is never populated
    from pack or policy content.
    """
    now = now or _utc_now()
    if schemas is None:
        schemas, schema_findings = validate.load_schemas(root / "schemas", root)
        if schema_findings:
            raise UpdateError("schema directory is not clean")

    policy = load_policy(pack_dir, schemas, root)
    policy_version = policy.get("policy_version", "unknown")
    pack_id = (policy.get("pack") or {}).get("id", "")
    automation = policy.get("automation") or {}

    state = load_state(pack_dir)
    result = RunResult(
        pack_id=pack_id,
        outcome="no-change",
        trigger=trigger,
        started_at=now,
        current_version=state.get("last_valid_version", ""),
    )

    if not automation.get("enabled", False):
        result.outcome = "disabled"
        result.messages.append("automation is disabled by policy")
        result.finished_at = now
        return result

    candidate_id = f"candidate-{now.replace(':', '-')}-{run_id}"
    candidate_dir = pack_dir / CANDIDATE_DIRECTORY

    # --- retrieval and change detection ----------------------------------
    changed_sources: list[dict] = []
    for source in policy.get("sources", []):
        if not isinstance(source, dict) or source.get("enabled") is False:
            continue
        source_id = source.get("id", "<unknown>")
        entry = _state_source(state, source_id)
        try:
            retrieval = _fetch_with_retry(
                source,
                root=root,
                now=now,
                state=entry,
                options=adapter_options or {},
            )
        except source_adapters.AdapterError as exc:
            entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
            entry["last_checked_at"] = now
            # A rate limit is a scheduling signal, not a knowledge change and
            # not a defect in the pack. The run is deferred, the last valid
            # version stays active and nothing is written to the records.
            result.outcome = "rate-limited" if exc.rate_limited else "failed"
            result.messages.append(f"{source_id}: {exc.reason}")
            result.audit.append(
                audit_record(
                    run_id=run_id,
                    trigger=trigger,
                    phase="retrieval",
                    subject=source_id,
                    decision="rate-limited" if exc.rate_limited else "failed",
                    reason=exc.reason,
                    policy_version=policy_version,
                    now=now,
                )
            )
            continue

        result.retrievals.append(retrieval.to_record())
        entry["last_checked_at"] = now
        entry["consecutive_failures"] = 0

        if retrieval.not_modified:
            # The server confirmed nothing changed. No candidate, no version,
            # no commit, no pull request.
            result.audit.append(
                audit_record(
                    run_id=run_id,
                    trigger=trigger,
                    phase="change-detection",
                    subject=source_id,
                    decision="not-modified",
                    reason="server responded 304 to the conditional request",
                    policy_version=policy_version,
                    now=now,
                    inputs=[retrieval.content_hash] if retrieval.content_hash else [],
                )
            )
            continue

        if retrieval.etag:
            entry["etag"] = retrieval.etag
        if retrieval.last_modified:
            entry["last_modified"] = retrieval.last_modified

        if entry.get("content_hash") == retrieval.content_hash:
            result.audit.append(
                audit_record(
                    run_id=run_id,
                    trigger=trigger,
                    phase="change-detection",
                    subject=source_id,
                    decision="no-change",
                    reason="content hash unchanged",
                    policy_version=policy_version,
                    now=now,
                    inputs=[retrieval.content_hash],
                )
            )
            continue

        changed_sources.append({"source": source, "retrieval": retrieval})
        result.changed_sources.append(source_id)
        result.audit.append(
            audit_record(
                run_id=run_id,
                trigger=trigger,
                phase="change-detection",
                subject=source_id,
                decision="changed",
                reason="content hash differs from recorded hash",
                policy_version=policy_version,
                now=now,
                inputs=[retrieval.content_hash],
            )
        )

    # A rate limit is not a failure of the pack and not a no-change result: it
    # is a deferred run. Both terminate the run before any candidate exists,
    # and both must survive the no-change branch below.
    if result.outcome in {"failed", "rate-limited"}:
        if result.outcome == "failed":
            state["counters"]["failures"] = state.get("counters", {}).get("failures", 0) + 1
        result.finished_at = now
        _finish(pack_dir, state, result, now, apply_state)
        return result

    if not changed_sources:
        result.outcome = "no-change"
        result.finished_at = now
        _finish(pack_dir, state, result, now, apply_state)
        return result

    # --- effective automation level --------------------------------------
    level = automation.get("level", "detect")
    for change in changed_sources:
        source = change["source"]
        ceiling = RISK_CEILING.get(source.get("risk_class", "high"), "detect")
        declared = source.get("automation_level")
        if declared:
            ceiling = _min_level(ceiling, declared)
        level = _min_level(level, ceiling)
    result.effective_level = level

    # --- candidate --------------------------------------------------------
    build_candidate(pack_dir, candidate_dir)
    result.candidate_path = candidate_dir
    try:
        for change in changed_sources:
            retrieval = change["retrieval"]
            source = change["source"]
            if source.get("mapping") and source.get("transformation"):
                apply_mapped_candidate(candidate_dir, source, retrieval)
            else:
                payload = json.loads(retrieval.content.decode("utf-8"))
                normalized = normalize_release_notes(payload)
                apply_release_note_candidate(candidate_dir, normalized, retrieval)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        json_mapping.MappingError,
        UpdateError,
    ) as exc:
        reason = f"candidate generation failed: {exc}"
        result.outcome = "quarantined"
        result.messages.append(reason)
        result.quarantine_path = quarantine(pack_dir, candidate_dir, candidate_id, reason, now)
        result.audit.append(
            audit_record(
                run_id=run_id,
                trigger=trigger,
                phase="candidate",
                subject=candidate_id,
                decision="quarantined",
                reason=reason,
                policy_version=policy_version,
                now=now,
            )
        )
        state["counters"]["failures"] = state.get("counters", {}).get("failures", 0) + 1
        result.finished_at = now
        _finish(pack_dir, state, result, now, apply_state)
        return result

    # --- gates ------------------------------------------------------------
    result.gates = run_gates(candidate_dir, policy, schemas, root)
    blocking = [gate for gate in result.gates if gate.outcome == "fail"]
    for gate in result.gates:
        result.audit.append(
            audit_record(
                run_id=run_id,
                trigger=trigger,
                phase="gate",
                subject=f"{candidate_id}:{gate.name}",
                decision=gate.outcome,
                reason=gate.detail or gate.outcome,
                policy_version=policy_version,
                now=now,
            )
        )

    if blocking:
        reason = "; ".join(f"{gate.name}: {gate.detail}" for gate in blocking)
        result.outcome = "quarantined"
        result.messages.append(reason)
        result.quarantine_path = quarantine(pack_dir, candidate_dir, candidate_id, reason, now)
        state.setdefault("quarantine", []).append(
            {"candidate_id": candidate_id, "quarantined_at": now, "reason": reason[:500]}
        )
        state["counters"]["failures"] = state.get("counters", {}).get("failures", 0) + 1
        result.finished_at = now
        _finish(pack_dir, state, result, now, apply_state)
        return result

    # --- version ----------------------------------------------------------
    increment = compute_increment(pack_dir, candidate_dir)
    current = state.get("last_valid_version") or "0.0.0"
    result.proposed_version = bump(current, increment)
    result.outcome = "candidate-ready" if level != "detect" else "change-detected"
    result.audit.append(
        audit_record(
            run_id=run_id,
            trigger=trigger,
            phase="promotion",
            subject=candidate_id,
            decision=result.outcome,
            reason=f"{increment} increment to {result.proposed_version} at level {level}",
            policy_version=policy_version,
            now=now,
        )
    )

    if level == "detect":
        # Detection only: report and discard. The pack is untouched.
        rollback(pack_dir, candidate_dir)
        result.candidate_path = None

    state["counters"]["candidates"] = state.get("counters", {}).get("candidates", 0) + 1
    for change in changed_sources:
        entry = _state_source(state, change["source"]["id"])
        entry["content_hash"] = change["retrieval"].content_hash
        entry["last_change_at"] = now

    result.finished_at = now
    _finish(pack_dir, state, result, now, apply_state)
    return result


def _finish(pack_dir: Path, state: dict, result: RunResult, now: str, apply_state: bool) -> None:
    state["pack_id"] = state.get("pack_id") or result.pack_id
    state["last_run"] = {
        "run_id": result.audit[0]["run_id"] if result.audit else "local",
        "started_at": result.started_at,
        "finished_at": now,
        "trigger": result.trigger,
        "outcome": result.outcome,
    }
    state.setdefault("counters", {})
    state["counters"]["runs"] = state["counters"].get("runs", 0) + 1
    if apply_state:
        save_state(pack_dir, state)
        if result.audit:
            append_audit(pack_dir, result.audit, now)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--trigger", default="manual")
    parser.add_argument("--run-id", default="local")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="persist automation state and audit records; without it the run is a dry run",
    )
    args = parser.parse_args(argv)

    try:
        result = run_update(
            args.pack,
            root=args.root,
            trigger=args.trigger,
            run_id=args.run_id,
            apply_state=args.apply,
        )
    except UpdateError as exc:
        print(f"update failed, last valid version stays active: {exc}", file=sys.stderr)
        return 1

    print(f"pack:      {result.pack_id}")
    print(f"outcome:   {result.outcome}")
    print(f"level:     {result.effective_level}")
    if result.changed_sources:
        print(f"changed:   {', '.join(result.changed_sources)}")
    for gate in result.gates:
        print(f"gate:      {gate.name}: {gate.outcome}{' - ' + gate.detail if gate.detail else ''}")
    if result.proposed_version:
        print(f"version:   {result.current_version or '0.0.0'} -> {result.proposed_version}")
    if result.quarantine_path is not None:
        print(f"quarantine: {result.quarantine_path}")
    for message in result.messages:
        print(f"note:      {message}")

    return 1 if result.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
