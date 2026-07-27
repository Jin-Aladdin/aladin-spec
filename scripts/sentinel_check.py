#!/usr/bin/env python3
"""Watch Aladdin repositories from outside and report the ones that went quiet.

A repository cannot reliably report its own silence. When a platform
disables its scheduled workflows after prolonged inactivity, the heartbeat
that would have noticed is disabled along with everything else. The
observer therefore has to live somewhere else (ADR-0005).

This module answers one question per repository: has anything that should
happen regularly stopped happening. It reads the GitHub API and writes a
report. It never edits knowledge content, never merges and never publishes;
the strongest action it can take is to ask a repository to run a workflow it
already declared.

Separating the evaluation from the API access keeps the decision logic
testable without a network: ``evaluate`` takes observations and returns
findings.

Usage::

    python scripts/sentinel_check.py --inventory inventory.yml
    python scripts/sentinel_check.py --inventory inventory.yml --dispatch
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

SENTINEL_VERSION = "0.1.0"
API_ROOT = "https://api.github.com"
REQUEST_TIMEOUT_SECONDS = 30
USER_AGENT = f"aladdin-sentinel/{SENTINEL_VERSION}"

#: Checks that only make sense for repositories that carry knowledge.
KNOWLEDGE_ROLES = frozenset({"knowledge-pack"})


class SentinelError(RuntimeError):
    """The sentinel could not complete its observation."""


@dataclass
class Observation:
    """What the sentinel could see about one repository."""

    repository: str
    role: str
    reachable: bool = True
    error: str = ""
    last_commit_at: str | None = None
    last_validation_at: str | None = None
    last_update_at: str | None = None
    last_release_at: str | None = None
    last_release_tag: str | None = None
    disabled_workflows: list[str] = field(default_factory=list)


@dataclass
class Finding:
    repository: str
    check: str
    severity: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.repository}: {self.message}"


# ---------------------------------------------------------------------------
# Evaluation, independent of any network access
# ---------------------------------------------------------------------------


def _age_in_days(timestamp: str | None, now: datetime) -> int | None:
    if not timestamp:
        return None
    text = timestamp.replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (now - moment).days


def thresholds_for(entry: dict, defaults: dict) -> dict:
    merged = dict(defaults or {})
    merged.update(entry.get("thresholds") or {})
    return merged


def evaluate(observation: Observation, thresholds: dict, now: datetime) -> list[Finding]:
    """Turn one observation into findings.

    A threshold that is not declared means the check is not performed. That
    is how a repository opts out of a check that does not apply to it, rather
    than the sentinel inventing a default and reporting noise.
    """
    findings: list[Finding] = []

    if not observation.reachable:
        return [
            Finding(
                observation.repository,
                "reachability",
                "critical",
                f"repository could not be read: {observation.error}",
            )
        ]

    checks = [
        ("commit_max_age_days", observation.last_commit_at, "commit-age", "newest commit"),
        (
            "validation_max_age_days",
            observation.last_validation_at,
            "validation-age",
            "last successful validation run",
        ),
        ("release_max_age_days", observation.last_release_at, "release-age", "most recent release"),
    ]

    if observation.role in KNOWLEDGE_ROLES:
        checks.append(
            (
                "update_max_age_days",
                observation.last_update_at,
                "update-age",
                "last successful knowledge update run",
            )
        )

    for key, timestamp, check, description in checks:
        limit = thresholds.get(key)
        if limit is None:
            continue
        age = _age_in_days(timestamp, now)
        if age is None:
            findings.append(
                Finding(
                    observation.repository,
                    check,
                    "warning",
                    f"no {description} could be determined, so its age cannot be judged",
                )
            )
        elif age > limit:
            findings.append(
                Finding(
                    observation.repository,
                    check,
                    "critical" if age > limit * 2 else "warning",
                    f"{description} is {age} days old, above the limit of {limit}",
                )
            )

    if thresholds.get("require_enabled_workflows", True) and observation.disabled_workflows:
        findings.append(
            Finding(
                observation.repository,
                "disabled-workflows",
                "critical",
                "scheduled automation is disabled: "
                + ", ".join(sorted(observation.disabled_workflows)),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# API access
# ---------------------------------------------------------------------------


def _request(path: str, token: str | None) -> object:
    url = path if path.startswith("http") else f"{API_ROOT}{path}"
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def observe(entry: dict, token: str | None) -> Observation:
    """Read the public signals of one repository."""
    repository = entry["repository"]
    observation = Observation(repository=repository, role=entry.get("role", "knowledge-pack"))

    try:
        commits = _request(f"/repos/{repository}/commits?per_page=1", token)
        if isinstance(commits, list) and commits:
            observation.last_commit_at = commits[0]["commit"]["committer"]["date"]

        try:
            release = _request(f"/repos/{repository}/releases/latest", token)
            if isinstance(release, dict):
                observation.last_release_at = release.get("published_at")
                observation.last_release_tag = release.get("tag_name")
        except urllib.error.HTTPError as exc:
            if exc.code != 404:  # 404 simply means no release yet
                raise

        workflows = _request(f"/repos/{repository}/actions/workflows", token)
        if isinstance(workflows, dict):
            for workflow in workflows.get("workflows", []):
                # disabled_inactivity is the state a platform assigns after
                # prolonged quiet. It is the failure this sentinel exists for.
                if workflow.get("state") in {"disabled_inactivity", "disabled_manually"}:
                    observation.disabled_workflows.append(workflow.get("name", "unnamed"))

        runs = _request(
            f"/repos/{repository}/actions/runs?status=success&per_page=30", token
        )
        if isinstance(runs, dict):
            for run in runs.get("workflow_runs", []):
                name = (run.get("name") or "").lower()
                finished = run.get("updated_at")
                if "valid" in name and observation.last_validation_at is None:
                    observation.last_validation_at = finished
                if "update" in name and observation.last_update_at is None:
                    observation.last_update_at = finished

    except urllib.error.HTTPError as exc:
        observation.reachable = False
        observation.error = f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        observation.reachable = False
        observation.error = str(exc)

    return observation


def dispatch_recovery(entry: dict, token: str) -> str:
    """Ask a repository to run a workflow it already declared.

    This is the strongest action the sentinel can take. It starts declared
    automation; it never edits content, merges or publishes.
    """
    recovery = entry.get("recovery") or {}
    event = recovery.get("dispatch_event")
    if not recovery.get("enabled") or not event:
        return "recovery dispatch is not enabled for this repository"

    payload = json.dumps({"event_type": event}).encode("utf-8")
    request = urllib.request.Request(
        f"{API_ROOT}/repos/{entry['repository']}/dispatches", data=payload, method="POST"
    )
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS):
            return f"dispatched {event}"
    except urllib.error.HTTPError as exc:
        return f"dispatch failed with HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return f"dispatch failed: {exc}"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def build_report(
    inventory: dict,
    observations: list[Observation],
    findings: list[Finding],
    now: datetime,
) -> dict:
    by_repository: dict[str, list[Finding]] = {}
    for finding in findings:
        by_repository.setdefault(finding.repository, []).append(finding)

    return {
        "report_version": SENTINEL_VERSION,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "watched": len(observations),
        "healthy": sum(1 for o in observations if not by_repository.get(o.repository)),
        "unhealthy": len(by_repository),
        "repositories": [
            {
                "repository": observation.repository,
                "role": observation.role,
                "reachable": observation.reachable,
                "last_commit_at": observation.last_commit_at,
                "last_validation_at": observation.last_validation_at,
                "last_update_at": observation.last_update_at,
                "last_release_at": observation.last_release_at,
                "last_release_tag": observation.last_release_tag,
                "disabled_workflows": observation.disabled_workflows,
                "findings": [
                    {"check": f.check, "severity": f.severity, "message": f.message}
                    for f in by_repository.get(observation.repository, [])
                ],
            }
            for observation in observations
        ],
    }


def render_markdown(report: dict) -> str:
    lines = [
        "## Sentinel report",
        "",
        f"Watched {report['watched']} repositories: "
        f"{report['healthy']} healthy, {report['unhealthy']} needing attention.",
        "",
        "| Repository | Role | Last commit | Last release | Findings |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in report["repositories"]:
        findings = entry["findings"]
        summary = "none" if not findings else f"{len(findings)}"
        lines.append(
            f"| `{entry['repository']}` | {entry['role']} | "
            f"{entry['last_commit_at'] or 'unknown'} | "
            f"{entry['last_release_tag'] or 'none'} | {summary} |"
        )

    unhealthy = [e for e in report["repositories"] if e["findings"]]
    if unhealthy:
        lines += ["", "### Findings", ""]
        for entry in unhealthy:
            lines.append(f"**`{entry['repository']}`**")
            for finding in entry["findings"]:
                lines.append(f"- {finding['severity']}: {finding['message']}")
            lines.append("")
    else:
        lines += ["", "Every watched repository is within its declared thresholds."]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def load_inventory(path: Path) -> dict:
    if not path.is_file():
        raise SentinelError(f"no inventory at {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SentinelError("inventory must be a YAML mapping")
    if not data.get("repositories"):
        raise SentinelError("inventory declares no repositories")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=Path("sentinel-report.json"))
    parser.add_argument("--markdown", type=Path, default=None)
    parser.add_argument(
        "--dispatch",
        action="store_true",
        help="ask unhealthy repositories to run their declared recovery workflow",
    )
    parser.add_argument(
        "--fail-on-unhealthy",
        action="store_true",
        help="exit non-zero when any watched repository is unhealthy",
    )
    parser.add_argument("--now", default="", help="override the evaluation time, for tests")
    args = parser.parse_args(argv)

    try:
        inventory = load_inventory(args.inventory)
    except SentinelError as exc:
        print(f"sentinel failed: {exc}", file=sys.stderr)
        return 2

    now = (
        datetime.strptime(args.now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if args.now
        else datetime.now(timezone.utc)
    )
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    defaults = inventory.get("defaults") or {}

    observations: list[Observation] = []
    findings: list[Finding] = []
    for entry in inventory["repositories"]:
        if entry.get("enabled") is False:
            continue
        observation = observe(entry, token)
        observations.append(observation)
        entry_findings = evaluate(observation, thresholds_for(entry, defaults), now)
        findings.extend(entry_findings)

        if entry_findings and args.dispatch and token:
            print(f"{entry['repository']}: {dispatch_recovery(entry, token)}")

    report = build_report(inventory, observations, findings, now)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    markdown = render_markdown(report)
    if args.markdown is not None:
        args.markdown.write_text(markdown, encoding="utf-8", newline="\n")
    print(markdown)

    for finding in findings:
        print(str(finding), file=sys.stderr)

    if findings and args.fail_on_unhealthy:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
