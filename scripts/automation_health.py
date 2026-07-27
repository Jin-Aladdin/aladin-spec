#!/usr/bin/env python3
"""Automation health and heartbeat reporter.

Scheduled workflows are disabled after prolonged repository inactivity, so a
repository that relies on automation must be able to observe its own
automation. This script writes ``automation/health.json``: what ran, when it
last succeeded, and whether the automation has gone stale.

The heartbeat updates automation metadata only. It never touches knowledge
content, never changes a version and never creates a release, so a heartbeat
commit can never be mistaken for a knowledge change.

Usage::

    python scripts/automation_health.py --check validate=pass --check docs=pass
    python scripts/automation_health.py --now 2026-07-27T00:00:00Z --stale-after-days 45
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

HEALTH_VERSION = "0.1.0"
AUTOMATION_DIRECTORY = "automation"
HEALTH_FILENAME = "health.json"

DEFAULT_STALE_AFTER_DAYS = 45

VALID_STATUSES = {"pass", "fail", "skipped", "unknown"}


def _parse_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def last_commit_timestamp(root: Path) -> str:
    """Return the committer date of HEAD, or an empty string outside a checkout.

    The command is a fixed argument list. Nothing in it is derived from
    repository content.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%cI"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    raw = completed.stdout.strip()
    if not raw:
        return ""
    try:
        return _format(datetime.fromisoformat(raw))
    except ValueError:
        return ""


def parse_checks(pairs: list[str]) -> dict[str, str]:
    checks: dict[str, str] = {}
    for pair in pairs or []:
        name, _, status = pair.partition("=")
        name = name.strip()
        status = status.strip() or "unknown"
        if not name:
            raise ValueError(f"malformed check {pair!r}, expected name=status")
        if status not in VALID_STATUSES:
            raise ValueError(
                f"unknown status {status!r} for check {name!r}; expected one of "
                + ", ".join(sorted(VALID_STATUSES))
            )
        checks[name] = status
    return checks


def build_report(
    root: Path,
    *,
    now: str,
    checks: dict[str, str],
    stale_after_days: int,
    last_release_version: str = "",
    last_release_at: str = "",
    last_commit_at: str = "",
) -> dict:
    """Assemble the health report and decide whether automation is stale."""
    moment = _parse_timestamp(now)
    reasons: list[str] = []

    days_since_commit = None
    if last_commit_at:
        days_since_commit = (moment - _parse_timestamp(last_commit_at)).days
        if days_since_commit > stale_after_days:
            reasons.append(
                f"no commit for {days_since_commit} days, scheduled workflows may be disabled"
            )

    days_since_release = None
    if last_release_at:
        days_since_release = (moment - _parse_timestamp(last_release_at)).days

    failed = sorted(name for name, status in checks.items() if status == "fail")
    if failed:
        reasons.append("failing checks: " + ", ".join(failed))

    return {
        "health_version": HEALTH_VERSION,
        "generated_at": now,
        "checks": dict(sorted(checks.items())),
        "repository": {
            "last_commit_at": last_commit_at,
            "days_since_commit": days_since_commit,
        },
        "release": {
            "last_version": last_release_version,
            "last_release_at": last_release_at,
            "days_since_release": days_since_release,
        },
        "thresholds": {"stale_after_days": stale_after_days},
        "stale": bool(reasons),
        "reasons": reasons,
        "next_check_due": _format(moment + timedelta(days=1)),
    }


def write_report(root: Path, report: dict) -> Path:
    path = root / AUTOMATION_DIRECTORY / HEALTH_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--now", default="", help="report timestamp, defaults to the current time")
    parser.add_argument(
        "--check",
        action="append",
        dest="checks",
        default=None,
        help="check result as name=status, repeatable",
    )
    parser.add_argument("--stale-after-days", type=int, default=DEFAULT_STALE_AFTER_DAYS)
    parser.add_argument("--last-release-version", default="")
    parser.add_argument("--last-release-at", default="")
    parser.add_argument("--last-commit-at", default="")
    parser.add_argument(
        "--fail-when-stale",
        action="store_true",
        help="exit non-zero when the automation is stale, so a workflow can raise an issue",
    )
    args = parser.parse_args(argv)

    now = args.now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        checks = parse_checks(args.checks)
    except ValueError as exc:
        print(f"invalid arguments: {exc}", file=sys.stderr)
        return 2

    report = build_report(
        args.root,
        now=now,
        checks=checks,
        stale_after_days=args.stale_after_days,
        last_release_version=args.last_release_version,
        last_release_at=args.last_release_at,
        last_commit_at=args.last_commit_at or last_commit_timestamp(args.root),
    )
    path = write_report(args.root, report)

    print(f"health report: {path}")
    print(f"stale:         {report['stale']}")
    for reason in report["reasons"]:
        print(f"reason:        {reason}")

    if report["stale"] and args.fail_when_stale:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
