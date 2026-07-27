"""Tests for the sentinel.

The decision logic is separated from the API access so it can be tested
without a network: `evaluate` takes an observation and returns findings.
Those tests are the ones that matter, because a monitor that misjudges
silence is worse than no monitor.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import sentinel_check  # noqa: E402

TEMPLATE = REPOSITORY_ROOT / "templates" / "sentinel-repository"
NOW = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)


def days_ago(count: int) -> str:
    return (NOW - timedelta(days=count)).strftime("%Y-%m-%dT%H:%M:%SZ")


def observation(**fields) -> sentinel_check.Observation:
    defaults = {
        "repository": "example/repo",
        "role": "knowledge-pack",
        "last_commit_at": days_ago(1),
        "last_validation_at": days_ago(1),
        "last_update_at": days_ago(1),
        "last_release_at": days_ago(1),
    }
    defaults.update(fields)
    return sentinel_check.Observation(**defaults)


THRESHOLDS = {
    "commit_max_age_days": 30,
    "validation_max_age_days": 14,
    "update_max_age_days": 21,
    "release_max_age_days": 90,
    "require_enabled_workflows": True,
}


# ---------------------------------------------------------------------------
# Healthy
# ---------------------------------------------------------------------------


def test_a_recently_active_repository_produces_no_findings():
    assert sentinel_check.evaluate(observation(), THRESHOLDS, NOW) == []


def test_activity_exactly_at_the_limit_is_still_healthy():
    """The threshold is the last acceptable age, not the first failing one."""
    findings = sentinel_check.evaluate(
        observation(last_commit_at=days_ago(30)), THRESHOLDS, NOW
    )
    assert [f for f in findings if f.check == "commit-age"] == []


# ---------------------------------------------------------------------------
# Silence
# ---------------------------------------------------------------------------


def test_stale_commits_are_reported():
    findings = sentinel_check.evaluate(
        observation(last_commit_at=days_ago(45)), THRESHOLDS, NOW
    )
    assert any(f.check == "commit-age" for f in findings)


def test_far_past_the_limit_is_critical():
    findings = sentinel_check.evaluate(
        observation(last_commit_at=days_ago(200)), THRESHOLDS, NOW
    )
    commit = next(f for f in findings if f.check == "commit-age")
    assert commit.severity == "critical"


def test_moderately_past_the_limit_is_a_warning():
    findings = sentinel_check.evaluate(
        observation(last_commit_at=days_ago(40)), THRESHOLDS, NOW
    )
    commit = next(f for f in findings if f.check == "commit-age")
    assert commit.severity == "warning"


def test_stale_validation_is_reported():
    findings = sentinel_check.evaluate(
        observation(last_validation_at=days_ago(60)), THRESHOLDS, NOW
    )
    assert any(f.check == "validation-age" for f in findings)


def test_stale_update_is_reported_for_a_knowledge_pack():
    findings = sentinel_check.evaluate(
        observation(last_update_at=days_ago(60)), THRESHOLDS, NOW
    )
    assert any(f.check == "update-age" for f in findings)


# ---------------------------------------------------------------------------
# Role awareness
# ---------------------------------------------------------------------------


def test_a_specification_repository_is_not_judged_on_knowledge_updates():
    """It runs no updates by design, so their absence is not a fault."""
    findings = sentinel_check.evaluate(
        observation(role="specification", last_update_at=None), THRESHOLDS, NOW
    )
    assert not any(f.check == "update-age" for f in findings)


def test_a_knowledge_pack_without_update_history_is_reported():
    findings = sentinel_check.evaluate(
        observation(role="knowledge-pack", last_update_at=None), THRESHOLDS, NOW
    )
    assert any(f.check == "update-age" for f in findings)


# ---------------------------------------------------------------------------
# Opting out
# ---------------------------------------------------------------------------


def test_an_undeclared_threshold_is_not_checked():
    """Leaving a threshold unset is how a repository opts out of a check."""
    findings = sentinel_check.evaluate(
        observation(last_release_at=days_ago(9999)),
        {"commit_max_age_days": 30},
        NOW,
    )
    assert not any(f.check == "release-age" for f in findings)


def test_an_empty_threshold_set_produces_no_findings():
    assert sentinel_check.evaluate(observation(), {"require_enabled_workflows": False}, NOW) == []


# ---------------------------------------------------------------------------
# The failure the sentinel exists for
# ---------------------------------------------------------------------------


def test_disabled_workflows_are_critical():
    findings = sentinel_check.evaluate(
        observation(disabled_workflows=["Update knowledge"]), THRESHOLDS, NOW
    )
    disabled = next(f for f in findings if f.check == "disabled-workflows")
    assert disabled.severity == "critical"
    assert "Update knowledge" in disabled.message


def test_disabled_workflow_reporting_can_be_turned_off():
    findings = sentinel_check.evaluate(
        observation(disabled_workflows=["Update knowledge"]),
        {**THRESHOLDS, "require_enabled_workflows": False},
        NOW,
    )
    assert not any(f.check == "disabled-workflows" for f in findings)


def test_an_unreachable_repository_is_critical_and_short_circuits():
    """Silence from an unreachable repository must not read as health."""
    findings = sentinel_check.evaluate(
        observation(reachable=False, error="HTTP 404"), THRESHOLDS, NOW
    )
    assert len(findings) == 1
    assert findings[0].check == "reachability"
    assert findings[0].severity == "critical"


def test_a_missing_timestamp_is_reported_rather_than_assumed_fresh():
    findings = sentinel_check.evaluate(
        observation(last_validation_at=None), THRESHOLDS, NOW
    )
    validation = next(f for f in findings if f.check == "validation-age")
    assert "cannot be judged" in validation.message


def test_an_unparseable_timestamp_is_reported():
    findings = sentinel_check.evaluate(
        observation(last_commit_at="not-a-timestamp"), THRESHOLDS, NOW
    )
    assert any(f.check == "commit-age" for f in findings)


# ---------------------------------------------------------------------------
# Threshold merging
# ---------------------------------------------------------------------------


def test_repository_thresholds_override_the_defaults():
    merged = sentinel_check.thresholds_for(
        {"thresholds": {"commit_max_age_days": 5}}, {"commit_max_age_days": 90, "x": 1}
    )
    assert merged["commit_max_age_days"] == 5
    assert merged["x"] == 1


def test_defaults_apply_when_a_repository_declares_none():
    merged = sentinel_check.thresholds_for({}, {"commit_max_age_days": 90})
    assert merged["commit_max_age_days"] == 90


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def test_report_counts_healthy_and_unhealthy():
    healthy = observation(repository="example/healthy")
    unhealthy = observation(repository="example/quiet", last_commit_at=days_ago(400))
    findings = sentinel_check.evaluate(unhealthy, THRESHOLDS, NOW)

    report = sentinel_check.build_report({}, [healthy, unhealthy], findings, NOW)

    assert report["watched"] == 2
    assert report["healthy"] == 1
    assert report["unhealthy"] == 1


def test_markdown_report_names_the_unhealthy_repository():
    unhealthy = observation(repository="example/quiet", last_commit_at=days_ago(400))
    findings = sentinel_check.evaluate(unhealthy, THRESHOLDS, NOW)
    report = sentinel_check.build_report({}, [unhealthy], findings, NOW)

    markdown = sentinel_check.render_markdown(report)
    assert "example/quiet" in markdown
    assert "Findings" in markdown


def test_markdown_report_says_so_when_everything_is_fine():
    report = sentinel_check.build_report({}, [observation()], [], NOW)
    assert "within its declared thresholds" in sentinel_check.render_markdown(report)


# ---------------------------------------------------------------------------
# Recovery dispatch
# ---------------------------------------------------------------------------


def test_recovery_is_refused_when_not_enabled():
    result = sentinel_check.dispatch_recovery(
        {"repository": "example/repo", "recovery": {"enabled": False, "dispatch_event": "x"}},
        token="irrelevant",
    )
    assert "not enabled" in result


def test_recovery_is_refused_without_a_declared_event():
    result = sentinel_check.dispatch_recovery(
        {"repository": "example/repo", "recovery": {"enabled": True}}, token="irrelevant"
    )
    assert "not enabled" in result


# ---------------------------------------------------------------------------
# The shipped template
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def inventory_schema() -> dict:
    return json.loads(
        (REPOSITORY_ROOT / "schemas" / "sentinel-inventory.schema.json").read_text(encoding="utf-8")
    )


def test_template_inventory_validates(inventory_schema):
    inventory = yaml.safe_load((TEMPLATE / "inventory.yml").read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(inventory_schema).iter_errors(inventory), key=lambda e: list(e.path)
    )
    assert errors == [], [f"{list(e.absolute_path)}: {e.message}" for e in errors]


def test_template_inventory_loads_through_the_loader():
    inventory = sentinel_check.load_inventory(TEMPLATE / "inventory.yml")
    assert inventory["repositories"]


def test_template_recovery_starts_disabled():
    """Dispatching into another repository needs a credential that does not
    exist yet, so the template must not pretend otherwise."""
    inventory = yaml.safe_load((TEMPLATE / "inventory.yml").read_text(encoding="utf-8"))
    for entry in inventory["repositories"]:
        recovery = entry.get("recovery") or {}
        assert recovery.get("enabled", False) is False


def test_template_workflow_is_read_only_by_default():
    workflow = yaml.safe_load(
        (TEMPLATE / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8")
    )
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["watch"]["timeout-minutes"]
    assert workflow["concurrency"]["cancel-in-progress"] is False


def test_template_workflow_is_not_scheduled_at_minute_zero():
    workflow = yaml.safe_load(
        (TEMPLATE / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8")
    )
    triggers = workflow.get(True) or workflow.get("on")
    for entry in triggers["schedule"]:
        assert entry["cron"].split()[0] != "0"


def test_template_pins_the_specification_tooling():
    """An unpinned reference means an upstream change alters the watcher."""
    text = (TEMPLATE / ".github" / "workflows" / "sentinel.yml").read_text(encoding="utf-8")
    assert "ref: v0.1.0" in text
    assert "ref: main" not in text


def test_loader_rejects_an_empty_inventory(tmp_path):
    path = tmp_path / "inventory.yml"
    path.write_text("inventory_version: \"0.1.0\"\nrepositories: []\n", encoding="utf-8")
    with pytest.raises(sentinel_check.SentinelError, match="no repositories"):
        sentinel_check.load_inventory(path)


def test_loader_rejects_a_missing_inventory(tmp_path):
    with pytest.raises(sentinel_check.SentinelError, match="no inventory"):
        sentinel_check.load_inventory(tmp_path / "absent.yml")
