"""Tests for the Knowledge Pack repository template.

A template that stops validating is worse than no template: it hands a broken
starting point to whoever uses it next. These tests keep it usable, and keep
its safe defaults from being quietly relaxed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from security_scan import scan_pack  # noqa: E402
from validate import load_schemas, validate_pack  # noqa: E402

TEMPLATE = REPOSITORY_ROOT / "templates" / "knowledge-pack-repository"
WORKFLOWS = TEMPLATE / ".github" / "workflows"

REQUIRED_WORKFLOWS = [
    "validate.yml",
    "update-knowledge.yml",
    "release-pack.yml",
    "automation-health.yml",
    "manual-recovery.yml",
]


@pytest.fixture(scope="module")
def schemas() -> dict:
    loaded, findings = load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    assert findings == [], [str(f) for f in findings]
    return loaded


@pytest.fixture(scope="module")
def policy() -> dict:
    return yaml.safe_load((TEMPLATE / "automation" / "update-policy.yml").read_text(encoding="utf-8"))


def test_template_pack_is_valid(schemas):
    # The template is its own repository root once it is copied out.
    findings = validate_pack(TEMPLATE, schemas, TEMPLATE)
    assert findings == [], [str(f) for f in findings]


def test_template_pack_passes_the_security_gate():
    findings = scan_pack(TEMPLATE, TEMPLATE)
    assert findings == [], [str(f) for f in findings]


@pytest.mark.parametrize("name", REQUIRED_WORKFLOWS)
def test_workflow_exists_and_parses(name):
    path = WORKFLOWS / name
    assert path.is_file(), f"{name} is missing from the template"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert document.get("jobs"), f"{name} declares no jobs"


@pytest.mark.parametrize("name", REQUIRED_WORKFLOWS)
def test_workflow_declares_minimal_top_level_permissions(name):
    document = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert document.get("permissions") == {"contents": "read"}, (
        f"{name} must default to read-only permissions; write access belongs in the "
        "individual job that needs it"
    )


@pytest.mark.parametrize("name", ["update-knowledge.yml", "release-pack.yml", "automation-health.yml"])
def test_stateful_workflows_declare_concurrency(name):
    document = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    concurrency = document.get("concurrency")
    assert concurrency, f"{name} must declare a concurrency group"
    assert concurrency.get("cancel-in-progress") is False, (
        f"{name} must not cancel a run in progress; a half-finished update or release "
        "is worse than a delayed one"
    )


def test_scheduled_workflows_avoid_minute_zero():
    for name in ("update-knowledge.yml", "automation-health.yml"):
        document = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
        triggers = document.get(True) or document.get("on")
        schedule = triggers.get("schedule")
        assert schedule, f"{name} declares no schedule"
        for entry in schedule:
            minute = entry["cron"].split()[0]
            assert minute != "0", (
                f"{name} is scheduled at minute 0, the platform-wide congestion window"
            )


def test_update_workflow_supports_manual_and_external_triggers():
    document = yaml.safe_load((WORKFLOWS / "update-knowledge.yml").read_text(encoding="utf-8"))
    triggers = document.get(True) or document.get("on")
    assert "workflow_dispatch" in triggers, "manual recovery requires workflow_dispatch"
    assert "repository_dispatch" in triggers, "a sentinel requires repository_dispatch"


def test_template_automation_starts_disabled(policy):
    assert policy["automation"]["enabled"] is False
    assert policy["automation"]["level"] == "detect"
    assert policy["automation"]["failure_mode"] == "keep-last-valid"


def test_template_source_starts_untrusted(policy):
    source = policy["sources"][0]
    assert source["enabled"] is False
    assert source["risk_class"] == "high"
    assert source["automation_level"] == "detect"
    assert source["trust"]["level"] == "unknown"
    assert source["license"]["policy"] == "unclear"


def test_template_declares_every_gate_as_required(policy):
    assert set(policy["gates"].values()) == {"required"}


def test_template_documents_recovery_and_maintainers():
    for name in ("README.adoc", "RECOVERY.adoc", "MAINTAINERS.adoc", "SECURITY.adoc"):
        path = TEMPLATE / name
        assert path.is_file(), f"{name} is missing from the template"
        assert path.read_text(encoding="utf-8").strip(), f"{name} is empty"


def test_pull_request_is_only_opened_for_a_ready_candidate():
    """A no-change run must not try to open a pull request.

    Found on the first real pack: the step ran unconditionally and failed on
    a branch that was never created, turning a correct no-change run into a
    red pipeline.
    """
    workflow = yaml.safe_load(
        (WORKFLOWS / "update-knowledge.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["update"]["steps"]
    pr_steps = [s for s in steps if "create-pull-request" in str(s.get("uses", ""))]
    assert pr_steps, "the update workflow opens no pull request at all"
    for step in pr_steps:
        condition = step.get("if", "")
        assert "candidate-ready" in condition, (
            "the pull request step must be guarded by the engine outcome"
        )
