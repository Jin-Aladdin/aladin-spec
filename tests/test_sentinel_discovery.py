"""Tests for automatic Knowledge Pack discovery.

Discovery decides what gets watched. The dangerous failure is not adding
something wrong: it is silently dropping something that was being watched,
because then the repository goes quiet and nothing reports it.

Every test here checks that discovery adds carefully and removes never.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import sentinel_discover as discovery  # noqa: E402


def inventory_with(*repositories: str) -> dict:
    return {
        "inventory_version": "0.1.0",
        "defaults": {"commit_max_age_days": 120},
        "repositories": [
            {"repository": name, "role": "knowledge-pack", "thresholds": {}}
            for name in repositories
        ],
    }


def candidate(name: str, *, archived: bool = False, is_pack: bool = True, reason: str = ""):
    return discovery.Candidate(repository=name, archived=archived, is_pack=is_pack, reason=reason)


# ---------------------------------------------------------------------------
# Adding
# ---------------------------------------------------------------------------


def test_a_new_pack_is_added():
    inventory, added, _ = discovery.merge(
        inventory_with("owner/aladdin-spec"), [candidate("owner/aladdin-kb-weather")]
    )
    assert added == ["owner/aladdin-kb-weather"]
    assert any(e["repository"] == "owner/aladdin-kb-weather" for e in inventory["repositories"])


def test_a_known_pack_is_not_added_twice():
    _, added, _ = discovery.merge(
        inventory_with("owner/aladdin-kb-weather"), [candidate("owner/aladdin-kb-weather")]
    )
    assert added == []


def test_a_discovered_entry_starts_with_recovery_disabled():
    """Reaching into another repository is a decision, not a default."""
    inventory, _, _ = discovery.merge(inventory_with(), [candidate("owner/aladdin-kb-x")])
    entry = inventory["repositories"][0]
    assert entry["recovery"]["enabled"] is False


def test_a_discovered_entry_declines_the_release_check():
    """A pack that never published cannot be judged on release age."""
    inventory, _, _ = discovery.merge(inventory_with(), [candidate("owner/aladdin-kb-x")])
    assert inventory["repositories"][0]["thresholds"]["release_max_age_days"] is None


def test_a_discovered_entry_says_where_it_came_from():
    inventory, _, _ = discovery.merge(inventory_with(), [candidate("owner/aladdin-kb-x")])
    assert "automatically" in inventory["repositories"][0]["notes"]


# ---------------------------------------------------------------------------
# Refusing
# ---------------------------------------------------------------------------


def test_an_archived_repository_is_skipped():
    _, added, skipped = discovery.merge(
        inventory_with(), [candidate("owner/aladdin-kb-old", archived=True)]
    )
    assert added == []
    assert any("archived" in note for note in skipped)


def test_a_repository_without_a_manifest_is_skipped():
    """The name is a convention; the manifest is the evidence.

    Watching a repository that only looks like a pack produces findings
    nobody can act on.
    """
    _, added, skipped = discovery.merge(
        inventory_with(),
        [candidate("owner/aladdin-kb-empty", is_pack=False, reason="no aladdin-pack.yml")],
    )
    assert added == []
    assert any("aladdin-pack.yml" in note for note in skipped)


# ---------------------------------------------------------------------------
# Never removing
# ---------------------------------------------------------------------------


def test_an_entry_missing_from_discovery_is_kept():
    """A repository that stopped answering is the case worth reporting.

    Renamed, made private, or an API error: all three look the same from
    outside, and all three mean the sentinel should keep watching and let the
    reachability check speak.
    """
    inventory, added, _ = discovery.merge(
        inventory_with("owner/aladdin-kb-gone", "owner/aladdin-spec"), []
    )
    names = [e["repository"] for e in inventory["repositories"]]
    assert "owner/aladdin-kb-gone" in names
    assert added == []


def test_existing_thresholds_are_never_overwritten():
    """Thresholds are a maintainer's judgement, not a default to reassert."""
    inventory = inventory_with()
    inventory["repositories"].append(
        {
            "repository": "owner/aladdin-kb-weather",
            "role": "knowledge-pack",
            "thresholds": {"update_max_age_days": 7},
            "notes": "tightened by hand",
        }
    )
    merged, added, _ = discovery.merge(inventory, [candidate("owner/aladdin-kb-weather")])
    entry = next(e for e in merged["repositories"] if e["repository"] == "owner/aladdin-kb-weather")
    assert entry["thresholds"]["update_max_age_days"] == 7
    assert entry["notes"] == "tightened by hand"
    assert added == []


def test_non_pack_repositories_in_the_inventory_are_left_alone():
    inventory, _, _ = discovery.merge(
        inventory_with("owner/aladdin-spec", "owner/aladdin-sentinel"),
        [candidate("owner/aladdin-kb-weather")],
    )
    names = [e["repository"] for e in inventory["repositories"]]
    assert "owner/aladdin-spec" in names
    assert "owner/aladdin-sentinel" in names


# ---------------------------------------------------------------------------
# The result must remain valid
# ---------------------------------------------------------------------------


def test_the_merged_inventory_still_validates():
    import json

    from jsonschema import Draft202012Validator

    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "sentinel-inventory.schema.json").read_text(encoding="utf-8")
    )
    inventory = {
        "inventory_version": "0.1.0",
        "defaults": {"commit_max_age_days": 120, "validation_max_age_days": 45},
        "repositories": [
            {"repository": "owner/aladdin-spec", "role": "specification"},
        ],
    }
    merged, _, _ = discovery.merge(inventory, [candidate("owner/aladdin-kb-weather")])

    errors = list(Draft202012Validator(schema).iter_errors(merged))
    assert errors == [], [e.message for e in errors]


def test_the_merged_inventory_round_trips_through_yaml():
    """It is written back as YAML, so it has to survive that."""
    inventory, _, _ = discovery.merge(inventory_with(), [candidate("owner/aladdin-kb-x")])
    text = yaml.safe_dump(inventory, sort_keys=False, allow_unicode=True)
    assert yaml.safe_load(text) == inventory


# ---------------------------------------------------------------------------
# The workflow that runs it
# ---------------------------------------------------------------------------


def test_the_sentinel_workflow_runs_discovery_before_validating():
    """Discovery writes the inventory the next step validates."""
    workflow = yaml.safe_load(
        (
            REPOSITORY_ROOT
            / "templates"
            / "sentinel-repository"
            / ".github"
            / "workflows"
            / "sentinel.yml"
        ).read_text(encoding="utf-8")
    )
    names = [step["name"] for step in workflow["jobs"]["watch"]["steps"]]
    assert "Discover new Knowledge Pack repositories" in names
    assert names.index("Discover new Knowledge Pack repositories") < names.index(
        "Validate the inventory before acting on it"
    )


def test_the_sentinel_workflow_commits_only_what_discovery_added():
    workflow = yaml.safe_load(
        (
            REPOSITORY_ROOT
            / "templates"
            / "sentinel-repository"
            / ".github"
            / "workflows"
            / "sentinel.yml"
        ).read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["watch"]["steps"]
    commit = next(s for s in steps if s["name"] == "Commit newly discovered repositories")
    assert "steps.discovery.outputs.added == 'true'" in commit["if"]
