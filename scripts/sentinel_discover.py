#!/usr/bin/env python3
"""Find Knowledge Pack repositories and add them to a sentinel inventory.

A repository that nobody watches is a repository that can go quiet without
anyone noticing. Requiring a manual inventory edit for every new pack makes
that the default outcome: the step that protects against silence is the step
most likely to be skipped.

This script closes that gap. It lists an owner's repositories, keeps the ones
that look like Knowledge Packs, confirms each really is one, and writes the
missing entries into the inventory.

What it deliberately does not do:

* It never removes an entry. A repository that disappeared from the listing
  may have been renamed, made private or hit an API error, and forgetting to
  watch something is exactly the failure this exists to prevent.
* It never changes an existing entry. Thresholds are a maintainer's judgement.
* It never enables recovery dispatch. Reaching into another repository is a
  decision, not a default.

Usage::

    python scripts/sentinel_discover.py --owner Jin-Aladdin --inventory inventory.yml
    python scripts/sentinel_discover.py --owner Jin-Aladdin --inventory inventory.yml --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import yaml

DISCOVERY_VERSION = "0.1.0"
API_ROOT = "https://api.github.com"
TIMEOUT_SECONDS = 30
USER_AGENT = f"aladdin-sentinel-discovery/{DISCOVERY_VERSION}"
PAGE_SIZE = 100
MAX_PAGES = 20

#: Naming convention for a Knowledge Pack repository.
PACK_PREFIX = "aladdin-kb-"

#: The file whose presence proves a repository really is a Knowledge Pack.
#: Matching a name is a guess; finding a manifest is evidence.
MANIFEST_FILENAME = "aladdin-pack.yml"

#: Defaults for a newly discovered pack. Conservative on purpose: a pack the
#: sentinel has never seen gets thresholds loose enough not to cry wolf, and a
#: maintainer tightens them once its rhythm is known.
DISCOVERED_THRESHOLDS = {
    "commit_max_age_days": 180,
    "validation_max_age_days": 45,
    "update_max_age_days": 90,
    # A pack that has never published cannot be judged on release age, and
    # reporting the absence of something that never happened is noise.
    "release_max_age_days": None,
}


class DiscoveryError(RuntimeError):
    """Discovery could not be completed."""


@dataclass(frozen=True)
class Candidate:
    repository: str
    archived: bool
    is_pack: bool
    reason: str = ""


def _request(path: str, token: str | None) -> object:
    url = path if path.startswith("http") else f"{API_ROOT}{path}"
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", USER_AGENT)
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def list_repositories(owner: str, token: str | None) -> list[dict]:
    """List an owner's repositories, following pagination."""
    repositories: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        try:
            batch = _request(f"/users/{owner}/repos?per_page={PAGE_SIZE}&page={page}", token)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Not a user; try the organization endpoint before giving up.
                batch = _request(f"/orgs/{owner}/repos?per_page={PAGE_SIZE}&page={page}", token)
            else:
                raise DiscoveryError(f"could not list repositories for {owner}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise DiscoveryError(f"could not list repositories for {owner}: {exc}") from exc

        if not isinstance(batch, list) or not batch:
            break
        repositories.extend(batch)
        if len(batch) < PAGE_SIZE:
            break
    return repositories


def confirms_as_pack(full_name: str, token: str | None) -> tuple[bool, str]:
    """Check that the repository actually contains a pack manifest.

    Naming is a convention, not a guarantee. A repository called
    ``aladdin-kb-something`` that holds no manifest is not a Knowledge Pack,
    and watching it would produce findings nobody can act on.
    """
    try:
        _request(f"/repos/{full_name}/contents/{MANIFEST_FILENAME}", token)
        return True, ""
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, f"no {MANIFEST_FILENAME}"
        return False, f"HTTP {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, str(exc)


def discover(owner: str, token: str | None) -> list[Candidate]:
    """Return every repository that looks like, and proves to be, a pack."""
    candidates: list[Candidate] = []
    for repository in list_repositories(owner, token):
        name = repository.get("name", "")
        if not name.startswith(PACK_PREFIX):
            continue
        full_name = repository.get("full_name") or f"{owner}/{name}"
        archived = bool(repository.get("archived"))
        is_pack, reason = confirms_as_pack(full_name, token)
        candidates.append(
            Candidate(repository=full_name, archived=archived, is_pack=is_pack, reason=reason)
        )
    return sorted(candidates, key=lambda c: c.repository)


def entry_for(repository: str) -> dict:
    return {
        "repository": repository,
        "role": "knowledge-pack",
        "thresholds": dict(DISCOVERED_THRESHOLDS),
        "recovery": {"enabled": False},
        "notes": (
            "Added automatically by sentinel discovery. Thresholds are the "
            "conservative defaults for a pack whose rhythm is not yet known; "
            "tighten them once it has one."
        ),
    }


def merge(inventory: dict, candidates: list[Candidate]) -> tuple[dict, list[str], list[str]]:
    """Add missing packs. Existing entries are never touched."""
    repositories = inventory.setdefault("repositories", [])
    known = {
        entry.get("repository")
        for entry in repositories
        if isinstance(entry, dict) and entry.get("repository")
    }

    added: list[str] = []
    skipped: list[str] = []

    for candidate in candidates:
        if candidate.repository in known:
            continue
        if candidate.archived:
            skipped.append(f"{candidate.repository}: archived")
            continue
        if not candidate.is_pack:
            skipped.append(f"{candidate.repository}: {candidate.reason}")
            continue
        repositories.append(entry_for(candidate.repository))
        added.append(candidate.repository)

    return inventory, added, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--owner", required=True, help="account or organization to scan")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args(argv)

    if not args.inventory.is_file():
        print(f"no inventory at {args.inventory}", file=sys.stderr)
        return 2

    inventory = yaml.safe_load(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(inventory, dict):
        print("inventory must be a YAML mapping", file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    try:
        candidates = discover(args.owner, token)
    except DiscoveryError as exc:
        print(f"discovery failed: {exc}", file=sys.stderr)
        return 1

    inventory, added, skipped = merge(inventory, candidates)

    print(f"scanned {args.owner}: {len(candidates)} repositories match {PACK_PREFIX}*")
    for repository in added:
        print(f"  added   {repository}")
    for note in skipped:
        print(f"  skipped {note}")
    if not added:
        print("  nothing to add")

    if added and not args.dry_run:
        args.inventory.write_text(
            yaml.safe_dump(inventory, sort_keys=False, allow_unicode=True, width=88),
            encoding="utf-8",
            newline="\n",
        )
        print(f"wrote {args.inventory}")

    # A non-zero exit tells a workflow there is something to commit.
    return 3 if added else 0


if __name__ == "__main__":
    raise SystemExit(main())
