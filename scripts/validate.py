#!/usr/bin/env python3
"""Reference validator for the Aladdin Knowledge Pack specification.

The validator checks schema files, pack manifests and JSON Lines
collections without ever executing Knowledge Pack content.

Security boundary (ADR-0003):

* Knowledge Pack content is never imported, evaluated or executed.
* YAML is parsed with ``yaml.safe_load`` only, so no arbitrary Python
  objects can be constructed from a manifest.
* No shell command is ever derived from pack data.
* No network request is made during normal validation; ``url`` and
  ``$id`` values are treated as opaque identifiers and are not resolved.
* Declared entry points must stay inside the pack directory.

Usage::

    python scripts/validate.py
    python scripts/validate.py --pack examples/minimal-pack
    python scripts/validate.py --schemas schemas --pack examples/minimal-pack
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml
from jsonschema.validators import validator_for

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

MANIFEST_FILENAME = "aladdin-pack.yml"
MANIFEST_SCHEMA = "manifest.schema.json"

AUTOMATION_DIRECTORY = "automation"
POLICY_FILENAME = "update-policy.yml"
POLICY_SCHEMA = "update-policy.schema.json"

#: Canonical object identifier prefix per manifest content type.
#:
#: The key is the ``content.content_types`` value used in a manifest, which
#: is also the collection directory and the JSON Lines base name. The
#: ``prefix`` is the canonical identifier namespace defined by ADR-0002.
CONTENT_TYPES: dict[str, dict[str, str]] = {
    "claims": {"prefix": "claim", "schema": "claim.schema.json"},
    "sources": {"prefix": "source", "schema": "source.schema.json"},
    "evidence": {"prefix": "evidence", "schema": "evidence.schema.json"},
    "entities": {"prefix": "entity", "schema": "entity.schema.json"},
    "relations": {"prefix": "relation", "schema": "relation.schema.json"},
    "concepts": {"prefix": "concept", "schema": "concept.schema.json"},
    "translations": {"prefix": "translation", "schema": "translation.schema.json"},
    "conflicts": {"prefix": "conflict", "schema": "conflict.schema.json"},
    "evaluations": {"prefix": "evaluation", "schema": "evaluation.schema.json"},
    "policies": {"prefix": "policy", "schema": "policy.schema.json"},
}

#: Reverse lookup from identifier prefix to content type.
PREFIX_TO_CONTENT_TYPE = {spec["prefix"]: name for name, spec in CONTENT_TYPES.items()}

#: Any string of this shape is treated as a canonical cross reference.
REFERENCE_PATTERN = re.compile(
    r"^(" + "|".join(sorted(PREFIX_TO_CONTENT_TYPE)) + r"):[A-Za-z0-9][A-Za-z0-9._-]*$"
)

#: Object keys whose contents are never interpreted as core references.
#: Extensions belong to third parties and must not be resolved by the core
#: validator (ADR-0002, extension model).
OPAQUE_KEYS = frozenset({"extensions"})


@dataclass(frozen=True)
class Finding:
    """A single validation problem."""

    path: str
    message: str
    line: int | None = None
    record_id: str | None = None

    def __str__(self) -> str:
        location = self.path if self.line is None else f"{self.path}:{self.line}"
        subject = f" {self.record_id}:" if self.record_id else ""
        return f"{location}:{subject} {self.message}"


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


# --------------------------------------------------------------------------
# Schema loading
# --------------------------------------------------------------------------


def load_schemas(schemas_dir: Path, root: Path) -> tuple[dict[str, dict], list[Finding]]:
    """Load every schema file and check it against its own meta-schema."""
    findings: list[Finding] = []
    schemas: dict[str, dict] = {}

    if not schemas_dir.is_dir():
        return schemas, [Finding(_relative(schemas_dir, root), "schema directory not found")]

    seen_ids: dict[str, str] = {}
    for schema_path in sorted(schemas_dir.glob("*.schema.json")):
        rel = _relative(schema_path, root)
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            findings.append(Finding(rel, f"invalid JSON: {exc}", line=exc.lineno))
            continue

        if not isinstance(schema, dict):
            findings.append(Finding(rel, "schema must be a JSON object"))
            continue

        dialect = schema.get("$schema")
        if dialect != "https://json-schema.org/draft/2020-12/schema":
            findings.append(
                Finding(rel, f"expected JSON Schema draft 2020-12, found $schema={dialect!r}")
            )

        schema_id = schema.get("$id")
        if not schema_id:
            findings.append(Finding(rel, "schema is missing a $id"))
        elif schema_id in seen_ids:
            findings.append(Finding(rel, f"$id {schema_id} already used by {seen_ids[schema_id]}"))
        else:
            seen_ids[schema_id] = rel

        validator_cls = validator_for(schema)
        try:
            validator_cls.check_schema(schema)
        except Exception as exc:  # noqa: BLE001 - jsonschema raises SchemaError subclasses
            findings.append(Finding(rel, f"invalid schema definition: {exc}"))
            continue

        schemas[schema_path.name] = schema

    return schemas, findings


def _validator(schema: dict):
    validator_cls = validator_for(schema)
    return validator_cls(schema, format_checker=validator_cls.FORMAT_CHECKER)


def _instance_findings(
    schema: dict, instance: Any, path: str, line: int | None, record_id: str | None
) -> list[Finding]:
    findings = []
    for error in sorted(_validator(schema).iter_errors(instance), key=lambda e: list(e.path)):
        pointer = "/" + "/".join(str(part) for part in error.absolute_path)
        findings.append(Finding(path, f"{pointer}: {error.message}", line=line, record_id=record_id))
    return findings


# --------------------------------------------------------------------------
# JSON Lines handling
# --------------------------------------------------------------------------


def read_jsonl(path: Path, root: Path) -> tuple[list[tuple[int, dict]], list[Finding]]:
    """Read a JSON Lines file as ``(line_number, object)`` pairs."""
    rel = _relative(path, root)
    records: list[tuple[int, dict]] = []
    findings: list[Finding] = []

    text = path.read_text(encoding="utf-8")
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            findings.append(Finding(rel, "blank line is not a valid JSONL record", line=line_number))
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            findings.append(Finding(rel, f"invalid JSON: {exc.msg}", line=line_number))
            continue
        if not isinstance(record, dict):
            findings.append(
                Finding(rel, "each JSONL line must contain exactly one JSON object", line=line_number)
            )
            continue
        records.append((line_number, record))

    if text and not text.endswith("\n"):
        findings.append(Finding(rel, "file should end with a newline character"))

    return records, findings


def iter_references(record: Any) -> Iterator[str]:
    """Yield every canonical reference contained in a record.

    The record's own ``id`` is not a reference. Extension payloads are
    skipped: their contents belong to a third-party namespace and are not
    resolved by the core validator.
    """
    if isinstance(record, dict):
        for key, value in record.items():
            if key in OPAQUE_KEYS or key == "id":
                continue
            yield from iter_references(value)
    elif isinstance(record, list):
        for item in record:
            yield from iter_references(item)
    elif isinstance(record, str) and REFERENCE_PATTERN.match(record):
        yield record


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------


def check_relative_path(value: str, pack_dir: Path, boundary: str = "pack") -> str | None:
    """Return an error message when ``value`` is not a safe contained path."""
    if not value:
        return "path must not be empty"
    if "\\" in value:
        return "path must use forward slashes"
    candidate = Path(value)
    if candidate.is_absolute() or value.startswith("/"):
        return f"path must be relative to the {boundary} directory"
    if ".." in candidate.parts:
        return f"path must not traverse outside the {boundary} directory"
    resolved = (pack_dir / candidate).resolve()
    if not resolved.is_relative_to(pack_dir.resolve()):
        return f"path escapes the {boundary} directory"
    if not resolved.exists():
        return "declared path does not exist"
    if not resolved.is_file():
        return "declared path is not a file"
    return None


# --------------------------------------------------------------------------
# Pack validation
# --------------------------------------------------------------------------


def load_yaml_mapping(path: Path, root: Path) -> tuple[dict | None, list[Finding]]:
    """Parse a YAML file in safe mode and require a top-level mapping."""
    rel = _relative(path, root)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark is not None else None
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        return None, [Finding(rel, f"invalid YAML: {problem}", line=line)]
    if not isinstance(data, dict):
        return None, [Finding(rel, "file must contain a YAML mapping")]
    return data, []


def validate_policy(
    policy_path: Path,
    schemas: dict[str, dict],
    root: Path,
    manifest: dict | None = None,
) -> list[Finding]:
    """Validate an automation update policy.

    Beyond the schema, this checks the two invariants a schema cannot express:
    the policy must belong to the pack it sits in, and a static-file source
    must point at a file that exists inside the repository.
    """
    rel = _relative(policy_path, root)
    policy, findings = load_yaml_mapping(policy_path, root)
    if policy is None:
        return findings

    schema = schemas.get(POLICY_SCHEMA)
    if schema is None:
        findings.append(Finding(rel, f"cannot validate: {POLICY_SCHEMA} was not loaded"))
    else:
        findings.extend(_instance_findings(schema, policy, rel, None, None))

    policy_pack_id = (policy.get("pack") or {}).get("id") if isinstance(policy.get("pack"), dict) else None
    if manifest is not None and isinstance(manifest.get("pack"), dict):
        manifest_pack_id = manifest["pack"].get("id")
        if policy_pack_id and manifest_pack_id and policy_pack_id != manifest_pack_id:
            findings.append(
                Finding(
                    rel,
                    f"policy targets pack {policy_pack_id!r} but the manifest declares "
                    f"{manifest_pack_id!r}",
                )
            )

    sources = policy.get("sources") if isinstance(policy.get("sources"), list) else []
    seen_ids: dict[str, int] = {}
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            continue
        source_id = source.get("id")
        if isinstance(source_id, str):
            if source_id in seen_ids:
                findings.append(
                    Finding(
                        rel,
                        f"duplicate source policy for {source_id}, first declared at "
                        f"sources[{seen_ids[source_id]}]",
                    )
                )
            else:
                seen_ids[source_id] = index

        path_value = source.get("path")
        if isinstance(path_value, str):
            problem = check_relative_path(path_value, root, boundary="repository")
            if problem:
                findings.append(
                    Finding(rel, f"source {source_id} path {path_value!r}: {problem}")
                )

    return findings


def validate_pack(pack_dir: Path, schemas: dict[str, dict], root: Path) -> list[Finding]:
    """Validate one Knowledge Pack directory."""
    manifest_path = pack_dir / MANIFEST_FILENAME
    manifest_rel = _relative(manifest_path, root)

    if not manifest_path.is_file():
        return [Finding(_relative(pack_dir, root), f"missing {MANIFEST_FILENAME}")]

    manifest, findings = load_yaml_mapping(manifest_path, root)
    if manifest is None:
        return findings

    manifest_schema = schemas.get(MANIFEST_SCHEMA)
    if manifest_schema is None:
        findings.append(Finding(manifest_rel, f"cannot validate: {MANIFEST_SCHEMA} was not loaded"))
    else:
        findings.extend(_instance_findings(manifest_schema, manifest, manifest_rel, None, None))

    content = manifest.get("content") if isinstance(manifest.get("content"), dict) else {}
    declared_types = [t for t in (content.get("content_types") or []) if isinstance(t, str)]
    entry_points = [e for e in (content.get("entry_points") or []) if isinstance(e, str)]

    for entry_point in entry_points:
        problem = check_relative_path(entry_point, pack_dir)
        if problem:
            findings.append(Finding(manifest_rel, f"entry point {entry_point!r}: {problem}"))

    # Collections present on disk, keyed by content type.
    records: dict[str, list[tuple[int, dict]]] = {}
    for content_type, spec in CONTENT_TYPES.items():
        collection_path = pack_dir / content_type / f"{content_type}.jsonl"
        if not collection_path.is_file():
            continue
        rows, read_findings = read_jsonl(collection_path, root)
        findings.extend(read_findings)
        records[content_type] = rows

        rel = _relative(collection_path, root)
        if content_type not in declared_types:
            findings.append(
                Finding(rel, f"collection exists but {content_type!r} is not a declared content type")
            )

        schema = schemas.get(spec["schema"])
        if schema is None:
            findings.append(Finding(rel, f"cannot validate: {spec['schema']} was not loaded"))
        else:
            for line_number, record in rows:
                record_id = record.get("id") if isinstance(record.get("id"), str) else None
                findings.extend(_instance_findings(schema, record, rel, line_number, record_id))

        seen: dict[str, int] = {}
        for line_number, record in rows:
            record_id = record.get("id")
            if not isinstance(record_id, str):
                continue
            if not record_id.startswith(spec["prefix"] + ":"):
                findings.append(
                    Finding(
                        rel,
                        f"identifier must start with {spec['prefix']}:",
                        line=line_number,
                        record_id=record_id,
                    )
                )
            if record_id in seen:
                findings.append(
                    Finding(
                        rel,
                        f"duplicate identifier, first seen on line {seen[record_id]}",
                        line=line_number,
                        record_id=record_id,
                    )
                )
            else:
                seen[record_id] = line_number

    for content_type in declared_types:
        if content_type in CONTENT_TYPES and content_type not in records:
            findings.append(
                Finding(
                    manifest_rel,
                    f"content type {content_type!r} is declared but "
                    f"{content_type}/{content_type}.jsonl does not exist",
                )
            )

    findings.extend(_check_references(records, pack_dir, root))

    policy_path = pack_dir / AUTOMATION_DIRECTORY / POLICY_FILENAME
    if policy_path.is_file():
        findings.extend(validate_policy(policy_path, schemas, root, manifest=manifest))

    return findings


def _check_references(
    records: dict[str, list[tuple[int, dict]]], pack_dir: Path, root: Path
) -> list[Finding]:
    """Resolve every canonical cross reference against the loaded records."""
    known: dict[str, set[str]] = {
        content_type: {
            record["id"] for _, record in rows if isinstance(record.get("id"), str)
        }
        for content_type, rows in records.items()
    }

    findings: list[Finding] = []
    for content_type, rows in records.items():
        rel = _relative(pack_dir / content_type / f"{content_type}.jsonl", root)
        for line_number, record in rows:
            record_id = record.get("id") if isinstance(record.get("id"), str) else None
            for reference in sorted(set(iter_references(record))):
                prefix = reference.split(":", 1)[0]
                target_type = PREFIX_TO_CONTENT_TYPE[prefix]
                if target_type not in known:
                    findings.append(
                        Finding(
                            rel,
                            f"reference {reference} cannot be resolved: "
                            f"the pack contains no {target_type} collection",
                            line=line_number,
                            record_id=record_id,
                        )
                    )
                elif reference not in known[target_type]:
                    findings.append(
                        Finding(
                            rel,
                            f"reference {reference} does not exist in {target_type}",
                            line=line_number,
                            record_id=record_id,
                        )
                    )
    return findings


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def discover_packs(examples_dir: Path) -> list[Path]:
    if not examples_dir.is_dir():
        return []
    return sorted(p.parent for p in examples_dir.glob(f"*/{MANIFEST_FILENAME}"))


def validate_repository(
    root: Path = REPOSITORY_ROOT,
    schemas_dir: Path | None = None,
    packs: Iterable[Path] | None = None,
) -> list[Finding]:
    """Validate the schema directory and every discovered Knowledge Pack."""
    schemas_dir = schemas_dir or root / "schemas"
    schemas, findings = load_schemas(schemas_dir, root)

    pack_dirs = list(packs) if packs is not None else discover_packs(root / "examples")
    for pack_dir in pack_dirs:
        findings.extend(validate_pack(pack_dir, schemas, root))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT, help="repository root")
    parser.add_argument("--schemas", type=Path, default=None, help="schema directory")
    parser.add_argument(
        "--pack",
        type=Path,
        action="append",
        dest="packs",
        default=None,
        help="pack directory to validate (repeatable, defaults to examples/*)",
    )
    args = parser.parse_args(argv)

    findings = validate_repository(root=args.root, schemas_dir=args.schemas, packs=args.packs)

    for finding in findings:
        print(finding, file=sys.stderr)

    if findings:
        print(f"\n{len(findings)} problem(s) found.", file=sys.stderr)
        return 1

    print("Validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
