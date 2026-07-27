#!/usr/bin/env python3
"""Create a Knowledge Pack repository from the controlled template.

A new knowledge repository must never be created without an automation
foundation (ADR-0005). Copying the template by hand invites two failures:
placeholder values survive into a published pack, and the identifier
namespace ends up inconsistent between the manifest, the policy and the
records.

This script does the copy and the substitution, then validates the result
before returning. If the generated pack does not pass the same gates as a
real one, it is not written out as usable.

What it produces is deliberately inert: automation disabled, level detect,
no sources declared. Turning any of that on is a decision a maintainer
makes and a reviewer can see in a diff.

Usage::

    python scripts/new_knowledge_pack.py \\
        --id aladdin-kb-docker \\
        --name "Aladdin Docker Knowledge Pack" \\
        --domain docker \\
        --out ../aladdin-kb-docker
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate  # noqa: E402
from security_scan import scan_pack  # noqa: E402

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = REPOSITORY_ROOT / "templates" / "knowledge-pack-repository"

PACK_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
NAMESPACE_PATTERN = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")

TEMPLATE_PACK_ID = "aladdin-kb-template"
TEMPLATE_NAMESPACE = "template"

#: Files whose contents carry the template identity and must be rewritten.
SUBSTITUTED_SUFFIXES = frozenset({".yml", ".yaml", ".json", ".jsonl", ".adoc"})


class BootstrapError(RuntimeError):
    """The pack could not be created, or the result would not have been valid."""


@dataclass(frozen=True)
class BootstrapResult:
    path: Path
    pack_id: str
    namespace: str
    files: int

    def summary(self) -> str:
        return f"{self.pack_id} at {self.path} ({self.files} files)"


def derive_namespace(pack_id: str) -> str:
    """Derive the identifier namespace from the pack id.

    ``aladdin-kb-docker`` becomes ``docker``. The namespace prefixes every
    record identifier in the pack, so it has to be stable and readable rather
    than clever.
    """
    stem = pack_id
    for prefix in ("aladdin-kb-", "aladdin-"):
        if stem.startswith(prefix):
            stem = stem[len(prefix) :]
            break
    return stem.replace("-", ".") or pack_id


def _substitute(text: str, pack_id: str, name: str, description: str, namespace: str, domain: str) -> str:
    replacements = [
        (TEMPLATE_PACK_ID, pack_id),
        ("Aladdin Knowledge Pack Template", name),
        (f"source:{TEMPLATE_NAMESPACE}.", f"source:{namespace}."),
        (f"claim:{TEMPLATE_NAMESPACE}.", f"claim:{namespace}."),
        (f"evidence:{TEMPLATE_NAMESPACE}.", f"evidence:{namespace}."),
        (f"entity:{TEMPLATE_NAMESPACE}.", f"entity:{namespace}."),
        ("    - template\n", f"    - {domain}\n"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)

    # The manifest description is prose, not an identifier, so it is replaced
    # as a whole block rather than by token.
    text = text.replace(
        "    Starting point for a new Aladdin Knowledge Pack repository. Replace every\n"
        "    template value before publishing anything from this repository.",
        "    " + description,
    )
    return text


def create_pack(
    out_dir: Path,
    *,
    pack_id: str,
    name: str,
    description: str,
    domain: str,
    namespace: str | None = None,
    force: bool = False,
) -> BootstrapResult:
    """Copy the template, substitute the identity, then validate the result."""
    if not PACK_ID_PATTERN.fullmatch(pack_id):
        raise BootstrapError(
            f"pack id {pack_id!r} must be lowercase words separated by hyphens"
        )
    if len(description) < 20:
        raise BootstrapError(
            "the description must be at least 20 characters; the manifest schema "
            "rejects anything shorter, and a pack without a real description is "
            "not discoverable"
        )
    if not PACK_ID_PATTERN.fullmatch(domain):
        raise BootstrapError(f"domain {domain!r} must be lowercase words separated by hyphens")

    namespace = namespace or derive_namespace(pack_id)
    if not NAMESPACE_PATTERN.fullmatch(namespace):
        raise BootstrapError(f"namespace {namespace!r} is not a valid identifier namespace")

    if not TEMPLATE.is_dir():
        raise BootstrapError(f"no template at {TEMPLATE}")

    if out_dir.exists():
        if not force or any(out_dir.iterdir()):
            if not force:
                raise BootstrapError(
                    f"{out_dir} already exists; pass --force to overwrite an empty target"
                )
            shutil.rmtree(out_dir)

    shutil.copytree(TEMPLATE, out_dir)

    written = 0
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file():
            continue
        written += 1
        if path.suffix.lower() not in SUBSTITUTED_SUFFIXES:
            continue
        original = path.read_text(encoding="utf-8")
        updated = _substitute(original, pack_id, name, description, namespace, domain)
        if updated != original:
            path.write_text(updated, encoding="utf-8", newline="\n")

    _verify(out_dir, pack_id)
    return BootstrapResult(path=out_dir, pack_id=pack_id, namespace=namespace, files=written)


def _verify(pack_dir: Path, pack_id: str) -> None:
    """Run the same gates a real repository runs.

    A generated pack that cannot pass validation is worse than no generator:
    it hands someone a starting point that was broken before they touched it.
    """
    schemas, schema_findings = validate.load_schemas(REPOSITORY_ROOT / "schemas", REPOSITORY_ROOT)
    if schema_findings:
        raise BootstrapError("the specification schemas are not clean; cannot verify the result")

    # The generated pack is its own repository root once it is copied out.
    findings = validate.validate_pack(pack_dir, schemas, pack_dir)
    if findings:
        raise BootstrapError(
            "the generated pack does not validate: " + "; ".join(str(f) for f in findings[:5])
        )

    security = scan_pack(pack_dir, pack_dir)
    if security:
        raise BootstrapError(
            "the generated pack fails the security gate: "
            + "; ".join(str(f) for f in security[:5])
        )

    manifest, _ = validate.load_yaml_mapping(pack_dir / validate.MANIFEST_FILENAME, pack_dir)
    if not manifest or (manifest.get("pack") or {}).get("id") != pack_id:
        raise BootstrapError("the generated manifest does not carry the requested pack id")

    policy_path = pack_dir / validate.AUTOMATION_DIRECTORY / validate.POLICY_FILENAME
    policy, _ = validate.load_yaml_mapping(policy_path, pack_dir)
    if not policy or (policy.get("pack") or {}).get("id") != pack_id:
        raise BootstrapError("the generated update policy does not target the generated pack")
    if (policy.get("automation") or {}).get("enabled") is not False:
        raise BootstrapError("a generated pack must start with automation disabled")


def next_steps(result: BootstrapResult) -> str:
    return "\n".join(
        [
            f"Created {result.summary()}",
            "",
            "It validates and passes the security gate. It is also deliberately inert:",
            "automation is disabled, the level is detect, and no real source is declared.",
            "",
            "Next:",
            f"  1. Replace the placeholder records in {result.path.name}/claims, /sources",
            "     and /evidence with real content.",
            "  2. Declare each source in automation/update-policy.yml: adapter, allowlist,",
            "     licensing, risk class and limits.",
            "  3. Fill in MAINTAINERS.adoc with at least two people or roles.",
            "  4. Create the repository and push.",
            "  5. Let the validation workflow run and read it.",
            "  6. Only then set automation.enabled to true, and raise the level one",
            "     step at a time.",
            "  7. Add the repository to the sentinel inventory.",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--id", dest="pack_id", required=True, help="for example aladdin-kb-docker")
    parser.add_argument("--name", required=True, help="human readable pack name")
    parser.add_argument(
        "--description",
        default="",
        help="what this pack contains; at least 20 characters",
    )
    parser.add_argument("--domain", required=True, help="primary domain, for example docker")
    parser.add_argument(
        "--namespace",
        default=None,
        help="identifier namespace; derived from the pack id when omitted",
    )
    parser.add_argument("--out", type=Path, required=True, help="target directory")
    parser.add_argument("--force", action="store_true", help="overwrite an existing target")
    args = parser.parse_args(argv)

    description = args.description or (
        f"Knowledge Pack for {args.domain}. Replace this description with what the "
        f"pack actually contains before publishing."
    )

    try:
        result = create_pack(
            args.out,
            pack_id=args.pack_id,
            name=args.name,
            description=description,
            domain=args.domain,
            namespace=args.namespace,
            force=args.force,
        )
    except BootstrapError as exc:
        print(f"could not create the pack: {exc}", file=sys.stderr)
        return 1

    print(next_steps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
