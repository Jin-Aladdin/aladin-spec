"""Prove that a generated Knowledge Pack repository passes its own CI.

The template's workflows run the tooling from a pinned checkout of this
repository against a pack checked out somewhere else. Those are two
different directories, and the scripts have to be told so.

Getting that wrong is invisible here and fatal there: every generated
repository would have had a red pipeline on its first push, and the failure
would have looked like the pack was broken rather than the invocation. So
these tests reconstruct the layout the workflows create and run the exact
commands they run.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import new_knowledge_pack as bootstrap  # noqa: E402

TEMPLATE_WORKFLOWS = REPOSITORY_ROOT / "templates" / "knowledge-pack-repository" / ".github" / "workflows"

#: Scripts that read the canonical schemas and therefore need to be told
#: where they are when the pack and the tooling live in separate checkouts.
SCHEMA_DEPENDENT = ("validate.py", "update_engine.py")


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> Path:
    """The directory layout the template workflows produce.

    ``pack/`` is the Knowledge Pack repository, ``.aladdin-spec/`` is the
    pinned checkout of this repository.
    """
    root = tmp_path_factory.mktemp("ci")

    bootstrap.create_pack(
        root / "pack",
        pack_id="aladdin-kb-citest",
        name="CI Test Pack",
        description="Generated pack used to prove the template workflows actually run.",
        domain="citest",
    )

    tooling = root / ".aladdin-spec"
    tooling.mkdir()
    shutil.copytree(REPOSITORY_ROOT / "scripts", tooling / "scripts")
    shutil.copytree(REPOSITORY_ROOT / "schemas", tooling / "schemas")

    return root


def run_step(workspace: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *arguments],
        cwd=str(workspace),
        capture_output=True,
        text=True,
        timeout=300,
    )


# ---------------------------------------------------------------------------
# The steps the workflows actually run
# ---------------------------------------------------------------------------


def test_validate_step_succeeds(workspace):
    result = run_step(
        workspace,
        ".aladdin-spec/scripts/validate.py",
        "--root", "pack",
        "--pack", "pack",
        "--schemas", ".aladdin-spec/schemas",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_validate_step_without_schemas_path_fails_loudly(workspace):
    """The defect this test exists for, kept visible.

    Omitting the schema path made the validator look inside the pack, find no
    schemas, and report every record as unvalidatable. The pack was fine.
    """
    result = run_step(
        workspace,
        ".aladdin-spec/scripts/validate.py",
        "--root", "pack",
        "--pack", "pack",
    )
    assert result.returncode != 0
    assert "schema directory not found" in (result.stdout + result.stderr)


def test_security_step_succeeds(workspace):
    result = run_step(
        workspace,
        ".aladdin-spec/scripts/security_scan.py",
        "--root", "pack",
        "--pack", "pack",
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_security_step_succeeds_on_a_real_checkout(tmp_path):
    """A pack in CI is a git working copy, and .git is not pack content.

    Found on the first real repository: the scanner walked .git and reported
    hooks, config and packed objects as undeclared file types. Every generated
    repository would have failed its security gate on the first push, for
    content it never authored.
    """
    pack = tmp_path / "pack"
    bootstrap.create_pack(
        pack,
        pack_id="aladdin-kb-checkout",
        name="Checkout Test Pack",
        description="Pack used to check the scanner against a real working copy.",
        domain="checkout",
    )
    subprocess.run(["git", "init", "--quiet", "-b", "main"], cwd=str(pack), check=True)
    subprocess.run(["git", "add", "-A"], cwd=str(pack), check=True, capture_output=True)
    assert (pack / ".git").is_dir()

    from security_scan import scan_pack

    findings = scan_pack(pack, pack)
    assert findings == [], [str(f) for f in findings]


def test_update_engine_step_succeeds(workspace):
    result = run_step(
        workspace,
        ".aladdin-spec/scripts/update_engine.py",
        "--root", "pack",
        "--pack", "pack",
        "--schemas", ".aladdin-spec/schemas",
        "--trigger", "manual",
        "--run-id", "test",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # A generated pack ships with automation off, so this is the expected
    # outcome rather than a silent no-op.
    assert "disabled" in result.stdout


def test_build_step_succeeds(workspace):
    result = run_step(
        workspace,
        ".aladdin-spec/scripts/build_artifact.py",
        "--pack", "pack",
        "--out", "dist",
        "--source-commit", "0" * 40,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (workspace / "dist").is_dir()


def test_health_step_succeeds(workspace):
    result = run_step(
        workspace,
        ".aladdin-spec/scripts/automation_health.py",
        "--root", "pack",
        "--check", "validate=pass",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (workspace / "pack" / "automation" / "health.json").is_file()


# ---------------------------------------------------------------------------
# The workflows must keep passing the paths
# ---------------------------------------------------------------------------


def workflow_texts() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(TEMPLATE_WORKFLOWS.glob("*.yml"))}


@pytest.mark.parametrize("script", SCHEMA_DEPENDENT)
def test_every_schema_dependent_invocation_passes_the_schema_path(script):
    """A script that reads schemas must be told where they are.

    The pack repository does not contain them: they come from the pinned
    specification checkout.
    """
    for name, text in workflow_texts().items():
        # Normalize line continuations so a multi-line invocation reads as one.
        flattened = re.sub(r"\\\s*\n\s*", " ", text)
        for line in flattened.splitlines():
            if f"scripts/{script}" not in line:
                continue
            assert "--schemas .aladdin-spec/schemas" in line, (
                f"{name} invokes {script} without a schema path:\n  {line.strip()}"
            )


def test_workflows_reference_the_tooling_from_the_pinned_checkout():
    for name, text in workflow_texts().items():
        for match in re.findall(r"python\s+(\S*scripts/[a-z_]+\.py)", text):
            assert match.startswith(".aladdin-spec/"), (
                f"{name} runs {match}, which would look for tooling inside the pack"
            )


def test_workflows_check_out_the_pack_into_its_own_directory():
    """Both checkouts need a path, otherwise the second overwrites the first."""
    for name, text in workflow_texts().items():
        document = yaml.safe_load(text)
        for job in document["jobs"].values():
            checkouts = [
                step for step in job.get("steps", []) if "actions/checkout" in str(step.get("uses", ""))
            ]
            if len(checkouts) < 2:
                continue
            paths = [step.get("with", {}).get("path") for step in checkouts]
            assert all(paths), f"{name} has two checkouts and at least one has no path"
            assert len(set(paths)) == len(paths), f"{name} checks out twice into the same path"


# ---------------------------------------------------------------------------
# Build tooling is repository content, not pack content
# ---------------------------------------------------------------------------


def test_build_tooling_does_not_fail_the_security_gate(tmp_path):
    """ADR-0003 permits data importers and conversion tools in a repository.

    Found while building the first real pack: a data importer in scripts/
    quarantined every candidate, because the scanner treated repository
    tooling as pack content. The rule it was enforcing is about what reaches
    a consumer, and the artifact builder already excludes these directories.
    """
    from security_scan import scan_pack

    pack = tmp_path / "pack"
    bootstrap.create_pack(
        pack,
        pack_id="aladdin-kb-tooling",
        name="Tooling Test Pack",
        description="Pack used to check that build tooling does not fail the gate.",
        domain="tooling",
    )
    (pack / "scripts").mkdir()
    (pack / "scripts" / "import_something.py").write_text(
        "# a data importer, which ADR-0003 explicitly permits\n", encoding="utf-8"
    )

    findings = scan_pack(pack, pack)
    assert findings == [], [str(f) for f in findings]


def test_build_tooling_never_reaches_the_artifact(tmp_path):
    """Permitted in the repository is not the same as shipped to a consumer."""
    import zipfile

    import build_artifact

    pack = tmp_path / "pack"
    bootstrap.create_pack(
        pack,
        pack_id="aladdin-kb-tooling",
        name="Tooling Test Pack",
        description="Pack used to check that build tooling stays out of artifacts.",
        domain="tooling",
    )
    (pack / "scripts").mkdir()
    (pack / "scripts" / "import_something.py").write_text("# importer\n", encoding="utf-8")

    result = build_artifact.build(pack, tmp_path / "dist", source_commit="0" * 40)
    with zipfile.ZipFile(result.archive) as archive:
        names = archive.namelist()

    assert not any(name.startswith("scripts/") for name in names)
    assert not any(name.endswith(".py") for name in names)
    assert any(name == "aladdin-pack.yml" for name in names)
