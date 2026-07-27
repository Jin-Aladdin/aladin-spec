# Working on Aladdin

Instructions for anyone continuing this project: a person, or an AI assistant
asked to help with it.

This file is Markdown on purpose. It is the one convention this repository
breaks, because AI coding tools look for `AGENTS.md` by name. Everything else
here is AsciiDoc.

Read this first. It is short. The three documents it points at are not.

## What this project is

An open specification for **Knowledge Packs**: versioned, portable files of
structured knowledge where every statement carries the source it came from and
the exact location inside that source.

A Knowledge Pack is data, not software. It is JSON Lines and YAML. It can be
read with any text editor and any JSON parser, with no tool from this project.
That property is the point of the whole design.

## The rules that are not up for negotiation

These come from accepted Architecture Decision Records in `decisions/`. Changing
one requires writing a new ADR, not editing an old one.

1. **A Knowledge Pack never executes code at the consumer.** Not on load, not on
   validation, not on indexing. A source repository may contain build tools; the
   published artifact may not. (ADR-0003)

2. **A successful fetch is not an accepted update.** Retrieval produces a
   candidate. Five gates decide whether it advances. (ADR-0005)

3. **A failure keeps the last valid version active.** Nothing is half-written,
   nothing is deleted to make a gate pass. (ADR-0005)

4. **Confidence is not verification.** `confidence` is an estimate. `status` and
   `review` describe what was actually checked. A high number never implies a
   human looked at it. (ADR-0002)

5. **A source is not evidence.** A source is a document. Evidence is the exact
   location inside it. One reference to a long document does not support every
   claim that cites it. (ADR-0002)

6. **A claim says only what its evidence supports.** If a source establishes
   that an API reports something, the claim says that, not that the something
   is true.

7. **Automation authority is capped by risk class.** Medicine, law, finance,
   security, personal data and unclear licensing never publish automatically,
   whatever the policy says. (ADR-0005)

8. **A language model's output is an untrusted candidate.** A model may not
   assign a truth status, raise confidence, invent a source or evidence, grant a
   licence clearance, or publish an unreviewed claim. (ADR-0005)

## If you are an AI assistant

Rule 8 is about you.

You may draft claims, propose mappings, write import scripts and review
structure. What you produce is a candidate that a human or a gate accepts.

Concretely, do not:

- write a claim without a source and an evidence locator
- raise a `confidence` value to make an evaluation pass
- pick an SPDX licence identifier because a field requires one; if the real
  terms have no SPDX identifier, use `LicenseRef-<something>` and record the
  actual terms
- state that something works when you have not run it

That last one matters most here. This project found ten defects that only
appeared when something ran for real: a scanner that walked `.git`, a workflow
that took its gates from a moving branch, a pull request step that fired when
there was nothing to propose. Every one passed inspection and failed in
practice. **Run it. Read the output. Then say what happened.**

## Where to look

| Question | File |
|---|---|
| How do I create a Knowledge Pack? | `CREATING-A-KNOWLEDGE-PACK.adoc` |
| What are the binding architecture rules? | `decisions/ADR-0001` … `ADR-0006` |
| How does automation work in detail? | `specifications/automation-v1.adoc` |
| What does a record look like? | `schemas/*.schema.json`, `examples/` |
| What happens if the maintainer disappears? | `SUCCESSION.adoc` |
| What must never happen? | `SECURITY.adoc` |
| How are decisions made? | `GOVERNANCE.adoc` |

## Before you commit anything

```
python scripts/validate.py
python scripts/check_docs.py
python scripts/security_scan.py
python -m pytest tests -q
```

All four. Green. CI runs the same commands and will not be gentler.

Documentation is AsciiDoc, not Markdown. Repository content and commit messages
are English. A commit message explains *why*; the diff already shows what.

## Changing a schema

Schemas are frozen per release tag. `$id` names one immutable document at one
specification version (ADR-0006).

- Adding an optional field: minor version, identifiers move with it
- Requiring something new, removing something, changing what a field means:
  major version
- Fixing tooling without touching a schema: patch, identifiers stay

`tests/test_schema_identity.py` enforces that identifiers and version never
drift apart. If it fails, the version is wrong, not the test.

## Adding a source

A source must be declared before it can be used: adapter, domain allowlist,
licensing status, risk class, limits. Automatic retrieval does not imply
permitted reuse.

Two adapters exist: `static-file` and `json-api`. The other seven are declared
and refuse to run. That is deliberate: an unimplemented adapter fails closed
rather than degrading into something weaker.

If a response contains fields your mapping does not read, such as counters or
server timestamps, use `change_detection.method: mapped-values`. Hashing the
whole body reports a change on every run and opens a pull request every time.
This is not hypothetical; it is what the reference example did until it was
fixed.

## What is deliberately not solved

State these honestly rather than implying they are handled.

- **Nobody watches the sentinel.** The regress stops there by choice.
- **One person holds every role.** No technical measure fixes that.
- **Scheduled workflows are disabled after long inactivity.** The heartbeat
  delays this; it does not prevent it.
- **High-risk content is never published automatically.** Without a human
  reviewer, quarantined candidates accumulate. That is the intended behaviour.
- **No mirror outside GitHub is configured.** Backup bundles exist and are
  verified, but they are retained on the same provider.

## The shortest useful summary

Knowledge with a checkable source beats knowledge without one, and a system that
refuses to publish when unsure beats one that publishes confidently and is
wrong. Everything else here follows from those two sentences.
