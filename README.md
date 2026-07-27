Aladin Knowledge Pack Specification

«Open specification for portable, verifiable and versioned knowledge packs for trusted AI systems.»

Status

Pre-Alpha · Specification in development

Aladin Spec is currently in its initial design phase. The first stable specification has not yet been released.

Vision

AI systems need knowledge that is portable, traceable, testable and independent from a single model provider.

Aladin defines an open standard for building Knowledge Packs: versioned data artifacts that can provide structured and source-backed knowledge to AI systems, agents, retrieval pipelines and local language models.

The goal is not to create hundreds of permanently running API servers.

Instead, each knowledge repository acts as a source project that validates and builds optimized artifacts. A central gateway can load, index and serve those artifacts dynamically.

What is a Knowledge Pack?

An Aladin Knowledge Pack is a versioned and machine-readable collection of:

- claims and facts
- sources and provenance
- entities and relationships
- licenses and usage restrictions
- quality and trust metadata
- multilingual content
- compatibility information
- optional search indexes and embeddings
- checksums and build information

Knowledge Packs are designed to remain usable across different:

- language models
- vector databases
- knowledge graphs
- agent frameworks
- retrieval systems
- hosting environments

Core Principles

Portable

Knowledge must not depend on a single AI model, database or cloud provider.

Verifiable

Important claims must be connected to identifiable sources and provenance metadata.

Versioned

Every released Knowledge Pack must have a reproducible and identifiable version.

Declarative

Knowledge Packs primarily contain structured data. They must not require permanently running application servers.

Secure by Default

A Knowledge Pack must not execute arbitrary code inside the consuming AI system.

Backward Compatible

New specification versions should provide migration paths for older Knowledge Packs.

Open and Extensible

The base specification is public and may be implemented by different tools and platforms.

Proposed Architecture

Knowledge Repository
        │
        │ Validation and Build
        ▼
Versioned Knowledge Artifact
        │
        ▼
Artifact Storage and Registry
        │
        ▼
Global Metadata Index
        │
        ▼
Retrieval and Re-Ranking
        │
        ▼
Context Builder
        │
        ▼
AI Model or Agent

Initial Specification Scope

The first specification version will define:

1. Knowledge Pack manifest
2. Claim format
3. Source and provenance format
4. Entity and relationship format
5. Artifact metadata
6. Licensing metadata
7. Trust and quality metadata
8. Specification compatibility
9. Package versioning
10. Checksums and artifact integrity
11. Deprecation and recall procedures
12. Multilingual content
13. Embedding metadata
14. Validation requirements
15. Canonical Knowledge Model

Planned Repository Structure

aladin-spec/
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── GOVERNANCE.md
├── ROADMAP.md
├── schemas/
├── specifications/
├── examples/
├── decisions/
└── tests/

Planned Schema Files

schemas/
├── manifest.schema.json
├── claim.schema.json
├── source.schema.json
├── entity.schema.json
├── relation.schema.json
└── artifact.schema.json

Planned Specification Documents

specifications/
├── knowledge-pack-v1.md
├── source-provenance-v1.md
├── trust-score-v1.md
├── compatibility-v1.md
└── artifact-format-v1.md

Non-Goals

The Aladin Specification does not define:

- one mandatory language model
- one mandatory vector database
- one mandatory embedding provider
- one proprietary AI interface
- autonomous execution of untrusted repository code
- permanent API servers for every Knowledge Pack

Implementations may choose their own infrastructure as long as they follow the public compatibility requirements.

Versioning

The specification will follow Semantic Versioning.

MAJOR.MINOR.PATCH

Example:

1.0.0

- MAJOR: incompatible specification changes
- MINOR: backward-compatible additions
- PATCH: backward-compatible corrections and clarifications

Specification version "1.0.0" has not yet been released.

Project Roadmap

Phase 0 — Foundation

- define terminology
- define public and private boundaries
- document architecture decisions
- create initial schemas
- establish governance and security policies

Phase 1 — Minimal Specification

- create the first manifest schema
- define claims and sources
- build a minimal example Knowledge Pack
- create a standalone validator

Phase 2 — Reference Implementation

- build two real Knowledge Packs
- test artifact generation
- test registry integration
- test retrieval across multiple packs

Phase 3 — Ecosystem

- public registry
- gateway implementation
- SDKs
- MCP integration
- community validation process

Current Development Rule

The specification will be designed before repository generation, gateway development or large-scale Knowledge Pack creation begins.

This prevents incompatible repositories and avoids locking the ecosystem into an untested architecture.

Contributing

Contribution guidelines are currently being prepared.

Until the first contribution policy is published, architectural proposals may be submitted through GitHub Issues.

Security

Security issues should not be published as normal public issues.

A dedicated security policy and private reporting process will be added before the first executable reference implementation is released.

License

This repository is licensed under the "Apache License 2.0" (LICENSE).

The license applies to the specification and files contained in this repository unless a file explicitly states otherwise.

Third-party knowledge and datasets used by future Knowledge Packs may remain subject to their original licenses.

---

Aladin Spec is the foundation for an open ecosystem of portable, source-aware and verifiable AI knowledge.
