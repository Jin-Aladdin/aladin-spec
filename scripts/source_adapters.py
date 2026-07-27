#!/usr/bin/env python3
"""Source adapters for the Aladdin update engine.

An adapter turns one declared source into one retrieval record plus the
retrieved bytes. Adapters implement the contract in
``specifications/automation-v1.adoc``:

* only the declared input shape is accepted
* network targets are checked against the source allowlist
* timeouts, size limits and redirect limits are enforced
* the response content type is verified
* retrieved bytes are untrusted data and are never executed
* retrieval time, final location and content hash are recorded
* failures are reported as structured errors, never as partial success

The registry is a fixed mapping. An adapter is never selected, imported or
parameterized by Knowledge Pack content (ADR-0003).

Only the ``static-file`` adapter is implemented in this draft. It reads a
fixture inside the repository, which keeps the reference pipeline
deterministic and offline. Network adapters are declared but refuse to run
until their sandbox is specified and tested.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ADAPTER_VERSION = "0.1.0"

#: Adapters that are declared by the policy schema but not implemented yet.
DECLARED_ADAPTERS = (
    "static-file",
    "git-repository",
    "github-release",
    "json-api",
    "feed",
    "html-documentation",
    "pdf-document",
    "structured-dataset",
    "standards-document",
)


class AdapterError(RuntimeError):
    """A retrieval failed in a way the pipeline must record and not retry blindly."""

    def __init__(self, reason: str, *, source_id: str, retryable: bool = False) -> None:
        super().__init__(reason)
        self.reason = reason
        self.source_id = source_id
        self.retryable = retryable


@dataclass(frozen=True)
class Retrieval:
    """The audit record of one retrieval attempt."""

    source_id: str
    adapter: str
    adapter_version: str
    requested: str
    final: str
    retrieved_at: str
    status: str
    media_type: str
    size_bytes: int
    content_hash: str
    redirects: int = 0
    content: bytes = field(default=b"", repr=False, compare=False)

    def to_record(self) -> dict:
        """Return the retrieval record without the retrieved payload."""
        return {
            "source_id": self.source_id,
            "adapter": self.adapter,
            "adapter_version": self.adapter_version,
            "requested_url": self.requested,
            "final_url": self.final,
            "retrieved_at": self.retrieved_at,
            "status": self.status,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "content_hash": self.content_hash,
            "redirects": self.redirects,
        }


def content_hash(data: bytes) -> str:
    """Return the canonical Aladdin content hash of a byte string."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _media_type_for(path: Path) -> str:
    return {
        ".json": "application/json",
        ".jsonl": "application/x-ndjson",
        ".yml": "application/yaml",
        ".yaml": "application/yaml",
        ".csv": "text/csv",
        ".txt": "text/plain",
        ".html": "text/html",
        ".adoc": "text/plain",
    }.get(path.suffix.lower(), "application/octet-stream")


def fetch_static_file(
    source: dict,
    *,
    repository_root: Path,
    now: str | None = None,
) -> Retrieval:
    """Read a fixture stored inside the repository.

    The path is resolved against the repository root and must stay inside it.
    The file is read as bytes and never interpreted as code.
    """
    source_id = source.get("id", "<unknown>")
    declared_path = source.get("path")
    if not declared_path:
        raise AdapterError(
            "the static-file adapter requires a repository-relative path",
            source_id=source_id,
        )
    if "\\" in declared_path or declared_path.startswith("/") or ".." in Path(declared_path).parts:
        raise AdapterError(
            f"unsafe source path {declared_path!r}", source_id=source_id
        )

    target = (repository_root / declared_path).resolve()
    if not target.is_relative_to(repository_root.resolve()):
        raise AdapterError(
            f"source path {declared_path!r} escapes the repository", source_id=source_id
        )
    if target.is_symlink():
        raise AdapterError(f"source path {declared_path!r} is a symbolic link", source_id=source_id)
    if not target.is_file():
        raise AdapterError(
            f"source path {declared_path!r} does not exist", source_id=source_id, retryable=True
        )

    limits = source.get("limits") or {}
    max_bytes = limits.get("max_download_bytes")
    size = target.stat().st_size
    if max_bytes is not None and size > max_bytes:
        raise AdapterError(
            f"source is {size} bytes, above the declared limit of {max_bytes}",
            source_id=source_id,
        )

    media_type = _media_type_for(target)
    allowed_media_types = source.get("allowed_media_types")
    if allowed_media_types and media_type not in allowed_media_types:
        raise AdapterError(
            f"media type {media_type!r} is not in the declared allowlist",
            source_id=source_id,
        )

    data = target.read_bytes()
    return Retrieval(
        source_id=source_id,
        adapter="static-file",
        adapter_version=ADAPTER_VERSION,
        requested=declared_path,
        final=declared_path,
        retrieved_at=now or _utc_now(),
        status="ok",
        media_type=media_type,
        size_bytes=len(data),
        content_hash=content_hash(data),
        redirects=0,
        content=data,
    )


def _unimplemented(name: str) -> Callable[..., Retrieval]:
    def adapter(source: dict, **_: object) -> Retrieval:
        raise AdapterError(
            f"the {name!r} adapter is declared but not implemented in this draft; "
            "network retrieval requires a specified and tested sandbox",
            source_id=source.get("id", "<unknown>"),
        )

    return adapter


#: Fixed adapter registry. Never populated from pack or policy content.
ADAPTERS: dict[str, Callable[..., Retrieval]] = {
    "static-file": fetch_static_file,
    **{name: _unimplemented(name) for name in DECLARED_ADAPTERS if name != "static-file"},
}


def fetch(source: dict, *, repository_root: Path, now: str | None = None) -> Retrieval:
    """Retrieve one declared source through its declared adapter."""
    name = source.get("adapter")
    adapter = ADAPTERS.get(name)
    if adapter is None:
        raise AdapterError(
            f"unknown adapter {name!r}; adapters must come from the fixed registry",
            source_id=source.get("id", "<unknown>"),
        )
    return adapter(source, repository_root=repository_root, now=now)
