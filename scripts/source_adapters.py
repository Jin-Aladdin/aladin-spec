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
import http.client
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import net_guard  # noqa: E402

ADAPTER_VERSION = "0.1.0"

USER_AGENT = f"aladdin-spec-validator/{ADAPTER_VERSION} (+https://github.com/Jin-Aladdin/aladdin-spec)"

#: Media types accepted by the json-api adapter unless a policy narrows them.
#: An HTML response is refused even when its body happens to parse as JSON.
DEFAULT_JSON_MEDIA_TYPES = ("application/json",)
JSON_SUFFIX = "+json"

#: Status codes worth another attempt. Everything else is a decision, not a
#: hiccup, and retrying it only adds load.
RETRYABLE_STATUS = frozenset({408, 425, 500, 502, 503, 504})

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_DOWNLOAD_BYTES = 5_000_000
STREAM_CHUNK_BYTES = 65_536

#: Header names that must never reach a log, an artifact or an audit record.
SENSITIVE_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})

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

    def __init__(
        self,
        reason: str,
        *,
        source_id: str,
        retryable: bool = False,
        rate_limited: bool = False,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.source_id = source_id
        self.retryable = retryable
        self.rate_limited = rate_limited
        self.retry_after_seconds = retry_after_seconds


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
    http_status: int | None = None
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False
    content: bytes = field(default=b"", repr=False, compare=False)

    def to_record(self) -> dict:
        """Return the retrieval record without the retrieved payload.

        No request header is included. Authorization and cookie values must
        never reach an audit file, and the simplest way to guarantee that is
        to never put headers in the record at all.
        """
        record = {
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
        if self.http_status is not None:
            record["http_status"] = self.http_status
        if self.etag:
            record["etag"] = self.etag
        if self.last_modified:
            record["last_modified"] = self.last_modified
        if self.not_modified:
            record["not_modified"] = True
        return record


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


# ---------------------------------------------------------------------------
# json-api
# ---------------------------------------------------------------------------


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection that goes to one screened address.

    Screening a hostname and then letting the socket layer resolve it again is
    a time-of-check to time-of-use gap: the second lookup can return a
    different address, which is exactly how DNS rebinding reaches a loopback
    or metadata endpoint through an allowlisted name.

    The address is therefore pinned to the one that passed screening, while
    the TLS handshake still uses the hostname, so SNI and certificate
    validation stay correct.
    """

    def __init__(self, host: str, *, pinned_address: str, port: int, timeout: float, context):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP against a pinned address. Test-only, never used over the network."""

    def __init__(self, host: str, *, pinned_address: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_address = pinned_address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port), self.timeout, self.source_address
        )


def _media_type_of(content_type: str | None) -> str:
    """Return the bare media type, without parameters, lowercased."""
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def media_type_accepted(media_type: str, allowed: list[str]) -> bool:
    """Decide whether a media type may be parsed as JSON.

    ``application/*+json`` is accepted by suffix, which covers vendor types
    such as ``application/vnd.github+json``. An HTML response is refused even
    when its body happens to parse as JSON: the server declared what it sent,
    and guessing otherwise is how a login page becomes knowledge.
    """
    if not media_type:
        return False
    if media_type in [entry.lower() for entry in allowed]:
        return True
    if media_type.endswith(JSON_SUFFIX):
        return True
    return False


def _headers_for(source: dict, state: dict | None, conditional: bool) -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if conditional and state:
        etag = state.get("etag")
        last_modified = state.get("last_modified")
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
    return headers


def _read_limited(response, limit: int, source_id: str) -> bytes:
    """Read a response body, aborting as soon as the limit is exceeded.

    The body is streamed rather than read in one call, so an oversized or
    endless response is cut off during transfer instead of being held in
    memory first.
    """
    declared = response.getheader("Content-Length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise AdapterError(
                    f"response declares {declared} bytes, above the limit of {limit}",
                    source_id=source_id,
                )
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(STREAM_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise AdapterError(
                f"response exceeded the download limit of {limit} bytes during transfer",
                source_id=source_id,
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _rate_limit_error(response, source_id: str, status: int) -> AdapterError | None:
    """Detect a rate limit, which is a scheduling signal and not a change."""
    remaining = response.getheader("X-RateLimit-Remaining")
    retry_after = response.getheader("Retry-After")

    limited = status == 429 or (status == 403 and remaining == "0")
    if not limited:
        return None

    seconds: int | None = None
    if retry_after and retry_after.isdigit():
        seconds = int(retry_after)
    elif response.getheader("X-RateLimit-Reset"):
        seconds = None

    return AdapterError(
        f"rate limited by the server with HTTP {status}",
        source_id=source_id,
        retryable=False,
        rate_limited=True,
        retry_after_seconds=seconds,
    )


def fetch_json_api(
    source: dict,
    *,
    repository_root: Path,
    now: str | None = None,
    state: dict | None = None,
    allow_plain_http: bool = False,
    allow_private_addresses: bool = False,
    ssl_context: ssl.SSLContext | None = None,
) -> Retrieval:
    """Retrieve one JSON document over HTTPS under the declared limits.

    The two ``allow_*`` parameters exist so the test suite can drive a mock
    server on the loopback interface. They are function parameters, not policy
    fields: nothing in a Knowledge Pack or an update policy can set them.
    """
    source_id = source.get("id", "<unknown>")
    url = source.get("url")
    if not url:
        raise AdapterError("the json-api adapter requires a url", source_id=source_id)

    limits = source.get("limits") or {}
    max_bytes = limits.get("max_download_bytes", DEFAULT_MAX_DOWNLOAD_BYTES)
    max_redirects = limits.get("max_redirects", DEFAULT_MAX_REDIRECTS)
    connect_timeout = limits.get("connect_timeout_seconds", limits.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    read_timeout = limits.get("read_timeout_seconds", limits.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))

    allowed_domains = source.get("allowed_domains") or []
    allowed_media_types = source.get("allowed_media_types") or list(DEFAULT_JSON_MEDIA_TYPES)
    conditional = bool((source.get("conditional_requests") or {}).get("enabled", True))

    try:
        target = net_guard.screen_url(
            url,
            allowed_domains=allowed_domains,
            allow_plain_http=allow_plain_http,
            allow_private_addresses=allow_private_addresses,
        )
    except net_guard.TargetRejected as exc:
        raise AdapterError(exc.reason, source_id=source_id, retryable=False) from exc

    context = ssl_context or ssl.create_default_context()
    # Certificate and hostname verification are never disabled. Stated
    # explicitly because this is the single most common way an adapter like
    # this becomes worthless.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    visited: list[str] = []
    redirects = 0
    request_headers = _headers_for(source, state, conditional)

    while True:
        if target.url in visited:
            raise AdapterError(
                f"redirect loop detected at {target.url}", source_id=source_id, retryable=False
            )
        visited.append(target.url)

        if target.scheme == "https":
            connection = _PinnedHTTPSConnection(
                target.host,
                pinned_address=target.pinned_address,
                port=target.port,
                timeout=connect_timeout,
                context=context,
            )
        else:
            connection = _PinnedHTTPConnection(
                target.host,
                pinned_address=target.pinned_address,
                port=target.port,
                timeout=connect_timeout,
            )

        try:
            path = target.url.split(target.host, 1)[-1]
            path = path[path.index("/"):] if "/" in path else "/"
            connection.request("GET", path, headers=request_headers)
            if connection.sock is not None:
                connection.sock.settimeout(read_timeout)
            response = connection.getresponse()
            status = response.status

            if status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                response.read()
                redirects += 1
                if redirects > max_redirects:
                    raise AdapterError(
                        f"more than {max_redirects} redirects", source_id=source_id, retryable=False
                    )
                try:
                    target = net_guard.screen_redirect(
                        location,
                        previous=target,
                        allowed_domains=allowed_domains,
                        allow_plain_http=allow_plain_http,
                        allow_private_addresses=allow_private_addresses,
                    )
                except net_guard.TargetRejected as exc:
                    raise AdapterError(
                        f"redirect refused: {exc.reason}", source_id=source_id, retryable=False
                    ) from exc
                continue

            if status == 304:
                response.read()
                return Retrieval(
                    source_id=source_id,
                    adapter="json-api",
                    adapter_version=ADAPTER_VERSION,
                    requested=url,
                    final=target.url,
                    retrieved_at=now or _utc_now(),
                    status="not-modified",
                    media_type="",
                    size_bytes=0,
                    content_hash=(state or {}).get("content_hash", ""),
                    redirects=redirects,
                    http_status=304,
                    etag=(state or {}).get("etag"),
                    last_modified=(state or {}).get("last_modified"),
                    not_modified=True,
                    content=b"",
                )

            limited = _rate_limit_error(response, source_id, status)
            if limited is not None:
                response.read()
                raise limited

            if status != 200:
                response.read()
                raise AdapterError(
                    f"server responded with HTTP {status}",
                    source_id=source_id,
                    retryable=status in RETRYABLE_STATUS,
                )

            media_type = _media_type_of(response.getheader("Content-Type"))
            if not media_type:
                response.read()
                raise AdapterError(
                    "response carried no Content-Type", source_id=source_id, retryable=False
                )
            if not media_type_accepted(media_type, allowed_media_types):
                response.read()
                raise AdapterError(
                    f"media type {media_type!r} is not an accepted JSON type",
                    source_id=source_id,
                    retryable=False,
                )

            body = _read_limited(response, max_bytes, source_id)
            etag = response.getheader("ETag")
            last_modified = response.getheader("Last-Modified")

        except (socket.timeout, TimeoutError) as exc:
            raise AdapterError(
                f"request timed out after {read_timeout}s", source_id=source_id, retryable=True
            ) from exc
        except ssl.SSLError as exc:
            raise AdapterError(
                f"TLS failure: {exc}", source_id=source_id, retryable=False
            ) from exc
        except (ConnectionError, socket.gaierror, OSError) as exc:
            if isinstance(exc, AdapterError):
                raise
            raise AdapterError(
                f"connection failed: {exc}", source_id=source_id, retryable=True
            ) from exc
        finally:
            connection.close()

        break

    # The body is data. It is parsed to confirm it is JSON at all, and the
    # parsed value is never executed, imported or evaluated.
    try:
        json.loads(body.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise AdapterError(
            "response body is not valid UTF-8", source_id=source_id, retryable=False
        ) from exc
    except RecursionError as exc:
        raise AdapterError(
            "response body nests too deeply to parse safely",
            source_id=source_id,
            retryable=False,
        ) from exc
    except json.JSONDecodeError as exc:
        raise AdapterError(
            f"response body is not valid JSON: {exc.msg}", source_id=source_id, retryable=False
        ) from exc

    return Retrieval(
        source_id=source_id,
        adapter="json-api",
        adapter_version=ADAPTER_VERSION,
        requested=url,
        final=target.url,
        retrieved_at=now or _utc_now(),
        status="ok",
        media_type=media_type,
        size_bytes=len(body),
        content_hash=content_hash(body),
        redirects=redirects,
        http_status=200,
        etag=etag,
        last_modified=last_modified,
        content=body,
    )


def _unimplemented(name: str) -> Callable[..., Retrieval]:
    def adapter(source: dict, **_: object) -> Retrieval:
        raise AdapterError(
            f"the {name!r} adapter is declared but not implemented in this draft; "
            "network retrieval requires a specified and tested sandbox",
            source_id=source.get("id", "<unknown>"),
        )

    return adapter


#: Adapters implemented so far. The registry is a fixed mapping in source:
#: nothing in a Knowledge Pack or an update policy selects, adds or
#: parameterizes an adapter, and no adapter is ever imported from a path.
IMPLEMENTED_ADAPTERS = ("static-file", "json-api")

ADAPTERS: dict[str, Callable[..., Retrieval]] = {
    "static-file": fetch_static_file,
    "json-api": fetch_json_api,
    **{
        name: _unimplemented(name)
        for name in DECLARED_ADAPTERS
        if name not in IMPLEMENTED_ADAPTERS
    },
}


def fetch(
    source: dict,
    *,
    repository_root: Path,
    now: str | None = None,
    state: dict | None = None,
    **options,
) -> Retrieval:
    """Retrieve one declared source through its declared adapter.

    ``state`` carries the previously recorded validators for conditional
    requests. ``options`` reaches the adapter directly and is never populated
    from pack or policy content.
    """
    name = source.get("adapter")
    adapter = ADAPTERS.get(name)
    if adapter is None:
        raise AdapterError(
            f"unknown adapter {name!r}; adapters must come from the fixed registry",
            source_id=source.get("id", "<unknown>"),
        )
    if adapter is fetch_json_api:
        return adapter(source, repository_root=repository_root, now=now, state=state, **options)
    return adapter(source, repository_root=repository_root, now=now)
