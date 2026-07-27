"""Behaviour tests for the json-api adapter.

These run against a local mock server, so the suite never depends on an
external API staying reachable. The real endpoint is exercised by the
separately dispatched integration workflow.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import source_adapters  # noqa: E402

NOW = "2026-07-27T12:00:00Z"


def source_for(server, path="/release", **overrides) -> dict:
    source = {
        "id": "source:mock.release",
        "adapter": "json-api",
        "url": server.url(path),
        "allowed_domains": ["127.0.0.1"],
        "allowed_media_types": ["application/json"],
        "limits": {
            "max_download_bytes": 1_000_000,
            "timeout_seconds": 5,
            "connect_timeout_seconds": 5,
            "read_timeout_seconds": 5,
            "max_redirects": 3,
        },
    }
    source.update(overrides)
    return source


def fetch(source, options, **kwargs):
    return source_adapters.fetch(source, repository_root=REPOSITORY_ROOT, now=NOW, **options, **kwargs)


# ---------------------------------------------------------------------------
# Success cases
# ---------------------------------------------------------------------------


def test_valid_json_response(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document)
    result = fetch(source_for(mock_server), local_options)

    assert result.status == "ok"
    assert result.http_status == 200
    assert result.media_type == "application/json"
    assert result.size_bytes > 0
    assert result.content_hash.startswith("sha256:")
    assert json.loads(result.content)["tag_name"] == "curl-8_21_0"


def test_vendor_json_media_type_is_accepted(mock_server, local_options, release_document):
    mock_server.add_json(
        "/release", release_document, content_type="application/vnd.github+json; charset=utf-8"
    )
    result = fetch(source_for(mock_server), local_options)
    assert result.status == "ok"
    assert result.media_type == "application/vnd.github+json"


def test_media_type_parameters_are_ignored(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document, content_type="application/json;charset=UTF-8")
    assert fetch(source_for(mock_server), local_options).status == "ok"


def test_identical_content_produces_the_same_hash(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document)
    first = fetch(source_for(mock_server), local_options)
    second = fetch(source_for(mock_server), local_options)
    assert first.content_hash == second.content_hash


def test_redirect_within_the_allowlist_is_followed(mock_server, local_options, release_document):
    mock_server.add("/start", status=302, headers={"Location": mock_server.url("/release")}, body=b"")
    mock_server.add_json("/release", release_document)

    result = fetch(source_for(mock_server, path="/start"), local_options)
    assert result.status == "ok"
    assert result.redirects == 1
    assert result.final.endswith("/release")


def test_relative_redirect_is_followed(mock_server, local_options, release_document):
    mock_server.add("/start", status=302, headers={"Location": "/release"}, body=b"")
    mock_server.add_json("/release", release_document)
    result = fetch(source_for(mock_server, path="/start"), local_options)
    assert result.status == "ok"
    assert result.redirects == 1


def test_etag_and_last_modified_are_recorded(mock_server, local_options, release_document):
    mock_server.add_json(
        "/release",
        release_document,
        headers={"ETag": '"abc123"', "Last-Modified": "Wed, 24 Jun 2026 06:03:04 GMT"},
    )
    result = fetch(source_for(mock_server), local_options)
    assert result.etag == '"abc123"'
    assert result.last_modified == "Wed, 24 Jun 2026 06:03:04 GMT"
    assert result.to_record()["etag"] == '"abc123"'


def test_recorded_validators_are_sent_on_the_next_request(
    mock_server, local_options, release_document
):
    mock_server.add_json("/release", release_document)
    state = {"etag": '"abc123"', "last_modified": "Wed, 24 Jun 2026 06:03:04 GMT"}

    fetch(source_for(mock_server), local_options, state=state)

    headers = mock_server.last_request()["headers"]
    assert headers.get("if-none-match") == '"abc123"'
    assert headers.get("if-modified-since") == "Wed, 24 Jun 2026 06:03:04 GMT"


def test_not_modified_produces_no_content(mock_server, local_options):
    mock_server.add("/release", status=304, body=b"", content_type=None)
    state = {"etag": '"abc123"', "content_hash": "sha256:" + "a" * 64}

    result = fetch(source_for(mock_server), local_options, state=state)

    assert result.not_modified is True
    assert result.status == "not-modified"
    assert result.http_status == 304
    assert result.size_bytes == 0
    assert result.content == b""
    assert result.content_hash == state["content_hash"], "the known hash is preserved"


def test_conditional_requests_can_be_disabled(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document)
    source = source_for(mock_server, conditional_requests={"enabled": False})

    fetch(source, local_options, state={"etag": '"abc123"'})

    headers = mock_server.last_request()["headers"]
    assert "if-none-match" not in headers


def test_no_authorization_header_is_sent_or_recorded(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document)
    result = fetch(source_for(mock_server), local_options)

    sent = mock_server.last_request()["headers"]
    assert "authorization" not in sent
    assert "cookie" not in sent

    record = json.dumps(result.to_record()).lower()
    for forbidden in source_adapters.SENSITIVE_HEADERS:
        assert forbidden not in record


# ---------------------------------------------------------------------------
# Target refusal
# ---------------------------------------------------------------------------


def test_plain_http_is_refused_without_the_test_opt_in(mock_server, release_document):
    mock_server.add_json("/release", release_document)
    with pytest.raises(source_adapters.AdapterError, match="https"):
        source_adapters.fetch(
            source_for(mock_server), repository_root=REPOSITORY_ROOT, now=NOW
        )


def test_host_outside_the_allowlist_is_refused(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document)
    source = source_for(mock_server, allowed_domains=["example.org"])
    with pytest.raises(source_adapters.AdapterError, match="allowlist") as error:
        fetch(source, local_options)
    assert error.value.retryable is False


def test_missing_url_is_refused(local_options):
    with pytest.raises(source_adapters.AdapterError, match="requires a url"):
        source_adapters.fetch(
            {"id": "source:x", "adapter": "json-api"}, repository_root=REPOSITORY_ROOT
        )


def test_embedded_credentials_are_refused(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document)
    source = source_for(mock_server)
    source["url"] = f"http://user:secret@127.0.0.1:{mock_server.port}/release"
    with pytest.raises(source_adapters.AdapterError, match="credentials"):
        fetch(source, local_options)


# ---------------------------------------------------------------------------
# Redirect handling
# ---------------------------------------------------------------------------


def test_redirect_off_the_allowlist_is_refused(mock_server, local_options, release_document):
    mock_server.add(
        "/start", status=302, headers={"Location": "https://evil.test/x"}, body=b""
    )
    with pytest.raises(source_adapters.AdapterError, match="redirect refused"):
        fetch(source_for(mock_server, path="/start"), local_options)


def test_redirect_loop_is_detected(mock_server, local_options):
    mock_server.add("/a", status=302, headers={"Location": mock_server.url("/b")}, body=b"")
    mock_server.add("/b", status=302, headers={"Location": mock_server.url("/a")}, body=b"")
    with pytest.raises(source_adapters.AdapterError, match="redirect loop"):
        fetch(source_for(mock_server, path="/a"), local_options)


def test_too_many_redirects_are_refused(mock_server, local_options, release_document):
    for index in range(6):
        mock_server.add(
            f"/hop{index}",
            status=302,
            headers={"Location": mock_server.url(f"/hop{index + 1}")},
            body=b"",
        )
    mock_server.add_json("/hop6", release_document)

    source = source_for(mock_server, path="/hop0")
    source["limits"]["max_redirects"] = 2
    with pytest.raises(source_adapters.AdapterError, match="more than 2 redirects"):
        fetch(source, local_options)


def test_redirect_to_a_forbidden_scheme_is_refused(mock_server, local_options):
    mock_server.add("/start", status=302, headers={"Location": "file:///etc/passwd"}, body=b"")
    with pytest.raises(source_adapters.AdapterError, match="redirect refused"):
        fetch(source_for(mock_server, path="/start"), local_options)


# ---------------------------------------------------------------------------
# Content type
# ---------------------------------------------------------------------------


def test_html_response_is_refused_even_when_the_body_is_json(mock_server, local_options):
    mock_server.add("/release", body=b'{"tag_name": "x"}', content_type="text/html")
    with pytest.raises(source_adapters.AdapterError, match="not an accepted JSON type") as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.retryable is False


def test_missing_content_type_is_refused(mock_server, local_options):
    mock_server.add("/release", body=b"{}", content_type=None)
    with pytest.raises(source_adapters.AdapterError, match="no Content-Type"):
        fetch(source_for(mock_server), local_options)


def test_text_plain_is_refused(mock_server, local_options):
    mock_server.add("/release", body=b"{}", content_type="text/plain")
    with pytest.raises(source_adapters.AdapterError, match="not an accepted JSON type"):
        fetch(source_for(mock_server), local_options)


@pytest.mark.parametrize(
    "media_type,accepted",
    [
        ("application/json", True),
        ("application/vnd.github+json", True),
        ("application/ld+json", True),
        ("text/html", False),
        ("text/plain", False),
        ("application/xml", False),
        ("", False),
    ],
)
def test_media_type_acceptance(media_type, accepted):
    assert source_adapters.media_type_accepted(media_type, ["application/json"]) is accepted


# ---------------------------------------------------------------------------
# Size, JSON validity, depth
# ---------------------------------------------------------------------------


def test_oversized_declared_response_is_refused(mock_server, local_options):
    mock_server.add("/release", body=b'{"padding": "' + b"x" * 50_000 + b'"}')
    source = source_for(mock_server)
    source["limits"]["max_download_bytes"] = 1_000
    with pytest.raises(source_adapters.AdapterError, match="above the limit") as error:
        fetch(source, local_options)
    assert error.value.retryable is False


def test_oversized_undeclared_response_is_cut_off_during_transfer(mock_server, local_options):
    """A body larger than the limit must abort mid-transfer, not after buffering."""
    body = b'{"padding": "' + b"x" * 200_000 + b'"}'
    mock_server.add("/release", body=body, headers={"Transfer-Encoding": "chunked"})
    source = source_for(mock_server)
    source["limits"]["max_download_bytes"] = 1_000
    with pytest.raises(source_adapters.AdapterError, match="limit"):
        fetch(source, local_options)


def test_invalid_json_is_refused(mock_server, local_options):
    mock_server.add("/release", body=b"{not json")
    with pytest.raises(source_adapters.AdapterError, match="not valid JSON") as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.retryable is False


def test_non_utf8_body_is_refused(mock_server, local_options):
    mock_server.add("/release", body=b"\xff\xfe\x00invalid")
    with pytest.raises(source_adapters.AdapterError, match="UTF-8"):
        fetch(source_for(mock_server), local_options)


def test_deeply_nested_json_does_not_crash_the_adapter(mock_server, local_options):
    """A nesting bomb either parses or is refused, but never escapes as a crash."""
    depth = 5_000
    body = (b"[" * depth) + (b"]" * depth)
    mock_server.add("/release", body=body)
    try:
        result = fetch(source_for(mock_server), local_options)
    except source_adapters.AdapterError as error:
        assert error.retryable is False
    else:
        assert result.status == "ok"


# ---------------------------------------------------------------------------
# Status codes and retry classification
# ---------------------------------------------------------------------------


def test_not_found_is_not_retryable(mock_server, local_options):
    with pytest.raises(source_adapters.AdapterError, match="HTTP 404") as error:
        fetch(source_for(mock_server, path="/missing"), local_options)
    assert error.value.retryable is False


def test_server_error_is_retryable(mock_server, local_options):
    mock_server.add("/release", status=500, body=b"{}")
    with pytest.raises(source_adapters.AdapterError, match="HTTP 500") as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.retryable is True


def test_service_unavailable_is_retryable(mock_server, local_options):
    mock_server.add("/release", status=503, body=b"{}")
    with pytest.raises(source_adapters.AdapterError) as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.retryable is True


def test_client_error_is_not_retryable(mock_server, local_options):
    mock_server.add("/release", status=400, body=b"{}")
    with pytest.raises(source_adapters.AdapterError) as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.retryable is False


def test_rate_limit_is_flagged_and_not_retried(mock_server, local_options):
    mock_server.add("/release", status=429, body=b"{}", headers={"Retry-After": "60"})
    with pytest.raises(source_adapters.AdapterError, match="rate limited") as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.rate_limited is True
    assert error.value.retryable is False
    assert error.value.retry_after_seconds == 60


def test_github_style_rate_limit_is_recognized(mock_server, local_options):
    """GitHub answers an exhausted quota with 403 and a remaining counter of 0."""
    mock_server.add(
        "/release", status=403, body=b"{}", headers={"X-RateLimit-Remaining": "0"}
    )
    with pytest.raises(source_adapters.AdapterError, match="rate limited") as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.rate_limited is True


def test_forbidden_without_rate_limit_headers_is_a_plain_failure(mock_server, local_options):
    mock_server.add("/release", status=403, body=b"{}")
    with pytest.raises(source_adapters.AdapterError, match="HTTP 403") as error:
        fetch(source_for(mock_server), local_options)
    assert error.value.rate_limited is False


def test_timeout_is_retryable(mock_server, local_options, release_document):
    mock_server.add_json("/release", release_document, delay_seconds=2.0)
    source = source_for(mock_server)
    source["limits"]["read_timeout_seconds"] = 1
    source["limits"]["timeout_seconds"] = 1
    with pytest.raises(source_adapters.AdapterError) as error:
        fetch(source, local_options)
    assert error.value.retryable is True


def test_truncated_response_is_reported(mock_server, local_options):
    body = json.dumps({"tag_name": "x" * 5000}).encode("utf-8")
    mock_server.add("/release", body=body, truncate_after=100)
    with pytest.raises(source_adapters.AdapterError):
        fetch(source_for(mock_server), local_options)
