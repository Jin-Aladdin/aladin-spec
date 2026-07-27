"""Shared test fixtures.

The network tests drive a mock HTTP server on the loopback interface, which
is exactly the address the adapter refuses. The two opt-outs are function
parameters on the adapter, never policy fields, so a Knowledge Pack cannot
reach them; the tests pass them explicitly.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@dataclass
class Route:
    """One canned response."""

    status: int = 200
    body: bytes = b"{}"
    content_type: str | None = "application/json"
    headers: dict[str, str] = field(default_factory=dict)
    delay_seconds: float = 0.0
    #: Serve this many bytes and then stop, to simulate a truncated transfer.
    truncate_after: int | None = None


class MockServer:
    """A local HTTP server that answers from a routing table."""

    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[dict] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle --------------------------------------------------------
    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:  # keep test output clean
                pass

            def do_GET(self) -> None:  # noqa: N802 - required name
                outer.requests.append(
                    {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
                )
                route = outer.routes.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return

                if route.delay_seconds:
                    import time

                    time.sleep(route.delay_seconds)

                self.send_response(route.status)
                if route.content_type is not None:
                    self.send_header("Content-Type", route.content_type)
                for name, value in route.headers.items():
                    self.send_header(name, value)

                if route.status in (204, 304):
                    self.end_headers()
                    return

                if route.truncate_after is not None:
                    # Declare more than will be sent, then close early.
                    self.send_header("Content-Length", str(len(route.body)))
                    self.end_headers()
                    self.wfile.write(route.body[: route.truncate_after])
                    self.close_connection = True
                    return

                self.send_header("Content-Length", str(len(route.body)))
                self.end_headers()
                self.wfile.write(route.body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # -- helpers ----------------------------------------------------------
    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    @property
    def host(self) -> str:
        return "127.0.0.1"

    def url(self, path: str = "/") -> str:
        return f"http://{self.host}:{self.port}{path}"

    def add(self, path: str, **kwargs) -> Route:
        route = Route(**kwargs)
        self.routes[path] = route
        return route

    def add_json(self, path: str, document, **kwargs) -> Route:
        body = json.dumps(document, ensure_ascii=False).encode("utf-8")
        return self.add(path, body=body, **kwargs)

    def last_request(self) -> dict:
        assert self.requests, "no request was recorded"
        return self.requests[-1]


@pytest.fixture
def mock_server():
    server = MockServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def local_options(mock_server):
    """Adapter options that permit the loopback mock server.

    Only tests pass these. No policy field, manifest value or pack record can
    set them.
    """
    return {"allow_plain_http": True, "allow_private_addresses": True}


@pytest.fixture
def release_document():
    """A response shaped like the real GitHub releases endpoint."""
    return {
        "tag_name": "curl-8_21_0",
        "name": "curl 8.21.0",
        "published_at": "2026-06-24T06:03:04Z",
        "html_url": "https://github.com/curl/curl/releases/tag/curl-8_21_0",
        "draft": False,
        "prerelease": False,
    }
