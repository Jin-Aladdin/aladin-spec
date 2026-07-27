#!/usr/bin/env python3
"""Network target screening for Aladdin source adapters.

A source adapter fetches material the repository does not control, from a URL
the repository does not control either. That makes every retrieval a
server-side request forgery candidate: a hostname on the allowlist can resolve
to a loopback address, a redirect can leave the allowlist, and a name that
screened as safe can resolve to something else on the second lookup.

This module answers one question and answers it conservatively: may this
process open a connection to this target, and to which exact address.

Design rules:

* Deny by default. Anything not positively recognized as safe is rejected.
* Screen the name, then screen every resolved address, then connect to a
  pinned address. A domain allowlist alone is not sufficient, because it says
  nothing about where the name points.
* If any resolved address is unsafe, reject the whole target. A host that
  answers with one public and one loopback address is not a host to trust.
* Rejections are not retryable. A blocked target does not become allowed by
  trying again, and retrying a blocked target is itself a signal worth not
  emitting.

Nothing in this module executes retrieved content.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

GUARD_VERSION = "0.1.0"

#: Only TLS in normal operation. Plain HTTP is a deliberate test-only opt-in
#: and is never reachable from policy or pack content.
SECURE_SCHEMES = frozenset({"https"})
TEST_ONLY_SCHEMES = frozenset({"http"})

#: Schemes that must never be attempted, listed explicitly so a rejection
#: message can name them rather than saying "unsupported".
FORBIDDEN_SCHEMES = frozenset(
    {"file", "ftp", "ftps", "data", "gopher", "jar", "netdoc", "mailto", "ldap", "dict", "sftp"}
)

DEFAULT_PORTS = {"https": 443, "http": 80}

#: Cloud instance metadata endpoints. Most are already covered by the
#: link-local and private range checks, but they are named explicitly so a
#: rejection says what was actually blocked.
METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",  # AWS, Azure, GCP, DigitalOcean, OpenStack
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "192.0.0.192",  # Oracle Cloud
        "fd00:ec2::254",  # AWS IMDSv2 over IPv6
    }
)

#: Ranges that Python's own classification does not flag, or flags only in
#: newer versions. Listed explicitly so behaviour does not depend on the
#: interpreter version.
EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("192.88.99.0/24"),  # deprecated 6to4 relay anycast
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 well-known prefix
    ipaddress.ip_network("2002::/16"),  # 6to4
)

MAX_HOSTNAME_LENGTH = 253


class TargetRejected(Exception):
    """A target must not be contacted.

    A rejection is never retryable: the target did not fail, it was refused.
    """

    def __init__(self, reason: str, *, target: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.target = target
        self.retryable = False


@dataclass(frozen=True)
class ScreenedTarget:
    """A target that passed screening, with the addresses it may use."""

    url: str
    scheme: str
    host: str
    port: int
    path: str
    addresses: tuple[str, ...] = field(default=())

    @property
    def pinned_address(self) -> str:
        """The address the connection must actually use."""
        return self.addresses[0]


# ---------------------------------------------------------------------------
# Address screening
# ---------------------------------------------------------------------------


def classify_address(value: str) -> str | None:
    """Return a rejection reason for an address, or None when it is usable."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return f"{value!r} is not a valid IP address"

    # An IPv4-mapped or IPv4-compatible IPv6 address carries an IPv4 address
    # inside it. ::ffff:127.0.0.1 is loopback, and screening only the outer
    # form would miss that.
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or getattr(address, "sixtofour", None)
        if embedded is None and address.teredo:
            embedded = address.teredo[1]
        if embedded is not None:
            inner = classify_address(str(embedded))
            if inner is not None:
                return f"IPv6 address embeds IPv4 address {embedded}: {inner}"

    if str(address) in METADATA_ADDRESSES:
        return f"{address} is a cloud instance metadata endpoint"

    checks = (
        ("is_unspecified", "an unspecified address"),
        ("is_loopback", "a loopback address"),
        ("is_link_local", "a link-local address"),
        ("is_multicast", "a multicast address"),
        ("is_reserved", "a reserved address"),
        ("is_private", "a private address"),
    )
    for attribute, description in checks:
        if getattr(address, attribute, False):
            return f"{address} is {description}"

    if getattr(address, "is_site_local", False):
        return f"{address} is a site-local address"

    for network in EXTRA_BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            return f"{address} is in the blocked range {network}"

    if not address.is_global:
        return f"{address} is not globally routable"

    return None


def resolve_addresses(host: str, port: int) -> list[str]:
    """Resolve a hostname to every address it currently points at."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetRejected(f"hostname {host!r} could not be resolved: {exc}", target=host) from exc

    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise TargetRejected(f"hostname {host!r} resolved to no address", target=host)
    return addresses


# ---------------------------------------------------------------------------
# Name screening
# ---------------------------------------------------------------------------


def host_matches_allowlist(host: str, allowed_domains: list[str]) -> bool:
    """Match a host against the allowlist, exactly or as a subdomain.

    ``example.org`` permits ``example.org`` and ``api.example.org``, and does
    not permit ``notexample.org`` or ``example.org.attacker.test``.
    """
    candidate = host.lower().rstrip(".")
    for entry in allowed_domains:
        allowed = str(entry).lower().rstrip(".")
        if not allowed:
            continue
        if candidate == allowed or candidate.endswith("." + allowed):
            return True
    return False


def screen_url(
    url: str,
    *,
    allowed_domains: list[str],
    allow_plain_http: bool = False,
    allow_private_addresses: bool = False,
) -> ScreenedTarget:
    """Screen a URL and resolve it to the addresses a connection may use.

    ``allow_plain_http`` and ``allow_private_addresses`` exist so the test
    suite can drive a mock server on the loopback interface. They are function
    parameters on purpose: no policy field, manifest value or piece of pack
    content can reach them.
    """
    if not isinstance(url, str) or not url:
        raise TargetRejected("no URL given")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()

    if scheme in FORBIDDEN_SCHEMES:
        raise TargetRejected(f"scheme {scheme!r} is never permitted", target=url)
    if scheme not in SECURE_SCHEMES:
        if not (allow_plain_http and scheme in TEST_ONLY_SCHEMES):
            raise TargetRejected(
                f"scheme {scheme!r} is not permitted; retrieval requires https",
                target=url,
            )

    if parts.username or parts.password or "@" in parts.netloc:
        raise TargetRejected("URL must not embed credentials", target=url)

    host = parts.hostname
    if not host:
        raise TargetRejected("URL has no host", target=url)
    if len(host) > MAX_HOSTNAME_LENGTH:
        raise TargetRejected("hostname is longer than the DNS limit", target=url)

    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise TargetRejected(f"invalid port in URL: {exc}", target=url) from exc

    if not allow_plain_http and port != DEFAULT_PORTS[scheme]:
        raise TargetRejected(
            f"port {port} is not the default port for {scheme}", target=url
        )

    if not host_matches_allowlist(host, allowed_domains or []):
        raise TargetRejected(
            f"host {host!r} is not covered by the declared domain allowlist", target=url
        )

    addresses = resolve_addresses(host, port)

    if not allow_private_addresses:
        # Every resolved address must be safe. One unsafe answer poisons the
        # whole target: which address a later connection would pick is not
        # something this process can guarantee.
        for address in addresses:
            reason = classify_address(address)
            if reason is not None:
                raise TargetRejected(
                    f"host {host!r} resolves to a blocked address: {reason}", target=url
                )

    return ScreenedTarget(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        path=parts.path or "/",
        addresses=tuple(addresses),
    )


def screen_redirect(
    location: str,
    *,
    previous: ScreenedTarget,
    allowed_domains: list[str],
    allow_plain_http: bool = False,
    allow_private_addresses: bool = False,
) -> ScreenedTarget:
    """Screen a redirect target with the same rules as the original request.

    A redirect is a new request to a new target. It receives no trust from the
    fact that the first hop was allowed.
    """
    from urllib.parse import urljoin

    if not location:
        raise TargetRejected("redirect response carried no Location header")

    absolute = urljoin(previous.url, location)
    return screen_url(
        absolute,
        allowed_domains=allowed_domains,
        allow_plain_http=allow_plain_http,
        allow_private_addresses=allow_private_addresses,
    )
