"""Network safety tests for target screening.

Every case here is a way an allowlisted-looking target reaches somewhere it
must not: a loopback address behind a public name, an IPv4 loopback wrapped in
IPv6 notation, a metadata endpoint, a credential smuggled into the authority
component, a redirect that leaves the allowlist.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import net_guard  # noqa: E402

ALLOWED = ["example.org"]


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------

BLOCKED_ADDRESSES = [
    ("127.0.0.1", "loopback"),
    ("127.1.2.3", "loopback"),
    ("::1", "loopback"),
    ("0.0.0.0", "unspecified"),
    ("::", "unspecified"),
    ("10.0.0.1", "private"),
    ("172.16.5.4", "private"),
    ("192.168.1.1", "private"),
    ("fc00::1", "private"),
    ("fd12:3456::1", "private"),
    ("169.254.1.1", "link-local"),
    ("fe80::1", "link-local"),
    ("224.0.0.1", "multicast"),
    ("ff02::1", "multicast"),
    ("100.64.0.1", "blocked range"),
    ("::ffff:127.0.0.1", "embeds IPv4"),
    ("::ffff:10.0.0.1", "embeds IPv4"),
    ("2002:7f00:1::1", "embeds IPv4"),
]

#: Ranges where the interpreter's own classification already refuses the
#: address, so the exact wording depends on the Python version. What matters
#: is that they are blocked, not which layer blocked them.
BLOCKED_REGARDLESS_OF_REASON = [
    "198.18.0.1",  # benchmarking
    "192.0.0.1",  # IETF protocol assignments
    "64:ff9b::7f00:1",  # NAT64 prefix wrapping a loopback address
    "192.88.99.1",  # deprecated 6to4 relay anycast
    "240.0.0.1",  # reserved for future use
    "255.255.255.255",  # broadcast
]

METADATA_ADDRESSES = [
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "192.0.0.192",
    "fd00:ec2::254",
]

ALLOWED_ADDRESSES = ["8.8.8.8", "1.1.1.1", "140.82.121.4", "2606:4700:4700::1111"]


@pytest.mark.parametrize("address,expected", BLOCKED_ADDRESSES, ids=[a for a, _ in BLOCKED_ADDRESSES])
def test_unsafe_addresses_are_classified(address, expected):
    reason = net_guard.classify_address(address)
    assert reason is not None, f"{address} was not blocked"
    assert expected in reason


@pytest.mark.parametrize("address", BLOCKED_REGARDLESS_OF_REASON)
def test_reserved_ranges_are_blocked(address):
    """These are refused by the interpreter's own classification or by ours.

    The wording differs between Python versions; being blocked does not.
    """
    reason = net_guard.classify_address(address)
    assert reason is not None, f"{address} was not blocked"
    assert address in reason


@pytest.mark.parametrize("address", METADATA_ADDRESSES)
def test_cloud_metadata_endpoints_are_named_explicitly(address):
    reason = net_guard.classify_address(address)
    assert reason is not None
    assert "metadata" in reason, f"{address} was blocked, but not identified as metadata"


@pytest.mark.parametrize("address", ALLOWED_ADDRESSES)
def test_public_addresses_are_allowed(address):
    assert net_guard.classify_address(address) is None


def test_garbage_is_not_an_address():
    assert net_guard.classify_address("not-an-address") is not None


# ---------------------------------------------------------------------------
# Scheme, credentials, port
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scheme", ["file", "ftp", "data", "gopher", "jar", "ldap", "dict", "sftp", "netdoc"]
)
def test_forbidden_schemes_are_named(scheme):
    with pytest.raises(net_guard.TargetRejected, match="never permitted"):
        net_guard.screen_url(f"{scheme}://example.org/x", allowed_domains=ALLOWED)


def test_plain_http_is_refused_by_default():
    with pytest.raises(net_guard.TargetRejected, match="requires https"):
        net_guard.screen_url("http://example.org/x", allowed_domains=ALLOWED)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@example.org/x",
        "https://user@example.org/x",
        "https://:secret@example.org/x",
    ],
)
def test_embedded_credentials_are_refused(url):
    with pytest.raises(net_guard.TargetRejected, match="credentials"):
        net_guard.screen_url(url, allowed_domains=ALLOWED)


def test_non_default_port_is_refused():
    with pytest.raises(net_guard.TargetRejected, match="default port"):
        net_guard.screen_url("https://example.org:8443/x", allowed_domains=ALLOWED)


def test_missing_host_is_refused():
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_url("https:///path", allowed_domains=ALLOWED)


def test_empty_url_is_refused():
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_url("", allowed_domains=ALLOWED)


# ---------------------------------------------------------------------------
# Allowlist matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,allowed,expected",
    [
        ("example.org", ["example.org"], True),
        ("api.example.org", ["example.org"], True),
        ("deep.api.example.org", ["example.org"], True),
        ("example.org.", ["example.org"], True),
        ("notexample.org", ["example.org"], False),
        ("example.org.attacker.test", ["example.org"], False),
        ("exampleXorg", ["example.org"], False),
        ("evil.test", ["example.org"], False),
        ("example.org", [], False),
        ("EXAMPLE.ORG", ["example.org"], True),
    ],
)
def test_allowlist_matching(host, allowed, expected):
    assert net_guard.host_matches_allowlist(host, allowed) is expected


def test_host_outside_allowlist_is_refused():
    with pytest.raises(net_guard.TargetRejected, match="allowlist"):
        net_guard.screen_url("https://evil.test/x", allowed_domains=ALLOWED)


def test_suffix_confusion_is_refused():
    """example.org.attacker.test must not pass an example.org allowlist."""
    with pytest.raises(net_guard.TargetRejected, match="allowlist"):
        net_guard.screen_url("https://example.org.attacker.test/x", allowed_domains=ALLOWED)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_loopback_name_is_refused_even_when_allowlisted():
    """A domain allowlist says nothing about where the name points."""
    with pytest.raises(net_guard.TargetRejected, match="blocked address"):
        net_guard.screen_url("https://localhost/x", allowed_domains=["localhost"])


def test_literal_loopback_address_is_refused():
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_url("https://127.0.0.1/x", allowed_domains=["127.0.0.1"])


def test_literal_ipv6_loopback_is_refused():
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_url("https://[::1]/x", allowed_domains=["::1"])


def test_metadata_address_is_refused():
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_url("https://169.254.169.254/latest/meta-data/", allowed_domains=["169.254.169.254"])


def test_unresolvable_host_is_refused():
    with pytest.raises(net_guard.TargetRejected, match="could not be resolved"):
        net_guard.screen_url(
            "https://this-name-does-not-exist.invalid/x",
            allowed_domains=["this-name-does-not-exist.invalid"],
        )


def test_private_target_is_reachable_only_with_the_explicit_test_opt_in():
    """The opt-in is a function parameter, unreachable from policy content."""
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_url("http://127.0.0.1/x", allowed_domains=["127.0.0.1"])

    target = net_guard.screen_url(
        "http://127.0.0.1/x",
        allowed_domains=["127.0.0.1"],
        allow_plain_http=True,
        allow_private_addresses=True,
    )
    assert target.pinned_address == "127.0.0.1"


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------


def _target(url: str = "https://example.org/a") -> net_guard.ScreenedTarget:
    return net_guard.ScreenedTarget(
        url=url, scheme="https", host="example.org", port=443, path="/a", addresses=("93.184.216.34",)
    )


def test_redirect_off_the_allowlist_is_refused():
    with pytest.raises(net_guard.TargetRejected, match="allowlist"):
        net_guard.screen_redirect("https://evil.test/x", previous=_target(), allowed_domains=ALLOWED)


def test_redirect_to_loopback_is_refused():
    with pytest.raises(net_guard.TargetRejected):
        net_guard.screen_redirect(
            "http://127.0.0.1/x", previous=_target(), allowed_domains=["127.0.0.1"]
        )


def test_redirect_to_a_forbidden_scheme_is_refused():
    with pytest.raises(net_guard.TargetRejected, match="never permitted"):
        net_guard.screen_redirect("file:///etc/passwd", previous=_target(), allowed_domains=ALLOWED)


def test_redirect_without_location_is_refused():
    with pytest.raises(net_guard.TargetRejected, match="no Location"):
        net_guard.screen_redirect("", previous=_target(), allowed_domains=ALLOWED)


def test_relative_redirect_resolves_against_the_previous_target():
    with pytest.raises(net_guard.TargetRejected) as error:
        net_guard.screen_redirect("/b", previous=_target(), allowed_domains=["evil.test"])
    # Resolved against example.org, so it fails the allowlist rather than
    # being treated as a bare path.
    assert "example.org" in str(error.value)
