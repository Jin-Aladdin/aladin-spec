"""Tests for the declarative JSON transformation.

The mapping is a security boundary as much as a convenience: if a policy
field could express computation, pack configuration would become code. These
tests assert both that it maps correctly and that it stays inert.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import json_mapping  # noqa: E402

DOCUMENT = {
    "tag_name": "curl-8_21_0",
    "name": "curl 8.21.0",
    "published_at": "2026-06-24T06:03:04Z",
    "html_url": "https://github.com/curl/curl/releases/tag/curl-8_21_0",
    "draft": False,
    "download_count": 42,
    "assets": [{"name": "a.tar.gz"}, {"name": "b.zip"}],
    "nested": {"deep": {"value": "found"}},
    "with~tilde": "tilde",
    "with/slash": "slash",
}


# ---------------------------------------------------------------------------
# Pointer resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pointer,expected",
    [
        ("/tag_name", "curl-8_21_0"),
        ("/nested/deep/value", "found"),
        ("/assets/0/name", "a.tar.gz"),
        ("/assets/1/name", "b.zip"),
        ("/draft", False),
        ("/download_count", 42),
        ("/with~0tilde", "tilde"),
        ("/with~1slash", "slash"),
    ],
)
def test_pointer_resolution(pointer, expected):
    found, value = json_mapping.resolve_pointer(DOCUMENT, pointer)
    assert found is True
    assert value == expected


def test_empty_pointer_returns_the_document():
    found, value = json_mapping.resolve_pointer(DOCUMENT, "")
    assert found is True
    assert value is DOCUMENT


@pytest.mark.parametrize(
    "pointer", ["/absent", "/nested/absent", "/assets/9/name", "/tag_name/deeper"]
)
def test_missing_pointer_is_reported_as_absent(pointer):
    found, _ = json_mapping.resolve_pointer(DOCUMENT, pointer)
    assert found is False


def test_malformed_pointer_is_rejected():
    with pytest.raises(json_mapping.MappingError, match="must be empty or start"):
        json_mapping.resolve_pointer(DOCUMENT, "tag_name")


def test_tilde_escaping_order():
    """~01 decodes to ~1, not to a slash."""
    assert json_mapping.parse_pointer("/a~01b") == ["a~1b"]


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------


def test_valid_mapping():
    mapping = {
        "release_tag": {"pointer": "/tag_name", "type": "string", "required": True},
        "published_at": {
            "pointer": "/published_at",
            "type": "string",
            "format": "date-time",
            "required": True,
        },
        "release_url": {"pointer": "/html_url", "type": "string", "format": "uri", "required": True},
    }
    values = json_mapping.apply_mapping(DOCUMENT, mapping)
    assert values["release_tag"] == "curl-8_21_0"
    assert values["published_at"] == "2026-06-24T06:03:04Z"


def test_missing_required_field_is_rejected():
    mapping = {"missing": {"pointer": "/nope", "type": "string", "required": True}}
    with pytest.raises(json_mapping.MappingError, match="required field") as error:
        json_mapping.apply_mapping(DOCUMENT, mapping)
    assert error.value.retryable is False


def test_missing_optional_field_is_omitted():
    mapping = {"missing": {"pointer": "/nope", "type": "string"}}
    assert json_mapping.apply_mapping(DOCUMENT, mapping) == {}


def test_missing_optional_field_uses_its_default():
    mapping = {"missing": {"pointer": "/nope", "type": "string", "default": "fallback"}}
    assert json_mapping.apply_mapping(DOCUMENT, mapping)["missing"] == "fallback"


def test_wrong_type_is_rejected():
    mapping = {"release_tag": {"pointer": "/download_count", "type": "string"}}
    with pytest.raises(json_mapping.MappingError, match="expected string"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_boolean_is_not_an_integer():
    """bool subclasses int in Python; a mapping must not conflate them."""
    mapping = {"count": {"pointer": "/draft", "type": "integer"}}
    with pytest.raises(json_mapping.MappingError, match="boolean"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_invalid_format_is_rejected():
    mapping = {"published_at": {"pointer": "/tag_name", "type": "string", "format": "date-time"}}
    with pytest.raises(json_mapping.MappingError, match="format"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_length_constraints():
    mapping = {"release_tag": {"pointer": "/tag_name", "type": "string", "max_length": 3}}
    with pytest.raises(json_mapping.MappingError, match="longer than"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_pattern_constraint():
    mapping = {"release_tag": {"pointer": "/tag_name", "type": "string", "pattern": r"^v\d+$"}}
    with pytest.raises(json_mapping.MappingError, match="pattern"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_enum_constraint():
    mapping = {"release_tag": {"pointer": "/tag_name", "enum": ["a", "b"]}}
    with pytest.raises(json_mapping.MappingError, match="enumeration"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_array_item_type_and_limit():
    mapping = {"assets": {"pointer": "/assets", "type": "array", "max_items": 1}}
    with pytest.raises(json_mapping.MappingError, match="above the limit"):
        json_mapping.apply_mapping(DOCUMENT, mapping)


def test_rule_without_pointer_is_rejected():
    with pytest.raises(json_mapping.MappingError, match="no pointer"):
        json_mapping.apply_mapping(DOCUMENT, {"field": {"type": "string"}})


def test_empty_mapping_is_rejected():
    with pytest.raises(json_mapping.MappingError, match="empty"):
        json_mapping.apply_mapping(DOCUMENT, {})


def test_mapping_is_deterministic():
    mapping = {"release_tag": {"pointer": "/tag_name", "type": "string", "required": True}}
    assert json_mapping.apply_mapping(DOCUMENT, mapping) == json_mapping.apply_mapping(
        DOCUMENT, mapping
    )


# ---------------------------------------------------------------------------
# Depth
# ---------------------------------------------------------------------------


def test_depth_measurement_is_iterative():
    document = {"a": 1}
    for _ in range(5_000):
        document = {"a": document}
    assert json_mapping.measure_depth(document) > 5_000


def test_excessive_depth_is_rejected():
    document = {"a": 1}
    for _ in range(200):
        document = {"a": document}
    with pytest.raises(json_mapping.MappingError, match="nests"):
        json_mapping.check_depth(document, max_depth=64)


def test_shallow_document_passes():
    json_mapping.check_depth(DOCUMENT, max_depth=64)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


def test_template_substitutes_mapped_values():
    rendered = json_mapping.render_template(
        "Tag {release_tag} published at {published_at}.",
        {"release_tag": "curl-8_21_0", "published_at": "2026-06-24T06:03:04Z"},
    )
    assert rendered == "Tag curl-8_21_0 published at 2026-06-24T06:03:04Z."


def test_template_rejects_unknown_placeholders():
    with pytest.raises(json_mapping.MappingError, match="unmapped field"):
        json_mapping.render_template("{absent}", {"present": "x"})


@pytest.mark.parametrize(
    "template",
    [
        "{release_tag.__class__}",
        "{release_tag.__class__.__mro__}",
        "{release_tag[0]}",
        "{release_tag!r}",
        "{release_tag:>10}",
        "{0}",
        "{}",
    ],
)
def test_template_cannot_reach_attributes_or_format_specifications(template):
    """str.format would evaluate these. The substitution here must not.

    A format string reaching __class__ is a documented way out of a template
    sandbox, which is why substitution is done with an explicit expression
    that only accepts plain field names.
    """
    try:
        rendered = json_mapping.render_template(template, {"release_tag": "curl"})
    except json_mapping.MappingError:
        return  # refused, which is also acceptable

    # The placeholder is left untouched: nothing was resolved, so nothing was
    # evaluated. Compare against the input rather than searching for words,
    # since the input itself contains them.
    assert rendered == template, "the placeholder must not be interpreted"
    assert "<class" not in rendered, "no Python object representation leaked in"
    assert "curl" not in rendered, "no value was substituted through an expression"


def test_template_renders_booleans_and_numbers():
    assert json_mapping.render_template("{flag} {count}", {"flag": True, "count": 3}) == "true 3"


def test_template_refuses_structured_values():
    with pytest.raises(json_mapping.MappingError, match="unambiguous string form"):
        json_mapping.render_template("{items}", {"items": [1, 2]})


def test_mapped_pointers_are_exposed_for_evidence():
    mapping = {
        "release_tag": {"pointer": "/tag_name", "type": "string"},
        "published_at": {"pointer": "/published_at", "type": "string"},
    }
    assert json_mapping.mapped_pointers(mapping) == {
        "release_tag": "/tag_name",
        "published_at": "/published_at",
    }
