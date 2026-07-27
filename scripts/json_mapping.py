#!/usr/bin/env python3
"""Declarative JSON transformation for Aladdin source adapters.

A retrieved JSON document has to become canonical records. That step is where
an expression language would be convenient and dangerous: any policy field
that can be evaluated turns pack configuration into code, which ADR-0003
forbids.

This module is deliberately not a language. It supports JSON Pointer lookup,
a fixed type check, optional values with declared defaults, arrays of scalars,
and string templates that substitute already-extracted values and nothing
else.

There is no eval, no exec, no import, no attribute access, no arithmetic and
no control flow. A mapping cannot express computation, so a malicious policy
cannot smuggle any.

Example::

    mapping:
      release_tag:
        pointer: /tag_name
        type: string
        required: true
      published_at:
        pointer: /published_at
        type: string
        format: date-time
        required: true
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from jsonschema import FormatChecker

MAPPING_VERSION = "0.1.0"

#: Maximum nesting depth accepted in a retrieved document. A deeply nested
#: structure is a denial-of-service vector against any recursive consumer,
#: and no legitimate API response needs this depth.
DEFAULT_MAX_DEPTH = 64

TYPE_CHECKS: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "integer": (int,),
    "number": (int, float),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}

#: Template placeholders are plain field names. Nothing else is substituted,
#: so no attribute, index or format specification can be reached through a
#: template.
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")

_FORMAT_CHECKER = FormatChecker()


class MappingError(Exception):
    """A retrieved document does not satisfy the declared mapping.

    Never retryable: the response arrived intact and does not fit. Fetching it
    again produces the same mismatch.
    """

    def __init__(self, reason: str, *, field: str = "", pointer: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field
        self.pointer = pointer
        self.retryable = False


@dataclass(frozen=True)
class MappedValue:
    """One extracted value together with the location it came from."""

    field: str
    value: Any
    pointer: str
    present: bool


def measure_depth(document: Any) -> int:
    """Return the nesting depth of a parsed document without recursing.

    Iterative on purpose: measuring a hostile document must not be the thing
    that exhausts the stack.
    """
    depth = 0
    stack: list[tuple[Any, int]] = [(document, 1)]
    while stack:
        node, level = stack.pop()
        depth = max(depth, level)
        if isinstance(node, dict):
            for value in node.values():
                stack.append((value, level + 1))
        elif isinstance(node, list):
            for value in node:
                stack.append((value, level + 1))
    return depth


def check_depth(document: Any, max_depth: int = DEFAULT_MAX_DEPTH) -> None:
    depth = measure_depth(document)
    if depth > max_depth:
        raise MappingError(
            f"document nests {depth} levels deep, above the limit of {max_depth}"
        )


def parse_pointer(pointer: str) -> list[str]:
    """Parse an RFC 6901 JSON Pointer into its unescaped tokens."""
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise MappingError(
            f"JSON Pointer {pointer!r} must be empty or start with '/'", pointer=pointer
        )
    tokens = []
    for raw in pointer.split("/")[1:]:
        # ~1 before ~0, otherwise "~01" would decode to "/" instead of "~1".
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tokens


def resolve_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    """Resolve a JSON Pointer. Returns ``(found, value)``."""
    node = document
    for token in parse_pointer(pointer):
        if isinstance(node, dict):
            if token not in node:
                return False, None
            node = node[token]
        elif isinstance(node, list):
            if not token.isdigit():
                return False, None
            index = int(token)
            if index >= len(node):
                return False, None
            node = node[index]
        else:
            return False, None
    return True, node


def _check_type(field: str, pointer: str, value: Any, declared: str) -> None:
    expected = TYPE_CHECKS.get(declared)
    if expected is None:
        raise MappingError(f"unknown declared type {declared!r}", field=field, pointer=pointer)

    # bool is a subclass of int in Python; a boolean is not an integer here.
    if declared in ("integer", "number") and isinstance(value, bool):
        raise MappingError(
            f"field {field!r} at {pointer} is a boolean, expected {declared}",
            field=field,
            pointer=pointer,
        )
    if not isinstance(value, expected):
        actual = type(value).__name__
        raise MappingError(
            f"field {field!r} at {pointer} is {actual}, expected {declared}",
            field=field,
            pointer=pointer,
        )


def _check_format(field: str, pointer: str, value: Any, declared: str) -> None:
    if not isinstance(value, str):
        return
    if not _FORMAT_CHECKER.conforms(value, declared):
        raise MappingError(
            f"field {field!r} at {pointer} does not satisfy format {declared!r}",
            field=field,
            pointer=pointer,
        )


def _check_constraints(field: str, pointer: str, value: Any, rule: dict) -> None:
    if isinstance(value, str):
        minimum = rule.get("min_length")
        maximum = rule.get("max_length")
        if minimum is not None and len(value) < minimum:
            raise MappingError(
                f"field {field!r} is shorter than {minimum} characters",
                field=field,
                pointer=pointer,
            )
        if maximum is not None and len(value) > maximum:
            raise MappingError(
                f"field {field!r} is longer than {maximum} characters",
                field=field,
                pointer=pointer,
            )
        pattern = rule.get("pattern")
        if pattern is not None and not re.fullmatch(pattern, value):
            raise MappingError(
                f"field {field!r} does not match the declared pattern",
                field=field,
                pointer=pointer,
            )

    if isinstance(value, list):
        item_type = rule.get("item_type")
        maximum = rule.get("max_items")
        if maximum is not None and len(value) > maximum:
            raise MappingError(
                f"field {field!r} has {len(value)} items, above the limit of {maximum}",
                field=field,
                pointer=pointer,
            )
        if item_type is not None:
            for index, item in enumerate(value):
                _check_type(f"{field}[{index}]", pointer, item, item_type)

    allowed = rule.get("enum")
    if allowed is not None and value not in allowed:
        raise MappingError(
            f"field {field!r} has a value outside the declared enumeration",
            field=field,
            pointer=pointer,
        )


def apply_mapping(document: Any, mapping: dict, *, max_depth: int = DEFAULT_MAX_DEPTH) -> dict:
    """Extract declared fields from a document.

    Returns a plain dictionary of field name to value. Missing optional fields
    are omitted unless the rule declares a default.
    """
    check_depth(document, max_depth)

    if not isinstance(mapping, dict) or not mapping:
        raise MappingError("mapping is empty")

    result: dict[str, Any] = {}
    for field, rule in mapping.items():
        if not isinstance(rule, dict):
            raise MappingError(f"mapping rule for {field!r} is not an object", field=field)

        pointer = rule.get("pointer")
        if not isinstance(pointer, str):
            raise MappingError(f"mapping rule for {field!r} has no pointer", field=field)

        found, value = resolve_pointer(document, pointer)

        if not found or value is None:
            if rule.get("required", False):
                raise MappingError(
                    f"required field {field!r} is missing at {pointer}",
                    field=field,
                    pointer=pointer,
                )
            if "default" in rule:
                result[field] = rule["default"]
            continue

        declared_type = rule.get("type")
        if declared_type is not None:
            _check_type(field, pointer, value, declared_type)

        declared_format = rule.get("format")
        if declared_format is not None:
            _check_format(field, pointer, value, declared_format)

        _check_constraints(field, pointer, value, rule)
        result[field] = value

    return result


def render_template(template: str, values: dict[str, Any]) -> str:
    """Substitute ``{field}`` placeholders with already-extracted values.

    Implemented with an explicit regular expression rather than ``str.format``
    on purpose: format strings reach attributes and indexes, so ``{x.__class__}``
    would be a way out of the sandbox. Here a placeholder is a field name and
    nothing else.
    """
    if not isinstance(template, str):
        raise MappingError("template must be a string")

    missing: list[str] = []

    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            missing.append(name)
            return ""
        value = values[name]
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (str, int, float)):
            return str(value)
        raise MappingError(
            f"template placeholder {name!r} refers to a {type(value).__name__}, "
            "which has no unambiguous string form"
        )

    rendered = PLACEHOLDER.sub(substitute, template)
    if missing:
        raise MappingError(
            "template refers to unmapped field(s): " + ", ".join(sorted(set(missing)))
        )
    return rendered


def mapped_pointers(mapping: dict) -> dict[str, str]:
    """Return the pointer used for each mapped field.

    Evidence records point at the exact locations a claim was derived from, so
    the pointers are part of the provenance, not an implementation detail.
    """
    return {
        field: rule["pointer"]
        for field, rule in mapping.items()
        if isinstance(rule, dict) and isinstance(rule.get("pointer"), str)
    }
