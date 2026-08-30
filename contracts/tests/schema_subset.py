"""Minimal JSON Schema subset used only by the checked-in contract schemas."""

from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Any
from urllib import parse


class SchemaValidationError(AssertionError):
    pass


def pointer(document: Any, fragment: str) -> Any:
    value = document
    if fragment:
        for part in fragment.lstrip("/").split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
    return value


def _is_type(value: Any, expected: str) -> bool:
    types = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
        "null": lambda item: item is None,
    }
    return types[expected](value)


def _format(value: str, name: str) -> bool:
    if name == "uuid":
        try:
            uuid.UUID(value)
            return True
        except ValueError:
            return False
    if name == "email":
        return re.fullmatch(r"[^@\s]+@[^@\s]+", value) is not None
    if name == "uri":
        parsed = parse.urlparse(value)
        return bool(parsed.scheme and (parsed.netloc or parsed.scheme not in {"http", "https"}))
    if name == "date-time":
        try:
            dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return True
        except ValueError:
            return False
    raise SchemaValidationError(f"unsupported checked-in format {name!r}")


def validate(
    value: Any,
    schema: dict[str, Any],
    *,
    root: dict[str, Any],
    schemas_by_name: dict[str, dict[str, Any]],
    schemas_by_id: dict[str, dict[str, Any]],
    path: str = "$",
) -> None:
    if "$ref" in schema:
        reference = schema["$ref"]
        if reference.startswith("#"):
            target_root = root
            target = pointer(root, reference[1:])
        else:
            name, _, fragment = reference.partition("#")
            target_root = schemas_by_name.get(name) or schemas_by_id.get(name)
            if target_root is None:
                raise SchemaValidationError(f"{path}: unknown schema reference {reference!r}")
            target = pointer(target_root, fragment)
        validate(value, target, root=target_root, schemas_by_name=schemas_by_name, schemas_by_id=schemas_by_id, path=path)
        return

    if "oneOf" in schema:
        successes = 0
        for option in schema["oneOf"]:
            try:
                validate(value, option, root=root, schemas_by_name=schemas_by_name, schemas_by_id=schemas_by_id, path=path)
                successes += 1
            except SchemaValidationError:
                pass
        if successes != 1:
            raise SchemaValidationError(f"{path}: expected exactly one oneOf match, got {successes}")

    if "type" in schema:
        expected_types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, item) for item in expected_types):
            raise SchemaValidationError(f"{path}: expected type {expected_types}, got {type(value).__name__}")
    if "const" in schema and value != schema["const"]:
        raise SchemaValidationError(f"{path}: expected const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value is not in enum")

    if isinstance(value, dict):
        required = set(schema.get("required", []))
        missing = required - value.keys()
        if missing:
            raise SchemaValidationError(f"{path}: missing required properties {sorted(missing)}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                validate(item, properties[key], root=root, schemas_by_name=schemas_by_name, schemas_by_id=schemas_by_id, path=f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                raise SchemaValidationError(f"{path}: unexpected property {key!r}")
            elif isinstance(schema.get("additionalProperties"), dict):
                validate(item, schema["additionalProperties"], root=root, schemas_by_name=schemas_by_name, schemas_by_id=schemas_by_id, path=f"{path}.{key}")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise SchemaValidationError(f"{path}: array is shorter than minItems")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], root=root, schemas_by_name=schemas_by_name, schemas_by_id=schemas_by_id, path=f"{path}[{index}]")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", float("inf")):
            raise SchemaValidationError(f"{path}: string length is outside bounds")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise SchemaValidationError(f"{path}: string does not match pattern")
        if "format" in schema and not _format(value, schema["format"]):
            raise SchemaValidationError(f"{path}: string does not match format {schema['format']!r}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            raise SchemaValidationError(f"{path}: number is outside bounds")
