"""ARKHEIA DVE — closed-subset JSON Schema (draft 2020-12) interpreter.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Interprets arkheia-receipt-schema-v1.json directly (single source of truth).
Unknown keywords raise at load. Pattern '$' is evaluated as end-of-string
(ECMA-262 semantics), not Python's "before trailing newline".
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any, Callable

from .jcs import CanonicalizationError, canonicalize

_ANNOTATIONS = {"$schema", "$id", "title", "description"}
_ASSERTIONS = {
    "type", "const", "enum", "minLength", "maxLength", "pattern", "not", "$ref",
    "additionalProperties", "required", "properties", "allOf", "if", "then", "else",
    "minimum", "maximum", "maxItems", "uniqueItems", "items", "maxProperties",
    "propertyNames", "$defs",
}


class SchemaDefinitionError(ValueError):
    pass


def _ecma_pattern(p: str) -> re.Pattern[str]:
    if p.endswith("$") and not p.endswith("\\$"):
        p = p[:-1] + r"\Z"
    return re.compile(p)


def _assert_supported(node: Any, path: str) -> None:
    if isinstance(node, bool):
        return
    if not isinstance(node, dict):
        raise SchemaDefinitionError(f"schema node at {path} must be an object or boolean")
    for k in node:
        if k not in _ANNOTATIONS and k not in _ASSERTIONS:
            raise SchemaDefinitionError(f'unsupported schema keyword "{k}" at {path}')
    for k in ("not", "if", "then", "else", "items", "propertyNames", "additionalProperties"):
        if k in node:
            _assert_supported(node[k], f"{path}/{k}")
    for group in ("properties", "$defs"):
        for k, v in node.get(group, {}).items():
            _assert_supported(v, f"{path}/{group}/{k}")
    for i, s in enumerate(node.get("allOf", [])):
        _assert_supported(s, f"{path}/allOf/{i}")
    if "pattern" in node:
        _ecma_pattern(node["pattern"])


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "unknown"


def _type_matches(expected: str, v: Any) -> bool:
    t = _json_type(v)
    if expected == "number":
        return t in ("number", "integer")
    return expected == t


def _deep_equal(a: Any, b: Any) -> bool:
    try:
        return canonicalize(a) == canonicalize(b)
    except CanonicalizationError:
        return False


Error = dict[str, str]


def compile_schema(root: dict[str, Any]) -> Callable[[Any], tuple[bool, list[Error]]]:
    _assert_supported(root, "#")
    cache: dict[str, re.Pattern[str]] = {}

    def rx(p: str) -> re.Pattern[str]:
        if p not in cache:
            cache[p] = _ecma_pattern(p)
        return cache[p]

    def resolve(ref: str) -> Any:
        if not ref.startswith("#/"):
            raise SchemaDefinitionError(f"only local refs supported: {ref}")
        node: Any = root
        for part in ref[2:].split("/"):
            if not isinstance(node, dict) or part not in node:
                raise SchemaDefinitionError(f"unresolvable ref {ref}")
            node = node[part]
        return node

    def validate(schema: Any, value: Any, path: str, errors: list[Error]) -> None:
        if schema is True:
            return
        if schema is False:
            errors.append({"path": path, "keyword": "false"})
            return
        if "$ref" in schema:
            validate(resolve(schema["$ref"]), value, path, errors)
        if "type" in schema and not _type_matches(schema["type"], value):
            errors.append({"path": path, "keyword": "type"})
            return
        if "const" in schema and not _deep_equal(schema["const"], value):
            errors.append({"path": path, "keyword": "const"})
        if "enum" in schema and not any(_deep_equal(e, value) for e in schema["enum"]):
            errors.append({"path": path, "keyword": "enum"})
        if "not" in schema:
            sub: list[Error] = []
            validate(schema["not"], value, path, sub)
            if not sub:
                errors.append({"path": path, "keyword": "not"})
        for s in schema.get("allOf", []):
            validate(s, value, path, errors)
        if "if" in schema:
            sub = []
            validate(schema["if"], value, path, sub)
            if not sub:
                if "then" in schema:
                    validate(schema["then"], value, path, errors)
            elif "else" in schema:
                validate(schema["else"], value, path, errors)

        t = _json_type(value)
        if t == "string":
            if "minLength" in schema and len(value) < schema["minLength"]:
                errors.append({"path": path, "keyword": "minLength"})
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                errors.append({"path": path, "keyword": "maxLength"})
            if "pattern" in schema and not rx(schema["pattern"]).search(value):
                errors.append({"path": path, "keyword": "pattern"})
        if t in ("integer", "number"):
            if "minimum" in schema and value < schema["minimum"]:
                errors.append({"path": path, "keyword": "minimum"})
            if "maximum" in schema and value > schema["maximum"]:
                errors.append({"path": path, "keyword": "maximum"})
        if t == "array":
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                errors.append({"path": path, "keyword": "maxItems"})
            if schema.get("uniqueItems") is True:
                seen: set[str] = set()
                for item in value:
                    try:
                        key = canonicalize(item)
                    except CanonicalizationError:
                        errors.append({"path": path, "keyword": "uniqueItems"})
                        break
                    if key in seen:
                        errors.append({"path": path, "keyword": "uniqueItems"})
                        break
                    seen.add(key)
            if "items" in schema:
                for i, item in enumerate(value):
                    validate(schema["items"], item, f"{path}[{i}]", errors)
        if t == "object":
            if "maxProperties" in schema and len(value) > schema["maxProperties"]:
                errors.append({"path": path, "keyword": "maxProperties"})
            for r in schema.get("required", []):
                if r not in value:
                    errors.append({"path": f"{path}.{r}", "keyword": "required"})
            if "propertyNames" in schema:
                for k in value:
                    validate(schema["propertyNames"], k, f"{path}{{{k}}}", errors)
            props = schema.get("properties", {})
            for k, v in value.items():
                if k in props:
                    validate(props[k], v, f"{path}.{k}", errors)
                elif "additionalProperties" in schema:
                    validate(schema["additionalProperties"], v, f"{path}.{k}", errors)

    def validate_root(value: Any) -> tuple[bool, list[Error]]:
        errors: list[Error] = []
        validate(root, value, "$", errors)
        return (not errors, errors)

    return validate_root


RECEIPT_SCHEMA: dict[str, Any] = json.loads(
    resources.files("arkheia_receipt").joinpath("schema/arkheia-receipt-schema-v1.json").read_text("utf-8")
)
validate_receipt_schema = compile_schema(RECEIPT_SCHEMA)
