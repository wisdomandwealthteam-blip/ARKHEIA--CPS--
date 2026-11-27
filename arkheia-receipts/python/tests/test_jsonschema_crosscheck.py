"""Independent cross-check: the reference `jsonschema` library must agree with
the in-tree interpreter on every vector. Requires the dev extra (jsonschema)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema", reason="install dev extra: pip install -e '.[dev]'")

from arkheia_receipt import RECEIPT_SCHEMA, validate_receipt_schema  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
V = json.loads((ROOT / "test-vectors" / "vectors.json").read_text("utf-8"))


def _ecma_pattern(validator, pattern, instance, schema):
    # jsonschema uses re.search, where '$' also matches before a trailing '\n'.
    # ECMA-262 (what JSON Schema specifies) does not; align before comparing.
    if not validator.is_type(instance, "string"):
        return
    p = pattern[:-1] + r"\Z" if pattern.endswith("$") else pattern
    if not re.search(p, instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


Strict = jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": _ecma_pattern})


def test_schema_is_valid_draft_2020_12():
    jsonschema.Draft202012Validator.check_schema(RECEIPT_SCHEMA)


def test_reference_validator_agrees_on_all_vectors():
    v = Strict(RECEIPT_SCHEMA)
    cases = [(s["receipt"], True) for s in V["chain"]]
    cases += [(n["receipt"], n["expected_error_code"] != "SCHEMA_INVALID") for n in V["negative"]]
    for receipt, expected_schema_valid in cases:
        ours, _ = validate_receipt_schema(receipt)
        theirs = v.is_valid(receipt)
        assert ours == theirs == expected_schema_valid, receipt
