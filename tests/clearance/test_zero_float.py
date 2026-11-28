"""AX-4: zero floating point — statically in the engine source, dynamically at the boundary."""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import arkheia_clearance
from arkheia_clearance import artifacts as A

PKG = Path(arkheia_clearance.__file__).parent
SOURCES = sorted(p for p in PKG.glob("*.py"))
FORBIDDEN_MODULES = {"math", "cmath", "statistics", "decimal", "random", "fractions", "numpy"}
ALLOWED_TIME_ATTRS = {"monotonic_ns", "perf_counter_ns"}


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = []
    for node in ast.walk(tree):
        where = f"{path.name}:{getattr(node, 'lineno', '?')}"
        if isinstance(node, ast.Constant) and type(node.value) in (float, complex):
            out.append(f"{where} float literal")
        elif isinstance(node, (ast.BinOp, ast.AugAssign)) and isinstance(node.op, (ast.Div, ast.Pow)):
            out.append(f"{where} {type(node.op).__name__} operator (true division / power)")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("float", "complex", "round", "pow"):
            out.append(f"{where} {node.func.id}() call")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for n in names:
                if n.split(".")[0] in FORBIDDEN_MODULES:
                    out.append(f"{where} imports {n}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "time":
            if node.attr not in ALLOWED_TIME_ATTRS:
                out.append(f"{where} time.{node.attr} (float clock)")
    return out


def test_sources_found():
    names = {p.name for p in SOURCES}
    assert {"engine.py", "aegis.py", "conservation.py", "u.py", "receipts.py", "timing.py"} <= names


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_engine_source_contains_no_floating_point(path):
    assert _violations(path) == []


def _float_injections(w, a):
    good = w.mandate(a, w.lease(a, issued=0), t=1, tag="f")
    raw = A.to_bytes(good).decode()
    yield raw.replace('"lamport":1,', '"lamport":1.0,')
    yield raw.replace('"bps":6000', '"bps":6e3')
    yield raw.replace('"bps":6000', '"bps":6000.0000001')
    yield raw.replace('"ttl":5000', '"ttl":5E3')
    yield raw.replace('"pool":"1000000"', '"pool":1000000.0')
    yield raw.replace('"pool":"1000000"', '"pool":"1e6"')
    yield raw.replace('"lamport":1,', '"lamport":Infinity,')
    yield raw.replace('"lamport":1,', '"lamport":-0.0,')
    yield raw.replace('"lamport":1,', '"lamport":true,')
    yield raw.replace('"bps":6000', '"bps":"6000"')


def test_every_float_like_input_is_rejected_before_evaluation(h):
    w, a = h.w, h.w.agent("alpha")
    for i, raw in enumerate(_float_injections(w, a)):
        assert raw != A.to_bytes(w.mandate(a, w.lease(a, issued=0), t=1, tag="f")).decode(), i
        r, reason = h.raw_mandate(raw.encode())
        assert (r.status, reason) == (403, "STRUCT"), (i, raw[:80])
    assert h.state(a) == "ALLOW"


def test_receipts_and_responses_are_integers_only(h):
    from arkheia_clearance.golden import run_scenario

    run_scenario(h.w, h.e)

    def walk(v):
        assert type(v) is not float
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for r in h.e.records():
        walk(json.loads(json.dumps(r)))
