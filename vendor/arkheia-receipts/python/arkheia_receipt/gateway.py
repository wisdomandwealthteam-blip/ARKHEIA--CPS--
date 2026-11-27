"""ARKHEIA-CPS-GATEWAY- — public, stateless receipt verifier.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Routes
  POST /v1/verify-receipt   body: <receipt>  or  {"receipt": <receipt>, "previous_receipt": <receipt>}
  GET  /v1/public-keys      published keyring

Responses are JCS-canonical JSON. A well-formed request with a bad receipt
returns 200 {"valid": false, "error_code": ...}; malformed requests get 4xx.

Framework-neutral core (handle_request) plus WSGI and ASGI apps with no
third-party dependencies. Configure with ARKHEIA_TRUSTED_KEYS_FILE.
"""

from __future__ import annotations

import os
from typing import Any, Awaitable, Callable, Iterable

from .jcs import canonical_bytes
from .keys import Keyring
from .receipt import format_timestamp, utc_now, verify_receipt
from .strict_json import StrictJsonError, parse_strict_json

MAX_BODY_BYTES = 256 * 1024
VERIFY_PATH = "/v1/verify-receipt"
KEYS_PATH = "/v1/public-keys"

Response = tuple[int, list[tuple[str, str]], bytes]


def _json(status: int, body: dict[str, Any], extra_headers: Iterable[tuple[str, str]] = ()) -> Response:
    data = canonical_bytes(body)
    headers = [
        ("content-type", "application/json; charset=utf-8"),
        ("content-length", str(len(data))),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        *extra_headers,
    ]
    return status, headers, data


def _is_json_content_type(ct: str | None) -> bool:
    if not ct:
        return False
    parts = [p.strip().lower() for p in ct.split(";")]
    if parts[0] != "application/json":
        return False
    return all(p in ("", "charset=utf-8") for p in parts[1:])


def handle_request(
    *,
    method: str,
    path: str,
    content_type: str | None,
    body: bytes,
    keyring: Keyring,
    now: Callable[[], Any] = utc_now,
) -> Response:
    verified_at = format_timestamp(now())
    if path == KEYS_PATH:
        if method != "GET":
            return _json(405, {"error_code": "METHOD_NOT_ALLOWED"}, [("allow", "GET")])
        return _json(200, keyring.to_json())
    if path != VERIFY_PATH:
        return _json(404, {"error_code": "NOT_FOUND"})
    if method != "POST":
        return _json(405, {"error_code": "METHOD_NOT_ALLOWED"}, [("allow", "POST")])
    if not _is_json_content_type(content_type):
        return _json(415, {"error_code": "UNSUPPORTED_MEDIA_TYPE"})
    if len(body) > MAX_BODY_BYTES:
        return _json(413, {"error_code": "BODY_TOO_LARGE"})
    try:
        doc = parse_strict_json(body)
    except StrictJsonError:
        return _json(400, {"error_code": "BODY_PARSE_ERROR"})
    if not isinstance(doc, dict):
        return _json(400, {"error_code": "BODY_NOT_OBJECT"})

    if "receipt" in doc:
        if set(doc) - {"receipt", "previous_receipt"}:
            return _json(400, {"error_code": "UNKNOWN_ENVELOPE_FIELD"})
        receipt, previous = doc["receipt"], doc.get("previous_receipt")
    else:
        receipt, previous = doc, None

    result = verify_receipt(receipt, keyring, previous)
    if not result["valid"]:
        out: dict[str, Any] = {"valid": False, "verified_at": verified_at, "error_code": result["error_code"]}
        if "errors" in result:
            out["errors"] = result["errors"]
        return _json(200, out)
    return _json(
        200,
        {
            "valid": True,
            "verified_at": verified_at,
            "signer": result["signer"],
            "receipt_hash": result["receipt_hash"],
            "engine_id": receipt["engine_id"],
            "wrapper_domain": receipt["wrapper_domain"],
            "sequence": receipt["sequence"],
            "chain_link_verified": previous is not None,
        },
    )


def verify_upstream(body: bytes, keyring: Keyring) -> Response:
    """Gateway pass-through guard: forward a backend response ONLY if it is a valid
    signed receipt from a trusted key. Anything else -> 502, nothing forwarded."""
    try:
        receipt = parse_strict_json(body)
    except StrictJsonError:
        return _json(502, {"error_code": "UPSTREAM_RECEIPT_INVALID", "reason": "BODY_PARSE_ERROR"})
    result = verify_receipt(receipt, keyring)
    if not result["valid"]:
        return _json(502, {"error_code": "UPSTREAM_RECEIPT_INVALID", "reason": result["error_code"]})
    return _json(200, receipt, [("x-arkheia-receipt-hash", result["receipt_hash"])])


def load_keyring_from_env() -> Keyring:
    path = os.environ.get("ARKHEIA_TRUSTED_KEYS_FILE")
    if not path:
        raise RuntimeError("ARKHEIA_TRUSTED_KEYS_FILE is not set")
    return Keyring.from_file(path)


def make_wsgi_app(keyring: Keyring) -> Callable[..., Iterable[bytes]]:
    def app(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = -1
        if length < 0:
            status, headers, data = _json(400, {"error_code": "BAD_CONTENT_LENGTH"})
        elif length > MAX_BODY_BYTES:
            status, headers, data = _json(413, {"error_code": "BODY_TOO_LARGE"})
        else:
            body = environ["wsgi.input"].read(length) if length else b""
            status, headers, data = handle_request(
                method=environ.get("REQUEST_METHOD", ""),
                path=environ.get("PATH_INFO", ""),
                content_type=environ.get("CONTENT_TYPE"),
                body=body,
                keyring=keyring,
            )
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 413: "Payload Too Large", 415: "Unsupported Media Type"}
        start_response(f"{status} {reason.get(status, 'Error')}", headers)
        return [data]

    return app


def make_asgi_app(keyring: Keyring) -> Callable[..., Awaitable[None]]:
    async def app(scope: dict[str, Any], receive: Callable[..., Awaitable[dict[str, Any]]], send: Callable[..., Awaitable[None]]) -> None:
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            raise RuntimeError(f"unsupported ASGI scope {scope['type']}")
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        chunks: list[bytes] = []
        size = 0
        too_large = False
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            part = msg.get("body", b"")
            size += len(part)
            if size > MAX_BODY_BYTES:
                too_large = True
            elif part:
                chunks.append(part)
            if not msg.get("more_body", False):
                break
        if too_large:
            status, out_headers, data = _json(413, {"error_code": "BODY_TOO_LARGE"})
        else:
            status, out_headers, data = handle_request(
                method=scope.get("method", ""),
                path=scope.get("path", ""),
                content_type=headers.get("content-type"),
                body=b"".join(chunks),
                keyring=keyring,
            )
        await send({"type": "http.response.start", "status": status, "headers": [(k.encode(), v.encode()) for k, v in out_headers]})
        await send({"type": "http.response.body", "body": data})

    return app


if __name__ == "__main__":  # python -m arkheia_receipt.gateway  (stdlib server, for Codespaces smoke tests)
    from wsgiref.simple_server import make_server

    port = int(os.environ.get("PORT", "8080"))
    with make_server("0.0.0.0", port, make_wsgi_app(load_keyring_from_env())) as srv:
        print(f"ARKHEIA receipt verifier on :{port}{VERIFY_PATH}")
        srv.serve_forever()
