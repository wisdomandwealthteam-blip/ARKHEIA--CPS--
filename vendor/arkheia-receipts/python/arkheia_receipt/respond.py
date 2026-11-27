"""ARKHEIA DVE — fail-closed egress: a verdict never leaves unsigned.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

Framework-neutral. Adapt the (status, headers, body) triple to your framework:

  FastAPI / Starlette:  return Response(content=body, status_code=status, headers=dict(headers))
  Flask:                return Response(body, status=status, headers=headers)
  WebSocket:            await send_signed_ws(websocket.send_text, signer, ...)
"""

from __future__ import annotations

import re
from typing import Any, Awaitable, Callable, Mapping

from .jcs import canonical_bytes, canonicalize
from .receipt import ReceiptSigner

RECEIPT_HASH_HEADER = "x-arkheia-receipt-hash"
_CODE = re.compile(r"[A-Z_]{3,64}\Z")


def _error_code(e: BaseException) -> str:
    code = getattr(e, "code", None)
    return code if isinstance(code, str) and _CODE.match(code) else "RECEIPT_ISSUANCE_FAILED"


def signed_response(
    signer: ReceiptSigner, *, wrapper_domain: str, input_digest: str, verdict_payload: Mapping[str, Any], status: int = 200
) -> tuple[int, list[tuple[str, str]], bytes]:
    try:
        receipt, h = signer.issue(wrapper_domain=wrapper_domain, input_digest=input_digest, verdict_payload=verdict_payload)
    except Exception as e:  # noqa: BLE001 — converted to an explicit 500; the verdict is withheld, not leaked unsigned
        body = canonical_bytes({"error_code": _error_code(e)})
        return 500, [("content-type", "application/json; charset=utf-8"), ("cache-control", "no-store")], body
    body = canonical_bytes(receipt)
    return status, [
        ("content-type", "application/json; charset=utf-8"),
        ("cache-control", "no-store"),
        (RECEIPT_HASH_HEADER, h),
    ], body


async def send_signed_ws(
    send_text: Callable[[str], Awaitable[None]],
    signer: ReceiptSigner,
    *,
    wrapper_domain: str,
    input_digest: str,
    verdict_payload: Mapping[str, Any],
) -> bool:
    try:
        receipt, _ = signer.issue(wrapper_domain=wrapper_domain, input_digest=input_digest, verdict_payload=verdict_payload)
    except Exception as e:  # noqa: BLE001 — explicit error frame, verdict withheld
        await send_text(canonicalize({"type": "arkheia.error", "error_code": _error_code(e)}))
        return False
    await send_text(canonicalize({"type": "arkheia.receipt", "receipt": receipt}))
    return True
