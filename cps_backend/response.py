from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ResponseEnvelope:
    """
    Unified deterministic response envelope for all CPS backend modules.
    Every API-facing function returns this structure.
    """

    success: bool
    data: Optional[Dict[str, Any]] = field(default=None)
    error: Optional[str] = field(default=None)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Deterministic serializer. No variation, no ambiguity.
        """
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "meta": self.meta,
        }


def ok(data: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> ResponseEnvelope:
    """
    Successful response wrapper.
    """
    return ResponseEnvelope(
        success=True,
        data=data,
        error=None,
        meta=meta or {},
    )


def fail(message: str, meta: Optional[Dict[str, Any]] = None) -> ResponseEnvelope:
    """
    Failure response wrapper.
    """
    return ResponseEnvelope(
        success=False,
        data=None,
        error=message,
        meta=meta or {},
    )
