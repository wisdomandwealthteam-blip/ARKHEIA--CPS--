from typing import Dict, Any
from fastapi import FastAPI

from cps_backend.response import ok, fail
from cps_backend.risk import assess as assess_risk

app = FastAPI()

@app.get("/health")
def health() -> Dict[str, Any]:
    """
    Simple deterministic health check endpoint.
    Returns a ResponseEnvelope via ok().
    """
    return ok({"status": "online", "module": "cps_backend.api"}).to_dict()


@app.post("/risk")
def risk(case_id: str, factors: Dict[str, Any]) -> Dict[str, Any]:
    """
    Public API endpoint for risk assessment.
    Wraps the risk module and returns a deterministic envelope.
    """
    try:
        envelope = assess_risk(case_id, factors)
        return envelope.to_dict()
    except Exception as exc:
        return fail(f"API risk endpoint failure: {exc}").to_dict()


# Real-time CPS stream router
from stream import router as stream_router
app.include_router(stream_router)
