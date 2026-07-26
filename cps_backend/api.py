from fastapi import FastAPI
from fastapi import HTTPException

from schemas import AutoContractIn, HousingContractIn
from registry import REGISTRY
from risk import aggregate_risk

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/risk/auto")
def risk_auto(contract: AutoContractIn):
    evaluator = REGISTRY.get("AUTO")
    if evaluator is None:
        raise HTTPException(status_code=500, detail="AUTO evaluator missing")

    results = evaluator(contract)
    aggregated = aggregate_risk(results)
    return {"type": "AUTO", "raw": results, "aggregated": aggregated}


@app.post("/risk/housing")
def risk_housing(contract: HousingContractIn):
    evaluator = REGISTRY.get("HOUSING")
    if evaluator is None:
        raise HTTPException(status_code=500, detail="HOUSING evaluator missing")

    results = evaluator(contract)
    aggregated = aggregate_risk(results)
    return {"type": "HOUSING", "raw": results, "aggregated": aggregated}


@app.get("/registry")
def registry():
    return {"registered": list(REGISTRY.keys())}


@app.get("/status")
def status():
    return {
        "status": "ok",
        "message": "System operational",
        "evaluators": list(REGISTRY.keys())
    }


@app.get("/dashboard")
def dashboard():
    return {
        "status": "ok",
        "message": "Dashboard endpoint is live",
        "data": {
            "active_cases": 0,
            "pending_reviews": 0,
            "system_health": "green"
        }
    }
