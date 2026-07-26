from fastapi import FastAPI, HTTPException

from cps_backend.registry import REGISTRY
from cps_backend.schemas import AutoContractIn, HousingContractIn
from cps_backend.risk import aggregate_risk

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
