from fastapi import FastAPI
from cps_backend.api import health as health_logic, risk as risk_logic

app = FastAPI()

@app.get("/health")
def health():
    return health_logic()

@app.post("/risk")
def risk(case_id: str, factors: dict):
    return risk_logic(case_id, factors)

@app.get("/registry")
def registry():
    return {"status": "ok", "message": "Registry endpoint placeholder"}

@app.get("/status")
def status():
    return {"status": "ok", "message": "Status endpoint placeholder"}

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
