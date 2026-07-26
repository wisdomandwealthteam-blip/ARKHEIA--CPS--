payload = {
    "timestamp": time.time(),
    "status": "ok",
    "metrics": {
        "risk_score": round(random.uniform(0.0, 1.0), 3),
        "risk_level": "low" if random.random() < 0.5 else "high",
        "case_load": random.randint(1, 20),
        "active_cases": random.randint(1, 10)
    }
}
