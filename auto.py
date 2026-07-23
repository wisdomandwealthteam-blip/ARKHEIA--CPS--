def evaluate_auto(contract):
    results = {}

    # Payment‑to‑income risk
    if contract.payment_to_income > 0.30:
        results["affordability"] = "HIGH_RISK"

    # APR risk
    if contract.apr > 20:
        results["apr"] = "HIGH_RISK"

    # Documentation fee risk
    if contract.doc_fee > 899:
        results["doc_fee"] = "HIGH_RISK"

    return results
