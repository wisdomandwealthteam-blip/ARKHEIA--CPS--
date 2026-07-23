def evaluate_auto(contract):
    results = {}

    # Affordability
    if contract.payment_to_income > 0.30:
        results["affordability"] = "HIGH_RISK"

    # APR
    if contract.apr > 20:
        results["apr"] = "HIGH_RISK"

    # Doc fee
    if contract.doc_fee > 899:
        results["doc_fee"] = "HIGH_RISK"

    return results
