def evaluate_housing(contract):
    results = {}

    # Affordability
    if contract.rent / contract.income > 0.30:
        results["affordability"] = "HIGH_RISK"

    # Fees
    if contract.fees > contract.rent:
        results["fees"] = "HIGH_RISK"

    return results
