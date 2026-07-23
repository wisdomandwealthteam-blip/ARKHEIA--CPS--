def evaluate_housing(contract):
    results = {}

    # Rent‑to‑income affordability rule
    if contract.rent / contract.income > 0.30:
        results["affordability"] = "HIGH_RISK"

    # Fees exceeding rent
    if contract.fees > contract.rent:
        results["fees"] = "HIGH_RISK"

    return results
