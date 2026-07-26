from cps_backend.schemas import HousingContractIn


def evaluate_housing(contract: HousingContractIn) -> dict:
    """
    Deterministic ARKHEIA-CPS housing risk evaluator.
    Produces a simple, stable risk output for aggregation.
    """

    return {
        "age_factor": (2026 - contract.year_built) / 10,
        "size_factor": contract.square_feet / 1000,
        "address_length_factor": len(contract.address),
    }
