from cps_backend.schemas import AutoContractIn


def evaluate_auto(contract: AutoContractIn) -> dict:
    """
    Deterministic ARKHEIA-CPS auto risk evaluator.
    Produces a simple, stable risk output for aggregation.
    """

    return {
        "driver_age_factor": contract.driver_age / 10,
        "vehicle_value_factor": contract.vehicle_value / 5000,
        "vin_length_factor": len(contract.vin),
    }
