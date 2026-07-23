from .registry import REGISTRY

def evaluate_contract(vertical, contract):
    if vertical not in REGISTRY:
        raise ValueError(f"Unknown vertical: {vertical}")

    evaluator = REGISTRY[vertical]
    return evaluator(contract)
