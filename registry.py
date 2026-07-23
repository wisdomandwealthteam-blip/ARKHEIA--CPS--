from .auto import evaluate_auto
from .housing import evaluate_housing

REGISTRY = {
    "AUTO": evaluate_auto,
    "HOUSING": evaluate_housing
}
