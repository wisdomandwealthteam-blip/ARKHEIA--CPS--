from cps_backend.auto import evaluate_auto
from cps_backend.housing import evaluate_housing

REGISTRY = {
    "AUTO": evaluate_auto,
    "HOUSING": evaluate_housing,
}
