"""
cps_backend.routers.risk
===========================
The three public risk-evaluation endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from cps_backend.schemas.auto import AutoContractIn, AutoRiskOut
from cps_backend.schemas.common import AggregateRiskOut
from cps_backend.schemas.housing import HousingContractIn, HousingRiskOut
from cps_backend.services.access_control import require_module_access
from cps_backend.services.auth import ApiKeyContext, get_api_key_context
from cps_backend.services.auto_risk import evaluate_auto
from cps_backend.services.housing_risk import evaluate_housing
from cps_backend.services.rate_limit import check_rate_limit
from cps_backend.utils.logging_setup import logger

router = APIRouter(prefix="/risk", tags=["risk"])


@router.post("/auto", response_model=AutoRiskOut)
def risk_auto(
    contract: AutoContractIn,
    ctx: ApiKeyContext = Depends(get_api_key_context),
) -> AutoRiskOut:
    require_module_access(ctx.tier, "auto")
    check_rate_limit(ctx.tenant_id, ctx.tier)
    result = evaluate_auto(contract)
    logger.info(
        "auto risk evaluated tenant=%s tier=%s risk_score=%s risk_tier=%s",
        ctx.tenant_id,
        ctx.tier.value,
        result.risk_score,
        result.risk_tier,
    )
    return result


@router.post("/housing", response_model=HousingRiskOut)
def risk_housing(
    contract: HousingContractIn,
    ctx: ApiKeyContext = Depends(get_api_key_context),
) -> HousingRiskOut:
    require_module_access(ctx.tier, "housing")
    check_rate_limit(ctx.tenant_id, ctx.tier)
    result = evaluate_housing(contract)
    logger.info(
        "housing risk evaluated tenant=%s tier=%s risk_score=%s risk_tier=%s",
        ctx.tenant_id,
        ctx.tier.value,
        result.risk_score,
        result.risk_tier,
    )
    return result


@router.post("/aggregate", response_model=AggregateRiskOut)
def risk_aggregate(
    auto_contract: AutoContractIn | None = None,
    housing_contract: HousingContractIn | None = None,
    ctx: ApiKeyContext = Depends(get_api_key_context),
) -> AggregateRiskOut:
    """Accepts either or both contract types and combines whichever are
    present into a single weighted envelope. At least one must be
    supplied (enforced below rather than at the schema layer, since
    either field alone is valid)."""
    require_module_access(ctx.tier, "aggregate")
    check_rate_limit(ctx.tenant_id, ctx.tier)

    components: dict[str, object] = {}
    scores: list[float] = []

    if auto_contract is not None:
        auto_result = evaluate_auto(auto_contract)
        components["auto"] = auto_result.model_dump()
        scores.append(auto_result.risk_score)

    if housing_contract is not None:
        housing_result = evaluate_housing(housing_contract)
        components["housing"] = housing_result.model_dump()
        scores.append(housing_result.risk_score)

    if not scores:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of auto_contract or housing_contract is required.",
        )

    combined = round(sum(scores) / len(scores), 2)
    tier_label = (
        "LOW"
        if combined <= 25
        else "MODERATE"
        if combined <= 50
        else "ELEVATED"
        if combined <= 75
        else "HIGH"
    )

    logger.info(
        "aggregate risk evaluated tenant=%s tier=%s combined_score=%s",
        ctx.tenant_id,
        ctx.tier.value,
        combined,
    )

    return AggregateRiskOut(
        combined_risk_score=combined,
        combined_risk_tier=tier_label,
        components=components,
    )
