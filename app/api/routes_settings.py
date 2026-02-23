"""
api/routes_settings.py

Configuration endpoints for progressive containment rules and system settings.
These are admin-only endpoints — in production, protect with role-based auth
(e.g., only SOC team leads can modify containment thresholds).
"""

import logging
from typing import List
from fastapi import APIRouter, HTTPException, Body
from app.models.schemas import ContainmentRule, ContainmentRuleUpdate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])

# In production, rules persist in Redis or a database.
# For this prototype, an in-memory store is used.
_rules_store: dict = {
    "default": ContainmentRule(
        rule_id="default",
        name="Global Default Rule",
        warn_threshold=1,
        soft_limit_threshold=3,
        hard_block_threshold=5,
        applies_to_apps=[],
        enabled=True,
    )
}


@router.get("/containment-rules", response_model=List[ContainmentRule])
async def list_containment_rules() -> List[ContainmentRule]:
    """Returns all configured progressive containment rules."""
    return list(_rules_store.values())


@router.get("/containment-rules/{rule_id}", response_model=ContainmentRule)
async def get_containment_rule(rule_id: str) -> ContainmentRule:
    if rule_id not in _rules_store:
        raise HTTPException(404, f"Rule '{rule_id}' not found.")
    return _rules_store[rule_id]


@router.post("/containment-rules", response_model=ContainmentRule)
async def create_containment_rule(rule: ContainmentRule) -> ContainmentRule:
    """
    Creates a new containment rule for specific applications.
    App-specific rules take precedence over the global default rule.
    """
    if rule.rule_id in _rules_store:
        raise HTTPException(409, f"Rule '{rule.rule_id}' already exists. Use PUT to update.")

    if rule.warn_threshold >= rule.soft_limit_threshold:
        raise HTTPException(
            400,
            "warn_threshold must be less than soft_limit_threshold."
        )
    if rule.soft_limit_threshold >= rule.hard_block_threshold:
        raise HTTPException(
            400,
            "soft_limit_threshold must be less than hard_block_threshold."
        )

    _rules_store[rule.rule_id] = rule
    logger.info(f"Containment rule '{rule.rule_id}' created by admin.")
    return rule


@router.patch("/containment-rules/{rule_id}", response_model=ContainmentRule)
async def update_containment_rule(
    rule_id: str, update: ContainmentRuleUpdate
) -> ContainmentRule:
    """
    Partially updates a containment rule. Only provided fields are modified.
    This allows threshold tuning without resetting entire rule configuration.
    """
    if rule_id not in _rules_store:
        raise HTTPException(404, f"Rule '{rule_id}' not found.")

    existing = _rules_store[rule_id]
    updated_data = existing.model_dump()

    for field, value in update.model_dump(exclude_none=True).items():
        updated_data[field] = value

    updated_rule = ContainmentRule(**updated_data)
    _rules_store[rule_id] = updated_rule
    logger.info(f"Containment rule '{rule_id}' updated.")
    return updated_rule


@router.delete("/containment-rules/{rule_id}")
async def delete_containment_rule(rule_id: str) -> dict:
    if rule_id == "default":
        raise HTTPException(400, "Cannot delete the default containment rule.")
    if rule_id not in _rules_store:
        raise HTTPException(404, f"Rule '{rule_id}' not found.")

    del _rules_store[rule_id]
    logger.info(f"Containment rule '{rule_id}' deleted.")
    return {"deleted": True, "rule_id": rule_id}


@router.get("/health")
async def health_check() -> dict:
    """Simple health check for load balancer / monitoring probe."""
    return {"status": "healthy", "service": "ATLAS Settings API"}
