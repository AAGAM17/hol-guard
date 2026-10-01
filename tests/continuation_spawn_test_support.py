"""Spawnable continuation mocks without importing the store or pytest."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from codex_plugin_scanner.guard.continuation_contract import ContinuationOffer, ContinuationResult

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.continuation_worker import StoreContinuationPlan


def successful_isolated_plan(
    plan: StoreContinuationPlan,
    offer: ContinuationOffer,
    _action: str,
    _timeout_seconds: float,
) -> ContinuationResult:
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status="resumed",
        reason="app_server_turn_started",
        completed_at=datetime.fromisoformat(plan.observed_at),
        evidence_id="evidence-app-server-0001",
    )
