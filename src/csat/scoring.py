from __future__ import annotations

from .models import SEVERITY_ORDER


SEVERITY_PENALTY = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def penalty_for(severity: str) -> int:
    return SEVERITY_PENALTY.get(severity, 0)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)
