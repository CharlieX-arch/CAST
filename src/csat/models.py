from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    cis_control: str
    category: str
    description: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    score_penalty: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditResult:
    container_name: str
    image: str
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        penalty = sum(finding.score_penalty for finding in self.findings)
        return max(0, 100 - penalty)

    def severity_counts(self) -> Dict[str, int]:
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "container_name": self.container_name,
            "image": self.image,
            "score": self.score,
            "severity_counts": self.severity_counts(),
            "notes": list(self.notes),
            "findings": [finding.to_dict() for finding in self.findings],
        }
