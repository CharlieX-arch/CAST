from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import AuditResult


def render_markdown(results: Iterable[AuditResult]) -> str:
    items = list(results)
    lines: List[str] = ["# Container Security Audit Report", ""]

    total_findings = sum(len(item.findings) for item in items)
    lines.append(f"Audited containers: **{len(items)}**")
    lines.append(f"Total findings: **{total_findings}**")
    lines.append("")

    for result in items:
        counts = result.severity_counts()
        lines.extend([
            f"## {result.container_name}",
            f"- Image: `{result.image}`",
            f"- Risk score: **{result.score}** / 100",
            f"- Critical: {counts.get('critical', 0)}, High: {counts.get('high', 0)}, Medium: {counts.get('medium', 0)}, Low: {counts.get('low', 0)}",
            "",
        ])

        if result.notes:
            lines.append("### Notes")
            for note in result.notes:
                lines.append(f"- {note}")
            lines.append("")

        if not result.findings:
            lines.append("No security findings were detected for this container.")
            lines.append("")
            continue

        for finding in result.findings:
            lines.extend([
                f"### {finding.title}",
                f"- ID: {finding.id}",
                f"- Severity: {finding.severity}",
                f"- CIS Control: {finding.cis_control}",
                f"- Category: {finding.category}",
                f"- Description: {finding.description}",
            ])
            if finding.evidence:
                lines.append("- Evidence:")
                for evidence_line in finding.evidence:
                    lines.append(f"  - {evidence_line}")
            if finding.remediation:
                lines.append(f"- Remediation: {finding.remediation}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_report(path: str | Path, results: Iterable[AuditResult]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(results), encoding="utf-8")


def results_to_json(results: Iterable[AuditResult]) -> str:
    return json.dumps([result.to_dict() for result in results], indent=2)
