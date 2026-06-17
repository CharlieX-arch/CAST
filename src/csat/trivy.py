from __future__ import annotations

import json
import shutil
import subprocess
from typing import List

from .models import Finding
from .scoring import penalty_for


def scan_image(image_ref: str) -> List[Finding]:
    if not image_ref:
        return []

    if shutil.which("trivy") is None:
        return []

    command = [
        "trivy",
        "image",
        "--quiet",
        "--format",
        "json",
        image_ref,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode not in (0, 1):
        return []

    if not completed.stdout.strip():
        return []

    payload = json.loads(completed.stdout)
    findings: List[Finding] = []

    for result in payload.get("Results", []):
        target = result.get("Target", image_ref)
        for vulnerability in result.get("Vulnerabilities", []):
            severity = str(vulnerability.get("Severity", "LOW")).lower()
            vuln_id = vulnerability.get("VulnerabilityID", "UNKNOWN")
            package = vulnerability.get("PkgName", "unknown-package")
            installed = vulnerability.get("InstalledVersion", "unknown")
            title = f"{vuln_id} in {package}"
            details = vulnerability.get("Title") or vulnerability.get("Description") or "No description available"
            findings.append(
                Finding(
                    id=f"TRIVY-{vuln_id}",
                    title=title,
                    severity=severity,
                    cis_control="CIS 4.4",
                    category="image-vulnerability",
                    description=f"{details} Target: {target}",
                    evidence=[f"Package: {package} {installed}", f"Fixed version: {vulnerability.get('FixedVersion', 'unknown')}"],
                    remediation="Patch the image base layer, rebuild with updated packages, and rescan before release.",
                    score_penalty=penalty_for(severity),
                )
            )

    return findings
