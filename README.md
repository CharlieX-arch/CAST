# Container Security Audit Toolkit

Container Security Audit Toolkit is a Docker security assessment project that inspects running containers and produces CIS Docker Benchmark-aligned findings.

It combines Docker API inspection, optional image vulnerability scanning, risk scoring, and Markdown or JSON reporting.

## What it checks

- Privileged and host namespace settings
- Secrets exposed through environment variables
- Exposed and published ports
- Insecure bind mounts and Docker socket exposure
- Dangerous Linux capabilities and root execution
- Optional image vulnerability scanning through Trivy when installed

## Why it is useful

- Gives fast, repeatable container security triage from the Docker API
- Produces findings that map to CIS Docker Benchmark-style control areas
- Creates resume-friendly evidence of security automation, not just manual review
- Works well in local lab environments and demo stacks

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
csaudit audit --all --format table
```

## Example output

The report includes:

- Overall risk score
- CIS control references
- Severity breakdown
- Actionable remediation guidance

## Project structure

- src/csat/cli.py provides the command line interface
- src/csat/detectors.py contains the Docker security rules
- src/csat/trivy.py adds optional image vulnerability integration
- src/csat/reporting.py renders Markdown and JSON reports
- scripts/audit.sh offers a Bash wrapper for lab use

## Resume impact

Suggested resume wording:

- Developed a Docker container security audit toolkit that inspects runtime privilege boundaries, bind mounts, exposed ports, and environment-based secrets through the Docker API.
- Added optional image vulnerability scanning and CIS Docker Benchmark-aligned risk scoring to generate prioritized remediation findings.
- Automated repeatable container audit reporting in Markdown and JSON for lab environments and security review workflows.
