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

## How it works

- Connects to the local Docker daemon through the Docker API
- Inspects container runtime settings and image metadata
- Applies security checks for privilege, secrets, ports, mounts, and capabilities
- Optionally scans images with Trivy when installed
- Generates table, JSON, or Markdown output for review
