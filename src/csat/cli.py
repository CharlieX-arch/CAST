from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import docker
import typer
from rich.console import Console
from rich.table import Table

from .detectors import audit_container
from .models import AuditResult
from .reporting import render_markdown, results_to_json, write_report
from .trivy import scan_image


app = typer.Typer(add_completion=False, help="Docker container security audit toolkit")
console = Console()


def _docker_client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except docker.errors.DockerException as exc:  # type: ignore[attr-defined]
        raise typer.BadParameter(f"Unable to connect to Docker: {exc}") from exc


def _container_to_result(container) -> AuditResult:
    inspect = container.attrs
    image_ref = inspect.get("Config", {}).get("Image", container.image.tags[0] if container.image.tags else container.image.short_id)
    image_findings = scan_image(image_ref)
    findings = audit_container(inspect, image_findings=image_findings)
    notes = []
    if not image_findings:
        notes.append("No image vulnerabilities were recorded. Install Trivy to enable image vulnerability scanning.")
    return AuditResult(container_name=container.name, image=image_ref, findings=findings, notes=notes)


def _render_summary(results: List[AuditResult]) -> None:
    table = Table(title="Container Security Audit Summary", show_lines=True)
    table.add_column("Container", style="bold")
    table.add_column("Image")
    table.add_column("Score", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("High", justify="right")
    table.add_column("Medium", justify="right")

    for result in results:
        counts = result.severity_counts()
        table.add_row(
            result.container_name,
            result.image,
            str(result.score),
            str(counts.get("critical", 0)),
            str(counts.get("high", 0)),
            str(counts.get("medium", 0)),
        )

    console.print(table)


@app.command()
def audit(
    all: bool = typer.Option(False, "--all", help="Audit all running containers"),
    container: List[str] = typer.Option([], "--container", help="Container name or ID to audit", show_default=False),
    output: Optional[Path] = typer.Option(None, "--output", help="Write a Markdown report to this path"),
    format: str = typer.Option("table", "--format", help="Output format: table, json, markdown"),
) -> None:
    client = _docker_client()

    targets = []
    if all:
        targets = client.containers.list()
    elif container:
        for reference in container:
            targets.append(client.containers.get(reference))
    else:
        raise typer.BadParameter("Provide --all or at least one --container reference.")

    results = [_container_to_result(target) for target in targets]

    if output is not None:
        write_report(output, results)
        console.print(f"Wrote Markdown report to {output}")

    if format == "json":
        console.print(results_to_json(results))
    elif format == "markdown":
        console.print(render_markdown(results))
    else:
        _render_summary(results)


def main() -> None:
    app()
