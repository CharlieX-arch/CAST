from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from .models import Finding
from .scoring import penalty_for


SECRET_KEY_PATTERN = re.compile(r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)", re.IGNORECASE)
DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
    "SYS_TIME",
    "AUDIT_CONTROL",
}
SENSITIVE_MOUNTS = {
    "/var/run/docker.sock",
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/root",
}


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _env_pairs(config: Dict[str, Any]) -> Iterable[tuple[str, str]]:
    for raw_item in config.get("Env", []) or []:
        if "=" not in raw_item:
            continue
        key, value = raw_item.split("=", 1)
        yield key, value


def detect_privilege_findings(container: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    host_config = container.get("HostConfig", {}) or {}
    config = container.get("Config", {}) or {}

    if host_config.get("Privileged"):
        findings.append(
            Finding(
                id="PRIVILEGED-CONTAINER",
                title="Container is running in privileged mode",
                severity="critical",
                cis_control="CIS 5.2",
                category="privilege",
                description="Privileged mode grants broad access to the host kernel and weakens isolation boundaries.",
                evidence=["HostConfig.Privileged=true"],
                remediation="Remove privileged mode and grant only the minimum capabilities required by the workload.",
                score_penalty=penalty_for("critical"),
            )
        )

    for mode_name in ("NetworkMode", "IpcMode", "PidMode"):
        mode_value = _stringify(host_config.get(mode_name))
        if mode_value in {"host", "container:host"}:
            findings.append(
                Finding(
                    id=f"HOST-{mode_name.upper()}",
                    title=f"Container uses host {mode_name[:-4].lower()} namespace",
                    severity="high",
                    cis_control="CIS 5.3",
                    category="namespace",
                    description=f"{mode_name} is set to host-like behavior, which increases lateral movement and data exposure risk.",
                    evidence=[f"HostConfig.{mode_name}={mode_value}"],
                    remediation="Use isolated namespaces unless a host namespace is explicitly required and justified.",
                    score_penalty=penalty_for("high"),
                )
            )

    cap_add = set(host_config.get("CapAdd") or [])
    dangerous_caps = sorted(cap_add.intersection(DANGEROUS_CAPABILITIES))
    if dangerous_caps:
        findings.append(
            Finding(
                id="DANGEROUS-CAPABILITIES",
                title="Container has dangerous Linux capabilities added",
                severity="high",
                cis_control="CIS 5.3",
                category="capabilities",
                description="Additional capabilities reduce the security boundary and should be limited to explicit need.",
                evidence=[f"CapAdd={', '.join(dangerous_caps)}"],
                remediation="Drop unnecessary capabilities and prefer a narrowed seccomp or capability set.",
                score_penalty=penalty_for("high"),
            )
        )

    if not config.get("User"):
        findings.append(
            Finding(
                id="ROOT-DEFAULT",
                title="Container runs without an explicit non-root user",
                severity="medium",
                cis_control="CIS 4.1",
                category="user-context",
                description="An unset user often means the container will run as root by default.",
                evidence=["Config.User is empty"],
                remediation="Set a dedicated non-root UID or user in the image or runtime configuration.",
                score_penalty=penalty_for("medium"),
            )
        )

    return findings


def detect_env_secret_findings(container: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    config = container.get("Config", {}) or {}

    for key, value in _env_pairs(config):
        if not SECRET_KEY_PATTERN.search(key):
            continue
        if len(value.strip()) < 4:
            continue
        findings.append(
            Finding(
                id=f"SECRET-ENV-{key.upper()}",
                title=f"Potential secret exposed in environment variable {key}",
                severity="high",
                cis_control="CIS 4.3",
                category="secrets",
                description="Secrets stored in environment variables are easy to leak through process listings, logs, and crash dumps.",
                evidence=[f"{key}=<redacted>"],
                remediation="Move secrets to Docker secrets, mounted files, or a dedicated secret manager.",
                score_penalty=penalty_for("high"),
            )
        )

    return findings


def detect_port_findings(container: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    config = container.get("Config", {}) or {}
    network = container.get("NetworkSettings", {}) or {}
    exposed_ports = config.get("ExposedPorts") or {}
    published_ports = network.get("Ports") or {}

    if exposed_ports:
        findings.append(
            Finding(
                id="EXPOSED-PORTS",
                title="Container image exposes network ports",
                severity="medium",
                cis_control="CIS 4.5",
                category="network",
                description="Published or exposed ports enlarge the attack surface and should be justified.",
                evidence=[f"ExposedPorts={', '.join(sorted(exposed_ports.keys()))}"],
                remediation="Only expose ports that are required and pair them with firewall or network policy controls.",
                score_penalty=penalty_for("medium"),
            )
        )

    published = [port for port, bindings in published_ports.items() if bindings]
    if published:
        findings.append(
            Finding(
                id="PUBLISHED-PORTS",
                title="Container has published host ports",
                severity="medium",
                cis_control="CIS 4.5",
                category="network",
                description="Published host ports create direct ingress paths from the host network.",
                evidence=[f"PublishedPorts={', '.join(published)}"],
                remediation="Restrict port publishing to the smallest possible set and confirm they are externally required.",
                score_penalty=penalty_for("medium"),
            )
        )

    return findings


def detect_mount_findings(container: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    host_config = container.get("HostConfig", {}) or {}
    mounts = container.get("Mounts", []) or []

    bind_targets = host_config.get("Binds") or []
    all_mount_evidence = list(bind_targets)

    for mount in mounts:
        source = _stringify(mount.get("Source"))
        destination = _stringify(mount.get("Destination"))
        mode = _stringify(mount.get("Mode")) or _stringify(mount.get("RW"))
        all_mount_evidence.append(f"{source}:{destination}:{mode}")
        normalized_source = source.replace("\\", "/").lower()
        normalized_destination = destination.replace("\\", "/").lower()
        if normalized_source in SENSITIVE_MOUNTS or normalized_destination in SENSITIVE_MOUNTS:
            findings.append(
                Finding(
                    id="SENSITIVE-MOUNT",
                    title="Container mounts a sensitive host path",
                    severity="high",
                    cis_control="CIS 5.8",
                    category="mounts",
                    description="Sensitive bind mounts can expose host state or enable container escape paths.",
                    evidence=[f"{source}:{destination}"],
                    remediation="Remove sensitive mounts or convert them to read-only, scoped, and purpose-built volumes.",
                    score_penalty=penalty_for("high"),
                )
            )
        if mount.get("RW", False):
            findings.append(
                Finding(
                    id="READ-WRITE-MOUNT",
                    title="Container has a writable host volume mount",
                    severity="medium",
                    cis_control="CIS 5.8",
                    category="mounts",
                    description="Writable mounts increase the blast radius of a compromise and should be minimized.",
                    evidence=[f"{source}:{destination}:rw"],
                    remediation="Use read-only mounts when writes are not necessary and isolate data paths per service.",
                    score_penalty=penalty_for("medium"),
                )
            )

    if any("docker.sock" in mount.lower() for mount in all_mount_evidence):
        findings.append(
            Finding(
                id="DOCKER-SOCK-MOUNT",
                title="Container can access the Docker socket",
                severity="critical",
                cis_control="CIS 5.8",
                category="mounts",
                description="Access to the Docker socket is effectively host-level control in many environments.",
                evidence=[entry for entry in all_mount_evidence if "docker.sock" in entry.lower()],
                remediation="Remove the Docker socket mount or proxy it through a narrowly scoped management service.",
                score_penalty=penalty_for("critical"),
            )
        )

    return findings


def audit_container(container: Dict[str, Any], image_findings: List[Finding] | None = None) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(detect_privilege_findings(container))
    findings.extend(detect_env_secret_findings(container))
    findings.extend(detect_port_findings(container))
    findings.extend(detect_mount_findings(container))
    if image_findings:
        findings.extend(image_findings)
    return findings
