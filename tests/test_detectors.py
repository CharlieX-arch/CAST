from csat.detectors import audit_container
from csat.models import AuditResult


def sample_container():
    return {
        "Config": {
            "Image": "demo/web:latest",
            "Env": [
                "APP_MODE=production",
                "DB_PASSWORD=supersecret",
                "API_TOKEN=abcdef123456",
            ],
            "ExposedPorts": {"80/tcp": {}, "443/tcp": {}},
            "User": "",
        },
        "HostConfig": {
            "Privileged": True,
            "NetworkMode": "host",
            "IpcMode": "host",
            "PidMode": "host",
            "CapAdd": ["SYS_ADMIN", "NET_ADMIN"],
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/data:/data:rw"],
        },
        "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}},
        "Mounts": [
            {"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True},
            {"Source": "/data", "Destination": "/data", "RW": True},
        ],
    }


def test_audit_detects_multiple_high_risk_findings():
    findings = audit_container(sample_container())
    ids = {finding.id for finding in findings}

    assert "PRIVILEGED-CONTAINER" in ids
    assert "SECRET-ENV-DB_PASSWORD" in ids
    assert "EXPOSED-PORTS" in ids
    assert "DOCKER-SOCK-MOUNT" in ids


def test_audit_result_scoring_aggregates_penalties():
    result = AuditResult(container_name="demo", image="demo/web:latest", findings=audit_container(sample_container()))
    assert result.score < 100
    assert result.severity_counts()["critical"] >= 1
