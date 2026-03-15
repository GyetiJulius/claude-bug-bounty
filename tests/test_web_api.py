"""
Tests for the web API (web/app.py).

Uses FastAPI's built-in TestClient (backed by httpx) to exercise the REST
endpoints without starting a real server.  All scan executions are patched
so the tests stay fast and don't require security tools to be installed.
"""

from __future__ import annotations

import json
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Ensure repo root on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from web.app import app, _active_scans, _state_lock


@pytest.fixture(autouse=True)
def clear_active_scans():
    """Reset in-memory scan state between tests."""
    with _state_lock:
        _active_scans.clear()
    yield
    with _state_lock:
        _active_scans.clear()


@pytest.fixture()
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_health_returns_ok(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "tools" in body
    assert "timestamp" in body
    assert "python_version" in body


def test_health_tools_shape(client):
    resp = client.get("/api/health")
    tools = resp.json()["tools"]
    for name in ("subfinder", "httpx", "nuclei", "katana"):
        assert name in tools
        # Each value is a bool (installed or not)
        assert isinstance(tools[name], bool)


# ---------------------------------------------------------------------------
# List scans
# ---------------------------------------------------------------------------


def test_list_scans_empty(client, tmp_path):
    resp = client.get("/api/scans", params={"output_dir": str(tmp_path)})
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_shows_active(client, tmp_path):
    with _state_lock:
        _active_scans["run-test-001"] = {
            "run_id": "run-test-001",
            "status": "running",
            "profile": "quick",
            "targets": ["example.com"],
            "started_at": "2024-01-01T00:00:00+00:00",
            "finished_at": None,
            "output_dir": str(tmp_path),
            "dry_run": True,
        }

    resp = client.get("/api/scans", params={"output_dir": str(tmp_path)})
    assert resp.status_code == 200
    runs = resp.json()
    assert len(runs) == 1
    assert runs[0]["run_id"] == "run-test-001"
    assert runs[0]["status"] == "running"


def test_list_scans_includes_persisted(client, tmp_path):
    """Scans persisted as global_summary.json on disk should appear in the list."""
    run_id = "run-20240101T000000-abc123"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    summary = {
        "run_id": run_id,
        "status": "done",
        "profile": "quick",
        "started_at": "2024-01-01T00:00:00+00:00",
        "finished_at": "2024-01-01T00:05:00+00:00",
        "targets": {"example.com": {"status": "done", "findings": 2, "severity_breakdown": {"high": 2}, "phases": {}}},
        "totals": {"findings": 2, "high": 2},
    }
    (run_dir / "global_summary.json").write_text(json.dumps(summary))

    resp = client.get("/api/scans", params={"output_dir": str(tmp_path)})
    assert resp.status_code == 200
    runs = resp.json()
    assert any(r["run_id"] == run_id for r in runs)


# ---------------------------------------------------------------------------
# Start scan
# ---------------------------------------------------------------------------


def test_start_scan_returns_run_id(client):
    """POST /api/scans should accept a valid request and return a run_id."""
    with patch("web.app._executor") as mock_executor:
        mock_executor.submit = MagicMock()
        resp = client.post(
            "/api/scans",
            json={
                "targets": ["example.com"],
                "profile": "quick",
                "dry_run": True,
            },
        )
    assert resp.status_code == 202
    body = resp.json()
    assert "run_id" in body
    assert body["run_id"].startswith("run-")
    assert body["status"] == "running"


def test_start_scan_registers_in_active(client):
    with patch("web.app._executor") as mock_executor:
        mock_executor.submit = MagicMock()
        resp = client.post(
            "/api/scans",
            json={"targets": ["test.io"], "profile": "quick", "dry_run": True},
        )
    run_id = resp.json()["run_id"]
    with _state_lock:
        assert run_id in _active_scans
        assert _active_scans[run_id]["status"] == "running"
        assert "test.io" in _active_scans[run_id]["targets"]


def test_start_scan_requires_targets(client):
    resp = client.post("/api/scans", json={"targets": [], "profile": "quick"})
    assert resp.status_code == 422


def test_start_scan_invalid_profile(client):
    resp = client.post(
        "/api/scans",
        json={"targets": ["example.com"], "profile": "turbo"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Get scan detail
# ---------------------------------------------------------------------------


def test_get_scan_not_found(client, tmp_path):
    resp = client.get(
        "/api/scans/run-nonexistent-000",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 404


def test_get_scan_active(client, tmp_path):
    with _state_lock:
        _active_scans["run-test-002"] = {
            "run_id": "run-test-002",
            "status": "running",
            "profile": "deep",
            "targets": ["api.example.com"],
            "started_at": "2024-01-01T00:00:00+00:00",
            "finished_at": None,
            "output_dir": str(tmp_path),
            "dry_run": False,
        }

    resp = client.get(
        "/api/scans/run-test-002",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == "run-test-002"
    assert body["status"] == "running"
    assert "api.example.com" in body["targets"]


def test_get_scan_from_summary(client, tmp_path):
    run_id = "run-20240101T000000-aaa111"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    summary = {
        "run_id": run_id,
        "status": "done",
        "profile": "nightly",
        "started_at": "2024-01-01T00:00:00+00:00",
        "finished_at": "2024-01-01T00:10:00+00:00",
        "targets": {
            "example.com": {
                "status": "done",
                "findings": 3,
                "severity_breakdown": {"critical": 1, "high": 2},
                "phases": {"subdomain_enum": "done"},
            }
        },
        "totals": {"findings": 3},
    }
    (run_dir / "global_summary.json").write_text(json.dumps(summary))

    resp = client.get(
        f"/api/scans/{run_id}",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"] == run_id
    assert body["status"] == "done"
    assert body["profile"] == "nightly"
    assert "example.com" in body["targets"]
    assert body["targets"]["example.com"]["findings_count"] == 3


# ---------------------------------------------------------------------------
# Delete scan
# ---------------------------------------------------------------------------


def test_delete_scan_removes_directory(client, tmp_path):
    run_id = "run-20240101T000000-del001"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    (run_dir / "global_summary.json").write_text("{}")

    resp = client.delete(
        f"/api/scans/{run_id}",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    assert not run_dir.exists()


def test_delete_scan_not_found(client, tmp_path):
    resp = client.delete(
        "/api/scans/run-ghost",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 404


def test_delete_running_scan_rejected(client, tmp_path):
    with _state_lock:
        _active_scans["run-running-001"] = {
            "status": "running",
            "output_dir": str(tmp_path),
        }

    resp = client.delete(
        "/api/scans/run-running-001",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def test_get_findings_empty(client, tmp_path):
    run_id = "run-20240101T000000-fin001"
    (tmp_path / run_id).mkdir()

    resp = client.get(
        f"/api/scans/{run_id}/findings",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    assert resp.json()["findings"] == []
    assert resp.json()["count"] == 0


def test_get_findings_from_json(client, tmp_path):
    run_id = "run-20240101T000000-fin002"
    target = "vuln.example.com"
    run_dir = tmp_path / run_id / target
    run_dir.mkdir(parents=True)
    findings_data = [
        {"name": "SQL Injection", "severity": "critical", "url": "https://vuln.example.com/search?q=1", "template_id": "sqli-001"},
        {"name": "XSS", "severity": "high", "url": "https://vuln.example.com/page", "template_id": "xss-001"},
    ]
    (run_dir / "findings_dedup.json").write_text(json.dumps(findings_data))

    resp = client.get(
        f"/api/scans/{run_id}/findings",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    names = {f["name"] for f in body["findings"]}
    assert "SQL Injection" in names
    assert "XSS" in names


def test_get_findings_not_found(client, tmp_path):
    resp = client.get(
        "/api/scans/run-ghost/findings",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def test_get_report_not_found(client, tmp_path):
    run_id = "run-20240101T000000-rpt001"
    (tmp_path / run_id).mkdir()

    resp = client.get(
        f"/api/scans/{run_id}/targets/example.com/report",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 404


def test_get_report_success(client, tmp_path):
    run_id = "run-20240101T000000-rpt002"
    target = "example.com"
    target_dir = tmp_path / run_id / target
    target_dir.mkdir(parents=True)
    report_md = "# Report\n\n## Findings\n\n- XSS found"
    (target_dir / "report.md").write_text(report_md)

    resp = client.get(
        f"/api/scans/{run_id}/targets/{target}/report",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"] == target
    assert body["content"] == report_md


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_get_summary_not_found(client, tmp_path):
    resp = client.get(
        "/api/scans/run-ghost/summary",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 404


def test_get_summary_success(client, tmp_path):
    run_id = "run-20240101T000000-sum001"
    run_dir = tmp_path / run_id
    run_dir.mkdir()
    summary = {"run_id": run_id, "status": "done", "totals": {"findings": 5}}
    (run_dir / "global_summary.json").write_text(json.dumps(summary))

    resp = client.get(
        f"/api/scans/{run_id}/summary",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    assert resp.json()["run_id"] == run_id
    assert resp.json()["totals"]["findings"] == 5


def test_get_summary_running_scan(client, tmp_path):
    with _state_lock:
        _active_scans["run-sum-active"] = {
            "status": "running",
            "profile": "quick",
            "started_at": "2024-01-01T00:00:00+00:00",
        }

    resp = client.get(
        "/api/scans/run-sum-active/summary",
        params={"output_dir": str(tmp_path)},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "running"
