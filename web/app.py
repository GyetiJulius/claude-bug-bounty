"""
web/app.py — FastAPI backend for the AppSec Multi-Agent Framework.

Provides a REST API that wraps the existing agents/orchestrator pipeline and
serves the single-page frontend.

Endpoints
---------
GET  /                                     Serve SPA
GET  /api/health                           Health + tool availability check
GET  /api/tools                            List installed tools
POST /api/scans                            Launch a new scan (background thread)
GET  /api/scans                            List all scan runs
GET  /api/scans/{run_id}                   Get run status & target summaries
DELETE /api/scans/{run_id}                 Remove a run (output + DB record)
GET  /api/scans/{run_id}/findings          All findings for a run
GET  /api/scans/{run_id}/targets/{target}/findings   Per-target findings
GET  /api/scans/{run_id}/targets/{target}/report     Per-target Markdown report
GET  /api/scans/{run_id}/summary           Global summary JSON
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import threading
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so local modules resolve correctly
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

logger = logging.getLogger(__name__)

from models.state import RunConfig  # noqa: E402  (after path fixup)

# ---------------------------------------------------------------------------
# Global in-memory state for active / recently completed scans
# ---------------------------------------------------------------------------
_active_scans: dict[str, dict[str, Any]] = {}
_state_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=4)

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AppSec Multi-Agent Framework",
    description=(
        "Web interface for the AppSec multi-agent security scanning framework. "
        "Authorized use only — only scan systems you have explicit permission to test."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the SPA static files (if directory exists)
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1, description="List of target domains")
    profile: str = Field("quick", pattern="^(quick|deep|nightly)$")
    authorization_id: str = Field("", description="Required for active scan phases")
    dry_run: bool = False
    crawl_only: bool = False
    skip_subfinder: bool = False
    resume: bool = False
    threads: Optional[int] = Field(None, ge=1, le=50)
    rate_limit: Optional[int] = Field(None, ge=1, le=500)
    severity: Optional[str] = None
    provider: Optional[str] = Field(None, pattern="^(groq|cerebras)$")
    model: Optional[str] = None
    scope_allowlist: Optional[str] = None
    scope_exact: Optional[str] = None
    output_dir: str = "output"


class ScanSummary(BaseModel):
    run_id: str
    status: str
    profile: str
    targets: list[str]
    started_at: str
    finished_at: Optional[str] = None
    total_findings: int = 0
    dry_run: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _load_global_summary(run_id: str, output_dir: str = "output") -> Optional[dict]:
    path = Path(output_dir) / run_id / "global_summary.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _count_findings_from_summary(summary: Optional[dict]) -> int:
    if not summary:
        return 0
    return summary.get("totals", {}).get("findings", 0)


def _list_run_dirs(output_dir: str = "output") -> list[str]:
    """Scan output directory for run subdirectories."""
    root = Path(output_dir)
    if not root.exists():
        return []
    return sorted(
        [d.name for d in root.iterdir() if d.is_dir() and d.name.startswith("run-")],
        reverse=True,
    )


def _get_run_meta(run_id: str, output_dir: str = "output") -> Optional[dict]:
    """Build a metadata dict for a run from global_summary.json (or active state)."""
    with _state_lock:
        active = _active_scans.get(run_id)

    if active:
        summary = _load_global_summary(run_id, active.get("output_dir", output_dir))
        return {
            "run_id": run_id,
            "status": active.get("status", "running"),
            "profile": active.get("profile", "quick"),
            "targets": active.get("targets", []),
            "started_at": active.get("started_at", ""),
            "finished_at": active.get("finished_at"),
            "total_findings": _count_findings_from_summary(summary),
            "dry_run": active.get("dry_run", False),
        }

    # Try loading from persisted summary
    summary = _load_global_summary(run_id, output_dir)
    if summary:
        return {
            "run_id": run_id,
            "status": summary.get("status", "done"),
            "profile": summary.get("profile", "quick"),
            "targets": list(summary.get("targets", {}).keys()),
            "started_at": summary.get("started_at", ""),
            "finished_at": summary.get("finished_at"),
            "total_findings": _count_findings_from_summary(summary),
            "dry_run": False,
        }

    return None


def _build_run_config(req: ScanRequest, run_id: str) -> RunConfig:
    """Convert a ScanRequest into a RunConfig dict."""
    profile_defaults = {
        "quick":   {"threads": 10, "rate_limit": 50,  "nuclei_severity": ["critical", "high"]},
        "deep":    {"threads": 15, "rate_limit": 30,  "nuclei_severity": ["critical", "high", "medium"]},
        "nightly": {"threads": 20, "rate_limit": 20,  "nuclei_severity": ["critical", "high", "medium", "low"]},
    }
    defaults = profile_defaults.get(req.profile, profile_defaults["quick"])

    scope_allowlist = (
        [s.strip() for s in req.scope_allowlist.split(",") if s.strip()]
        if req.scope_allowlist else []
    )
    scope_exact = (
        [s.strip() for s in req.scope_exact.split(",") if s.strip()]
        if req.scope_exact else list(req.targets)
    )
    if scope_allowlist:
        scope_exact = []

    nuclei_severity = (
        [s.strip() for s in req.severity.split(",") if s.strip()]
        if req.severity else defaults["nuclei_severity"]
    )

    llm_provider = req.provider or os.environ.get("LLM_PROVIDER", "groq")
    llm_model = req.model or os.environ.get("LLM_MODEL", "")
    llm_fallback = os.environ.get("LLM_FALLBACK_PROVIDER", "")

    config: RunConfig = {
        "run_id": run_id,
        "targets": req.targets,
        "authorization_id": req.authorization_id or os.environ.get("AUTHORIZATION_ID", ""),
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "llm_fallback_provider": llm_fallback,
        "profile": req.profile,
        "threads": req.threads or defaults["threads"],
        "rate_limit": req.rate_limit or defaults["rate_limit"],
        "nuclei_severity": nuclei_severity,
        "nuclei_templates": [],
        "dry_run": req.dry_run,
        "resume": req.resume,
        "force": False,
        "skip_subfinder": req.skip_subfinder,
        "crawl_only": req.crawl_only,
        "scope_allowlist": scope_allowlist,
        "scope_exact": scope_exact,
        "output_dir": req.output_dir,
        "log_level": "INFO",
        "json_log_file": "",
    }
    return config


def _run_scan_background(run_id: str, config: RunConfig) -> None:
    """Execute a scan in a background thread; update in-memory state on finish."""
    from agents.orchestrator import Orchestrator

    try:
        orch = Orchestrator(config)
        final_state = orch.run()

        with _state_lock:
            if run_id in _active_scans:
                _active_scans[run_id]["status"] = final_state.get("status", "done")
                _active_scans[run_id]["final_state"] = final_state
                _active_scans[run_id]["finished_at"] = _now()

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Scan %s failed: %s\n%s",
            run_id,
            exc,
            traceback.format_exc(),
        )
        with _state_lock:
            if run_id in _active_scans:
                _active_scans[run_id]["status"] = "failed"
                _active_scans[run_id]["error"] = f"{type(exc).__name__}: {exc}"
                _active_scans[run_id]["finished_at"] = _now()


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def serve_spa():
    """Serve the SPA index.html."""
    from fastapi.responses import FileResponse
    index = _static_dir / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"message": "AppSec Multi-Agent Framework API — see /api/docs"})


@app.get("/api/health")
async def health():
    """Health check: returns tool availability and API status."""
    tools = {
        t: _tool_available(t)
        for t in ["subfinder", "httpx", "nuclei", "katana", "waybackurls", "gau", "assetfinder"]
    }
    return {
        "status": "ok",
        "timestamp": _now(),
        "tools": tools,
        "python_version": sys.version.split()[0],
    }


@app.get("/api/tools")
async def list_tools():
    """Detailed tool availability check."""
    import subprocess  # noqa: PLC0415

    tools = ["subfinder", "httpx", "nuclei", "katana", "waybackurls", "gau", "assetfinder", "nmap"]
    result = {}
    for tool in tools:
        if _tool_available(tool):
            try:
                r = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=3)
                ver = (r.stdout + r.stderr).strip().splitlines()
                result[tool] = {"installed": True, "version": ver[0] if ver else "installed"}
            except subprocess.TimeoutExpired:
                result[tool] = {"installed": True, "version": "installed (version check timed out)"}
            except Exception:  # noqa: BLE001
                result[tool] = {"installed": True, "version": "installed (version unavailable)"}
        else:
            result[tool] = {"installed": False, "version": None}
    return result


@app.post("/api/scans", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(req: ScanRequest):
    """Launch a new scan in the background. Returns run_id immediately."""
    import uuid  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    run_id = f"run-{ts}-{uuid.uuid4().hex[:6]}"

    config = _build_run_config(req, run_id)

    with _state_lock:
        _active_scans[run_id] = {
            "run_id": run_id,
            "status": "running",
            "profile": req.profile,
            "targets": req.targets,
            "started_at": _now(),
            "finished_at": None,
            "output_dir": req.output_dir,
            "dry_run": req.dry_run,
        }

    # Submit to thread pool (fire-and-forget, state updated by callback)
    _executor.submit(_run_scan_background, run_id, config)

    return {
        "run_id": run_id,
        "status": "running",
        "message": f"Scan started with {len(req.targets)} target(s)",
    }


@app.get("/api/scans")
async def list_scans(output_dir: str = "output"):
    """List all scan runs (active + persisted)."""
    runs: list[dict] = []
    seen: set[str] = set()

    # Active scans first
    with _state_lock:
        active_ids = list(_active_scans.keys())

    for run_id in active_ids:
        meta = _get_run_meta(run_id, output_dir)
        if meta:
            runs.append(meta)
            seen.add(run_id)

    # Persisted scans from output directory
    for run_id in _list_run_dirs(output_dir):
        if run_id not in seen:
            meta = _get_run_meta(run_id, output_dir)
            if meta:
                runs.append(meta)

    return runs


@app.get("/api/scans/{run_id}")
async def get_scan(run_id: str, output_dir: str = "output"):
    """Get full status and target details for a run."""
    # Check in-memory active scans first
    with _state_lock:
        active = _active_scans.get(run_id)

    if active:
        final_state = active.get("final_state")
        if final_state:
            return _format_run_detail(run_id, final_state, active)

        # Still running: read intermediate state from SQLite + filesystem
        return _build_intermediate_state(run_id, active, output_dir)

    # Try loading from persisted global summary
    summary = _load_global_summary(run_id, output_dir)
    if summary:
        return _format_summary_as_detail(run_id, summary)

    raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")


@app.delete("/api/scans/{run_id}", status_code=status.HTTP_200_OK)
async def delete_scan(run_id: str, output_dir: str = "output"):
    """Remove an existing scan run (output files + in-memory state)."""
    with _state_lock:
        if run_id in _active_scans and _active_scans[run_id].get("status") == "running":
            raise HTTPException(
                status_code=409,
                detail="Cannot delete a running scan. Wait for it to finish.",
            )
        _active_scans.pop(run_id, None)

    run_dir = Path(output_dir) / run_id
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)
    elif not _load_global_summary(run_id, output_dir):
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    return {"ok": True, "run_id": run_id}


@app.get("/api/scans/{run_id}/findings")
async def get_findings(
    run_id: str,
    target: Optional[str] = None,
    severity: Optional[str] = None,
    output_dir: str = "output",
):
    """Get findings for a run, optionally filtered by target or severity."""
    run_dir = Path(output_dir) / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

    findings: list[dict] = []

    # Try to load from per-target findings_dedup.json files
    for target_dir in run_dir.iterdir():
        if not target_dir.is_dir():
            continue
        t_name = target_dir.name
        if target and t_name != target:
            continue

        for fname in ("findings_dedup.json", "findings.json"):
            fpath = target_dir / fname
            if fpath.exists():
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        for f in data:
                            if isinstance(f, dict):
                                f["target"] = t_name
                                if severity is None or f.get("severity", "").lower() == severity.lower():
                                    findings.append(f)
                    break
                except Exception:  # noqa: BLE001
                    logger.warning("Failed to parse %s", fpath, exc_info=True)

    # Fall back to SQLite if available
    if not findings:
        db_path = run_dir / "scans.db"
        if db_path.exists():
            from utils.db import ScanDatabase  # noqa: PLC0415
            try:
                db = ScanDatabase(str(db_path))
                rows = db.get_findings(run_id, target=target, severity=severity)
                for row in rows:
                    if "raw_json" in row and row["raw_json"]:
                        try:
                            f = json.loads(row["raw_json"])
                            findings.append(f)
                        except Exception:  # noqa: BLE001
                            logger.warning("Failed to parse raw_json for finding id=%s", row.get("id"), exc_info=True)
                            findings.append(row)
                    else:
                        findings.append(row)
                db.close()
            except Exception:  # noqa: BLE001
                logger.warning("Failed to read findings from SQLite for run %s", run_id, exc_info=True)

    return {"run_id": run_id, "count": len(findings), "findings": findings}


@app.get("/api/scans/{run_id}/targets/{target_name}/findings")
async def get_target_findings(
    run_id: str,
    target_name: str,
    severity: Optional[str] = None,
    output_dir: str = "output",
):
    """Get findings for a specific target within a run."""
    return await get_findings(run_id, target=target_name, severity=severity, output_dir=output_dir)


@app.get("/api/scans/{run_id}/targets/{target_name}/report")
async def get_target_report(run_id: str, target_name: str, output_dir: str = "output"):
    """Get the Markdown report for a specific target."""
    report_path = Path(output_dir) / run_id / target_name / "report.md"
    if not report_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Report not found for target '{target_name}' in run '{run_id}'",
        )
    content = report_path.read_text(encoding="utf-8")
    return {"run_id": run_id, "target": target_name, "content": content}


@app.get("/api/scans/{run_id}/summary")
async def get_summary(run_id: str, output_dir: str = "output"):
    """Get the global summary JSON for a run."""
    summary = _load_global_summary(run_id, output_dir)
    if not summary:
        # Try active scan intermediate state
        with _state_lock:
            active = _active_scans.get(run_id)
        if active:
            return {
                "run_id": run_id,
                "status": active.get("status", "running"),
                "profile": active.get("profile", "quick"),
                "started_at": active.get("started_at", ""),
                "message": "Scan in progress — summary not yet available",
            }
        raise HTTPException(status_code=404, detail=f"Summary not found for run '{run_id}'")
    return summary


# ---------------------------------------------------------------------------
# Internal helpers for state formatting
# ---------------------------------------------------------------------------


def _format_run_detail(run_id: str, state: dict, active: dict) -> dict:
    """Format a completed GlobalRunState for the API response."""
    targets_out = {}
    for t, ts in state.get("targets", {}).items():
        findings = ts.get("deduped_findings") or ts.get("findings") or []
        targets_out[t] = {
            "target": t,
            "status": ts.get("status", "?"),
            "phases": ts.get("phases", {}),
            "findings_count": len(findings),
            "severity_breakdown": _severity_breakdown(findings),
            "error": ts.get("error"),
        }

    return {
        "run_id": run_id,
        "status": state.get("status", active.get("status", "done")),
        "profile": state.get("config", {}).get("profile", active.get("profile", "quick")),
        "started_at": state.get("started_at", active.get("started_at", "")),
        "finished_at": state.get("finished_at", active.get("finished_at")),
        "dry_run": state.get("config", {}).get("dry_run", active.get("dry_run", False)),
        "targets": targets_out,
        "tool_versions": state.get("tool_versions", {}),
    }


def _build_intermediate_state(run_id: str, active: dict, output_dir: str) -> dict:
    """Build a partial run state from the SQLite DB for an in-progress scan."""
    run_dir = Path(output_dir) / run_id
    targets_out: dict[str, Any] = {}

    for t in active.get("targets", []):
        target_dir = run_dir / t
        phases: dict[str, Any] = {}

        # Try reading checkpoint
        cp_file = target_dir / "checkpoint.json"
        if cp_file.exists():
            try:
                cp = json.loads(cp_file.read_text(encoding="utf-8"))
                phases = cp.get("phases", {})
            except Exception:  # noqa: BLE001
                pass

        # Try SQLite for phase status
        db_path = run_dir / "scans.db"
        if db_path.exists() and not phases:
            try:
                from utils.db import ScanDatabase  # noqa: PLC0415
                db = ScanDatabase(str(db_path))
                completed = db.get_completed_phases(run_id, t)
                # Build a phases dict from completed set; running phases aren't yet in DB
                phases = {ph: {"status": "done"} for ph in completed}
                db.close()
            except Exception:  # noqa: BLE001
                logger.warning("Failed to read phase status from DB for %s/%s", run_id, t, exc_info=True)

        targets_out[t] = {
            "target": t,
            "status": "running",
            "phases": phases,
            "findings_count": 0,
            "severity_breakdown": {},
            "error": None,
        }

    return {
        "run_id": run_id,
        "status": "running",
        "profile": active.get("profile", "quick"),
        "started_at": active.get("started_at", ""),
        "finished_at": None,
        "dry_run": active.get("dry_run", False),
        "targets": targets_out,
        "tool_versions": {},
    }


def _format_summary_as_detail(run_id: str, summary: dict) -> dict:
    """Convert a global_summary.json into the run detail format."""
    targets_out: dict[str, Any] = {}
    for t, info in summary.get("targets", {}).items():
        targets_out[t] = {
            "target": t,
            "status": info.get("status", "done"),
            "phases": {
                name: {"status": s}
                for name, s in info.get("phases", {}).items()
            },
            "findings_count": info.get("findings", 0),
            "severity_breakdown": info.get("severity_breakdown", {}),
            "error": None,
        }

    return {
        "run_id": run_id,
        "status": summary.get("status", "done"),
        "profile": summary.get("profile", "quick"),
        "started_at": summary.get("started_at", ""),
        "finished_at": summary.get("finished_at"),
        "dry_run": False,
        "targets": targets_out,
        "tool_versions": summary.get("tool_versions", {}),
    }


def _severity_breakdown(findings: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower() if isinstance(f, dict) else "unknown"
        counts[sev] = counts.get(sev, 0) + 1
    return counts
