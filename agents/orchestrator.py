"""
Multi-target orchestrator.

Processes multiple targets in parallel (bounded concurrency), tracking
per-target state and aggregating a global summary on completion.

Design
------
- Each target runs in its own thread via ``ThreadPoolExecutor``.
- One target failing does not crash others (failure isolation).
- Per-target checkpoint files allow ``--resume`` to skip completed phases.
- Structured JSON logging throughout.
- SQLite persistence of run state and findings.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agents.recon import ReconAgent
from agents.scanner import ScannerAgent
from agents.reporter import ReporterAgent
from models.policy import ScopePolicy, PolicyViolation
from models.state import (
    GlobalRunState,
    PhaseStatus,
    RunConfig,
    TargetState,
)
from utils.db import ScanDatabase
from utils.logging_utils import StructuredLogger

__all__ = ["Orchestrator"]


class Orchestrator:
    """
    Top-level multi-target orchestrator.

    Parameters
    ----------
    config:
        ``RunConfig`` dict; typically built from CLI args.
    """

    def __init__(self, config: RunConfig) -> None:
        self._cfg = config
        self._run_id = config.get("run_id") or _new_run_id()
        self._cfg["run_id"] = self._run_id  # type: ignore[typeddict-unknown-key]

        out_root = config.get("output_dir", "output")
        run_dir = Path(out_root) / self._run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        log_file = config.get("json_log_file") or str(run_dir / "run.log.json")
        self._log = StructuredLogger(
            name=f"appsec.{self._run_id[:8]}",
            log_file=log_file,
            level=config.get("log_level", "INFO"),
        )

        db_path = str(run_dir / "scans.db")
        self._db = ScanDatabase(db_path)

        self._policy = _build_policy(config)
        self._llm: Optional[Any] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> GlobalRunState:
        """
        Execute the full pipeline across all configured targets.

        Returns
        -------
        GlobalRunState
            The aggregated state after all targets have been processed.
        """
        targets = self._cfg.get("targets", [])
        if not targets:
            self._log.error("No targets specified")
            return self._empty_state()

        self._log.info(
            f"Starting run {self._run_id} with {len(targets)} target(s)",
            profile=self._cfg.get("profile", "quick"),
            dry_run=self._cfg.get("dry_run", False),
        )

        self._db.create_run(
            self._run_id,
            config=dict(self._cfg),
            profile=self._cfg.get("profile", "quick"),
        )

        started_at = _now()
        tool_versions = _collect_tool_versions()

        state: GlobalRunState = {
            "run_id": self._run_id,
            "config": self._cfg,
            "targets": {},
            "started_at": started_at,
            "tool_versions": tool_versions,
            "status": PhaseStatus.RUNNING.value,
        }

        # Optionally initialise LLM
        if not self._cfg.get("dry_run"):
            self._llm = _try_create_llm(self._cfg, self._log)

        max_workers = max(1, self._cfg.get("threads", 10))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self._process_target, target): target
                for target in targets
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    target_state = future.result()
                    state["targets"][target] = target_state
                except Exception as exc:  # noqa: BLE001
                    self._log.error(f"Target {target} crashed: {exc}", target=target)
                    state["targets"][target] = _error_state(
                        target, self._run_id, str(exc),
                        output_dir=str(Path(self._cfg.get("output_dir", "output")) / self._run_id / target),
                    )

        state["finished_at"] = _now()
        state["status"] = PhaseStatus.DONE.value

        self._db.finish_run(self._run_id, status="done")

        # Reporting
        try:
            reporter = ReporterAgent(state, self._log, llm=self._llm)
            reporter.run()
        except Exception as exc:  # noqa: BLE001
            self._log.error(f"Reporting failed: {exc}")

        self._log.info(
            f"Run {self._run_id} complete",
            targets=len(targets),
            elapsed=_elapsed(started_at),
        )
        return state

    # ------------------------------------------------------------------
    # Per-target pipeline
    # ------------------------------------------------------------------

    def _process_target(self, target: str) -> TargetState:
        """Process a single target through the full pipeline."""
        out_dir = str(
            Path(self._cfg.get("output_dir", "output")) / self._run_id / target
        )
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        checkpoint_file = str(Path(out_dir) / "checkpoint.json")

        # Resume: load completed phases
        completed_phases: set[str] = set()
        if self._cfg.get("resume") and not self._cfg.get("force"):
            completed_phases = self._db.get_completed_phases(self._run_id, target)
            if completed_phases:
                self._log.info(
                    f"Resuming {target}: skipping {completed_phases}",
                    target=target,
                )

        state: TargetState = {
            "target": target,
            "run_id": self._run_id,
            "authorization_id": self._cfg.get("authorization_id", ""),
            "output_dir": out_dir,
            "checkpoint_file": checkpoint_file,
            "phases": {},
            "status": PhaseStatus.RUNNING.value,
        }

        # Validate scope before doing any work
        try:
            self._policy.assert_in_scope(target, phase="init")
        except PolicyViolation as exc:
            self._log.error(f"Scope violation for {target}: {exc}", target=target)
            state["status"] = PhaseStatus.FAILED.value
            state["error"] = str(exc)
            return state

        # Phase: recon (always run unless explicitly disabled)
        if True:  # recon always runs; crawl_only only skips the scan phase
            recon = ReconAgent(
                state,
                self._policy,
                self._log,
                completed_phases=completed_phases,
                force=bool(self._cfg.get("force")),
            )
            try:
                recon.run()
                self._save_checkpoint(state)
                self._persist_phases(state)
            except PolicyViolation as exc:
                state["status"] = PhaseStatus.FAILED.value
                state["error"] = str(exc)
                return state
            except Exception as exc:  # noqa: BLE001
                self._log.error(f"Recon error for {target}: {exc}", target=target)
                # Continue to scan phase if we have previous data

        # Phase: scan (requires auth)
        if not self._cfg.get("crawl_only", False):
            scanner = ScannerAgent(
                state,
                self._policy,
                self._log,
                profile=self._cfg.get("profile", "quick"),
                threads=self._cfg.get("threads", 10),
                rate_limit=self._cfg.get("rate_limit", 50),
                nuclei_severity=self._cfg.get("nuclei_severity"),
                nuclei_templates=self._cfg.get("nuclei_templates"),
                completed_phases=completed_phases,
                force=bool(self._cfg.get("force")),
            )
            try:
                scanner.run()
                self._save_checkpoint(state)
                self._persist_phases(state)
                self._persist_findings(state)
            except PolicyViolation as exc:
                self._log.warning(
                    f"Scan skipped for {target} (policy): {exc}", target=target
                )

        state["status"] = PhaseStatus.DONE.value
        return state

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _save_checkpoint(self, state: TargetState) -> None:
        cp_file = state.get("checkpoint_file")
        if not cp_file:
            return
        data = {
            "run_id": state.get("run_id"),
            "target": state.get("target"),
            "phases": state.get("phases", {}),
            "saved_at": _now(),
        }
        Path(cp_file).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _persist_phases(self, state: TargetState) -> None:
        run_id = state.get("run_id", "")
        target = state.get("target", "")
        for phase, result in state.get("phases", {}).items():
            self._db.upsert_phase(
                run_id=run_id,
                target=target,
                phase=phase,
                status=result.get("status", "unknown"),
                started_at=result.get("started_at"),
                finished_at=result.get("finished_at"),
                artifact=result.get("artifact_path"),
                error=result.get("error"),
            )

    def _persist_findings(self, state: TargetState) -> None:
        findings = state.get("deduped_findings") or state.get("findings") or []
        for f in findings:
            try:
                self._db.insert_finding(dict(f))
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _empty_state(self) -> GlobalRunState:
        return {
            "run_id": self._run_id,
            "config": self._cfg,
            "targets": {},
            "started_at": _now(),
            "status": PhaseStatus.FAILED.value,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_policy(config: RunConfig) -> ScopePolicy:
    """Construct a ScopePolicy from RunConfig."""
    return ScopePolicy(
        allowlist_suffixes=config.get("scope_allowlist", []),
        exact_domains=config.get("scope_exact", []),
        require_authorization=not config.get("dry_run", False),
        authorization_id=config.get("authorization_id", ""),
        max_threads=config.get("threads", 10),
        max_rate=config.get("rate_limit", 50),
        dry_run=config.get("dry_run", False),
    )


def _new_run_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    short = uuid.uuid4().hex[:6]
    return f"run-{ts}-{short}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed(started_at: str) -> str:
    try:
        start = datetime.fromisoformat(started_at)
        delta = datetime.now(timezone.utc) - start
        return str(delta).split(".")[0]
    except Exception:  # noqa: BLE001
        return "?"


def _try_create_llm(config: RunConfig, log: StructuredLogger) -> Optional[Any]:
    """Attempt to create an LLM instance; return None on failure."""
    try:
        from llm.factory import create_llm
        from llm.config import LLMConfig

        llm_cfg = LLMConfig(
            provider=config.get("llm_provider", "groq"),  # type: ignore[arg-type]
            model=config.get("llm_model", ""),
            fallback_provider=config.get("llm_fallback_provider"),  # type: ignore[arg-type]
        )
        return create_llm(llm_cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning(f"LLM unavailable (skipping AI features): {exc}")
        return None


def _collect_tool_versions() -> dict[str, str]:
    """Collect version strings for key tools (best-effort)."""
    tools = {
        "subfinder": "subfinder -version",
        "httpx": "httpx -version",
        "nuclei": "nuclei -version",
        "katana": "katana -version",
        "waybackurls": "waybackurls -version",
        "gau": "gau --version",
    }
    versions: dict[str, str] = {}
    for tool, cmd in tools.items():
        if shutil.which(tool):
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=5
                )
                out = (result.stdout + result.stderr).strip().splitlines()
                versions[tool] = out[0] if out else "installed"
            except Exception:  # noqa: BLE001
                versions[tool] = "installed"
        else:
            versions[tool] = "not found"
    return versions


def _error_state(
    target: str,
    run_id: str,
    error: str,
    output_dir: str = "",
) -> TargetState:
    return {
        "target": target,
        "run_id": run_id,
        "status": PhaseStatus.FAILED.value,
        "error": error,
        "phases": {},
        "output_dir": output_dir,
    }
