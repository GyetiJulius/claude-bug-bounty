"""
Scanner agent.

Orchestrates nuclei scanning against alive parameter URLs, with configurable
severity filters, templates, concurrency, and rate limits.

All active-scan phases require an explicit authorization_id.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from models.policy import ScopePolicy, PolicyViolation
from models.state import Finding, PhaseStatus, TargetState
from utils.logging_utils import StructuredLogger

__all__ = ["ScannerAgent"]

# Nuclei severity presets per profile
_PROFILE_SEVERITY: dict[str, list[str]] = {
    "quick": ["critical", "high"],
    "deep": ["critical", "high", "medium"],
    "nightly": ["critical", "high", "medium", "low"],
}


class ScannerAgent:
    """
    Execute nuclei scanning against a target's alive param URLs.

    Parameters
    ----------
    target_state:
        Mutable per-target state dict.
    policy:
        Scope and safety policy (authorization check happens here).
    logger:
        Structured logger.
    profile:
        Scan profile (``quick`` | ``deep`` | ``nightly``).
    threads:
        Nuclei concurrency level.
    rate_limit:
        Max HTTP requests per second.
    nuclei_severity:
        Explicit severity list; overrides profile default if provided.
    nuclei_templates:
        Extra template paths / tags to pass to nuclei.
    completed_phases:
        Already-completed phases (resume support).
    force:
        Re-run completed phases.
    """

    def __init__(
        self,
        target_state: TargetState,
        policy: ScopePolicy,
        logger: StructuredLogger,
        profile: str = "quick",
        threads: int = 10,
        rate_limit: int = 50,
        nuclei_severity: Optional[list[str]] = None,
        nuclei_templates: Optional[list[str]] = None,
        completed_phases: Optional[set[str]] = None,
        force: bool = False,
    ) -> None:
        self._state = target_state
        self._policy = policy
        self._log = logger
        self._profile = profile
        self._threads = min(threads, policy.max_threads)
        self._rate = min(rate_limit, policy.max_rate)
        self._severity = nuclei_severity or _PROFILE_SEVERITY.get(profile, ["critical", "high"])
        self._templates = nuclei_templates or []
        self._done = completed_phases or set()
        self._force = force
        self._target = target_state["target"]
        self._out = Path(target_state.get("output_dir", f"output/{self._target}"))
        self._out.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> TargetState:
        """Execute scanning pipeline and return updated state."""
        self._policy.assert_in_scope(self._target, phase="scan")
        self._policy.assert_authorized(phase="scan")

        phases = [
            ("nuclei_scan", self._phase_nuclei_scan),
            ("finding_dedup", self._phase_finding_dedup),
        ]

        for phase_name, handler in phases:
            if phase_name in self._done and not self._force:
                self._log.info(f"Skipping completed phase: {phase_name}", target=self._target)
                self._set_phase(phase_name, PhaseStatus.SKIPPED)
                continue

            self._log.phase_start(phase_name, self._target)
            self._set_phase(phase_name, PhaseStatus.RUNNING, started_at=_now())
            try:
                handler()
                self._set_phase(phase_name, PhaseStatus.DONE, finished_at=_now())
                self._log.phase_done(phase_name, self._target)
            except PolicyViolation:
                raise
            except Exception as exc:  # noqa: BLE001
                self._set_phase(phase_name, PhaseStatus.FAILED, error=str(exc))
                self._log.phase_failed(phase_name, self._target, str(exc))

        return self._state

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------

    def _phase_nuclei_scan(self) -> None:
        """Run nuclei against alive param URLs."""
        param_file = self._out / "alive_params.txt"
        if not param_file.exists():
            # Fall back to filtered_urls
            param_file = self._out / "filtered_urls.txt"
        if not param_file.exists() or param_file.stat().st_size == 0:
            self._log.warning("No URLs to scan", target=self._target)
            self._state.setdefault("findings", [])
            return

        findings_json = self._out / "findings.json"
        findings_txt = self._out / "findings.txt"

        severity_flag = ",".join(self._severity)
        template_flags = " ".join(f"-t {t}" for t in self._templates) if self._templates else ""

        if self._policy.dry_run:
            self._log.info("[dry-run] Skipping nuclei scan", target=self._target)
            findings_json.write_text("[]", encoding="utf-8")
            self._state["findings"] = []
            return

        if not _tool_available("nuclei"):
            self._log.warning("nuclei not found — skipping scan phase", target=self._target)
            self._state.setdefault("findings", [])
            return

        cmd = (
            f"nuclei -l {param_file} "
            f"-severity {severity_flag} "
            f"-c {self._threads} "
            f"-rl {self._rate} "
            f"-json -o {findings_json} "
            f"-silent "
            f"{template_flags}"
        ).strip()

        self._log.info(f"Running: {cmd}", target=self._target)

        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=1800
            )
            if result.returncode not in (0, 1):  # nuclei exits 1 when findings exist
                self._log.warning(
                    f"nuclei non-zero exit {result.returncode}: {result.stderr[:200]}",
                    target=self._target,
                )
        except subprocess.TimeoutExpired:
            self._log.warning("nuclei timed out", target=self._target)

        # Parse JSON output (one JSON object per line)
        findings = _parse_nuclei_json(findings_json, self._target, self._state.get("run_id", ""))
        self._state["findings"] = findings

        # Plain text summary
        _write_findings_txt(findings_txt, findings)
        self._set_phase("nuclei_scan", PhaseStatus.RUNNING, artifact=str(findings_json))

    def _phase_finding_dedup(self) -> None:
        """Deduplicate findings by (template_id, url) key."""
        findings = self._state.get("findings") or _parse_nuclei_json(
            self._out / "findings.json", self._target, self._state.get("run_id", "")
        )

        seen: set[tuple[str, str]] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.get("template_id", ""), f.get("url", f.get("matched_at", "")))
            if key not in seen:
                seen.add(key)
                f["deduplicated"] = True
                deduped.append(f)

        out_file = self._out / "findings_dedup.json"
        out_file.write_text(
            json.dumps(deduped, indent=2, default=str), encoding="utf-8"
        )
        self._state["deduped_findings"] = deduped
        self._log.info(
            f"Dedup: {len(findings)} → {len(deduped)} findings",
            target=self._target,
        )
        self._set_phase("finding_dedup", PhaseStatus.RUNNING, artifact=str(out_file))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_phase(
        self,
        phase: str,
        status: PhaseStatus,
        *,
        started_at: Optional[str] = None,
        finished_at: Optional[str] = None,
        artifact: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        phases = self._state.setdefault("phases", {})  # type: ignore[attr-defined]
        existing = phases.get(phase, {})
        phases[phase] = {
            **existing,
            "status": status.value,
            **({"started_at": started_at} if started_at else {}),
            **({"finished_at": finished_at} if finished_at else {}),
            **({"artifact_path": artifact} if artifact else {}),
            **({"error": error} if error else {}),
        }


# ---------------------------------------------------------------------------
# Nuclei output parsing
# ---------------------------------------------------------------------------


def _parse_nuclei_json(path: Path, target: str, run_id: str) -> list[Finding]:
    """Parse nuclei JSON-lines output into Finding dicts."""
    if not path.exists():
        return []
    findings: list[Finding] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        f: Finding = {
            "template_id": raw.get("template-id", raw.get("templateID", "")),
            "name": raw.get("info", {}).get("name", raw.get("name", "")),
            "severity": raw.get("info", {}).get("severity", raw.get("severity", "unknown")),
            "url": raw.get("matched-at", raw.get("url", "")),
            "matched_at": raw.get("matched-at", ""),
            "description": raw.get("info", {}).get("description", ""),
            "tags": raw.get("info", {}).get("tags", []),
            "classification": raw.get("info", {}).get("classification", {}),
            "extracted_results": raw.get("extracted-results", []),
            "target": target,
            "run_id": run_id,
            "deduplicated": False,
        }
        findings.append(f)
    return findings


def _write_findings_txt(path: Path, findings: list[Finding]) -> None:
    lines = []
    for f in findings:
        sev = f.get("severity", "unknown").upper()
        name = f.get("name", "?")
        url = f.get("url", f.get("matched_at", ""))
        lines.append(f"[{sev}] {name} — {url}")
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _tool_available(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
