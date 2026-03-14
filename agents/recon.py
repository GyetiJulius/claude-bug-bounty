"""
Recon agent.

Orchestrates:
  1. Subdomain discovery   (subfinder, assetfinder)
  2. Live host detection   (httpx-toolkit)
  3. URL collection        (waybackurls, gau, katana)
  4. URL filtering         (scope + dedup + static removal)
  5. Parameter extraction  (grep for query strings)
  6. Param URL validation  (httpx)

All tool invocations respect dry_run and honour per-target output dirs.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.policy import ScopePolicy, PolicyViolation
from models.state import PhaseStatus, TargetState
from utils.logging_utils import StructuredLogger
from utils.url_filter import URLFilter

__all__ = ["ReconAgent"]

# Tools that should be present for full functionality
_RECON_TOOLS = ["subfinder", "httpx", "waybackurls", "gau", "katana", "assetfinder"]


class ReconAgent:
    """
    Execute the reconnaissance pipeline for a single target.

    Parameters
    ----------
    target_state:
        Mutable state dict for the target (modified in-place).
    policy:
        Scope and safety policy.
    logger:
        Structured logger.
    completed_phases:
        Set of phase names already completed (for resume support).
    force:
        Re-run phases even if already marked complete.
    """

    def __init__(
        self,
        target_state: TargetState,
        policy: ScopePolicy,
        logger: StructuredLogger,
        completed_phases: Optional[set[str]] = None,
        force: bool = False,
    ) -> None:
        self._state = target_state
        self._policy = policy
        self._log = logger
        self._done = completed_phases or set()
        self._force = force
        self._target = target_state["target"]
        self._out = Path(target_state.get("output_dir", f"output/{self._target}"))
        self._out.mkdir(parents=True, exist_ok=True)
        self._url_filter = URLFilter()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> TargetState:
        """Execute all recon phases and return the updated state."""
        self._policy.assert_in_scope(self._target, phase="recon")

        phases = [
            ("subdomain_enum", self._phase_subdomain_enum),
            ("live_host_check", self._phase_live_host_check),
            ("url_collection", self._phase_url_collection),
            ("url_filter", self._phase_url_filter),
            ("param_extraction", self._phase_param_extraction),
            ("alive_params", self._phase_alive_params),
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
            except PolicyViolation as exc:
                self._set_phase(phase_name, PhaseStatus.FAILED, error=str(exc))
                self._log.phase_failed(phase_name, self._target, str(exc))
                raise
            except Exception as exc:  # noqa: BLE001
                self._set_phase(phase_name, PhaseStatus.FAILED, error=str(exc))
                self._log.phase_failed(phase_name, self._target, str(exc))
                # Continue to next phase — failure isolation

        self._state["status"] = PhaseStatus.DONE
        return self._state

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------

    def _phase_subdomain_enum(self) -> None:
        out_file = self._out / "subdomains.txt"
        if self._policy.dry_run:
            self._log.info("[dry-run] Skipping subfinder", target=self._target)
            out_file.touch()
            self._state["subdomains"] = []
            return

        combined: set[str] = set()

        # subfinder
        combined.update(self._run_tool_lines(
            f"subfinder -d {self._target} -silent -o /dev/stdout",
            phase="subdomain_enum",
            tool="subfinder",
        ))

        # assetfinder (optional)
        if _tool_available("assetfinder"):
            combined.update(self._run_tool_lines(
                f"assetfinder --subs-only {self._target}",
                phase="subdomain_enum",
                tool="assetfinder",
            ))

        # Always include the root target itself
        combined.add(self._target)

        # Scope filter
        in_scope = [d for d in combined if self._policy.is_in_scope(d) or d == self._target]
        self._write_lines(out_file, sorted(in_scope))
        self._state["subdomains"] = sorted(in_scope)
        self._set_phase("subdomain_enum", PhaseStatus.RUNNING, artifact=str(out_file))

    def _phase_live_host_check(self) -> None:
        subs = self._state.get("subdomains") or self._read_lines(self._out / "subdomains.txt")
        if not subs:
            self._state["alive_hosts"] = []
            return

        out_file = self._out / "alive_subdomains.txt"
        if self._policy.dry_run:
            self._log.info("[dry-run] Skipping httpx live-check", target=self._target)
            self._state["alive_hosts"] = subs
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(subs))
            tmp_path = tmp.name

        try:
            lines = self._run_tool_lines(
                f"httpx -l {tmp_path} -silent -follow-redirects -o /dev/stdout",
                phase="live_host_check",
                tool="httpx",
            )
        finally:
            os.unlink(tmp_path)

        self._write_lines(out_file, lines)
        self._state["alive_hosts"] = lines
        self._set_phase("live_host_check", PhaseStatus.RUNNING, artifact=str(out_file))

    def _phase_url_collection(self) -> None:
        alive = self._state.get("alive_hosts") or self._read_lines(self._out / "alive_subdomains.txt")
        if not alive:
            self._state["all_urls"] = []
            return

        out_file = self._out / "all_urls.txt"
        if self._policy.dry_run:
            self._log.info("[dry-run] Skipping URL collection", target=self._target)
            self._state["all_urls"] = []
            return

        combined: set[str] = set()

        for host in alive:
            domain = host.replace("https://", "").replace("http://", "").split("/")[0]

            # waybackurls
            combined.update(self._run_tool_lines(
                f"echo {domain} | waybackurls",
                phase="url_collection",
                tool="waybackurls",
            ))

            # gau
            combined.update(self._run_tool_lines(
                f"gau --subs {domain}",
                phase="url_collection",
                tool="gau",
            ))

            # katana
            combined.update(self._run_tool_lines(
                f"katana -u {host} -silent -depth 3 -o /dev/stdout",
                phase="url_collection",
                tool="katana",
            ))

        self._write_lines(out_file, sorted(combined))
        self._state["all_urls"] = sorted(combined)
        self._set_phase("url_collection", PhaseStatus.RUNNING, artifact=str(out_file))

    def _phase_url_filter(self) -> None:
        all_urls = self._state.get("all_urls") or self._read_lines(self._out / "all_urls.txt")
        filtered = self._url_filter.filter(all_urls)

        out_file = self._out / "filtered_urls.txt"
        self._write_lines(out_file, filtered)
        self._state["filtered_urls"] = filtered
        self._log.info(
            f"URL filter: {len(all_urls)} → {len(filtered)} URLs",
            target=self._target,
        )
        self._set_phase("url_filter", PhaseStatus.RUNNING, artifact=str(out_file))

    def _phase_param_extraction(self) -> None:
        filtered = self._state.get("filtered_urls") or self._read_lines(self._out / "filtered_urls.txt")
        param_urls = self._url_filter.extract_param_urls(filtered)

        out_file = self._out / "params.txt"
        self._write_lines(out_file, param_urls)
        self._state["param_urls"] = param_urls
        self._log.info(
            f"Param extraction: {len(param_urls)} URLs with params",
            target=self._target,
        )
        self._set_phase("param_extraction", PhaseStatus.RUNNING, artifact=str(out_file))

    def _phase_alive_params(self) -> None:
        param_urls = self._state.get("param_urls") or self._read_lines(self._out / "params.txt")
        if not param_urls:
            self._state["alive_param_urls"] = []
            return

        out_file = self._out / "alive_params.txt"
        if self._policy.dry_run:
            self._log.info("[dry-run] Skipping param URL validation", target=self._target)
            self._state["alive_param_urls"] = param_urls
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(param_urls))
            tmp_path = tmp.name

        try:
            lines = self._run_tool_lines(
                f"httpx -l {tmp_path} -silent -follow-redirects -o /dev/stdout",
                phase="alive_params",
                tool="httpx",
            )
        finally:
            os.unlink(tmp_path)

        self._write_lines(out_file, lines)
        self._state["alive_param_urls"] = lines
        self._set_phase("alive_params", PhaseStatus.RUNNING, artifact=str(out_file))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_tool_lines(self, cmd: str, phase: str, tool: str) -> list[str]:
        """Run *cmd* and return non-empty stdout lines.  Logs tool errors."""
        if not _tool_available(tool.split()[0]):
            self._log.warning(f"Tool not found: {tool}", target=self._target, phase=phase)
            return []
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300
            )
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
        except subprocess.TimeoutExpired:
            self._log.warning(f"{tool} timed out", target=self._target, phase=phase)
            return []
        except Exception as exc:  # noqa: BLE001
            self._log.warning(f"{tool} error: {exc}", target=self._target, phase=phase)
            return []

    def _write_lines(self, path: Path, lines: list[str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

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


def _tool_available(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
