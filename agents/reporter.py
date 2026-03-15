"""
Reporter agent.

Generates per-target Markdown reports and global JSON summaries.

Outputs:
  output/<run_id>/<target>/report.md
  output/<run_id>/<target>/findings_dedup.json   (already written by scanner)
  output/<run_id>/global_summary.json
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from models.state import Finding, GlobalRunState, TargetState
from utils.logging_utils import StructuredLogger

__all__ = ["ReporterAgent"]


class ReporterAgent:
    """
    Generate Markdown and JSON reports for a completed run.

    Parameters
    ----------
    run_state:
        The completed global run state.
    logger:
        Structured logger.
    llm:
        Optional LangChain chat model.  When provided, AI-generated cluster
        summaries are included in the report.
    """

    def __init__(
        self,
        run_state: GlobalRunState,
        logger: StructuredLogger,
        llm: Optional[Any] = None,
    ) -> None:
        self._run = run_state
        self._log = logger
        self._llm = llm
        run_id = run_state.get("run_id", "unknown")
        out_root = run_state.get("config", {}).get("output_dir", "output")
        self._out_root = Path(out_root) / run_id

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Generate all reports."""
        self._out_root.mkdir(parents=True, exist_ok=True)

        targets = self._run.get("targets", {})
        for target, state in targets.items():
            try:
                self._report_target(target, state)
            except Exception as exc:  # noqa: BLE001
                self._log.error(f"Failed to generate report for {target}: {exc}")

        self._global_summary()
        self._log.info("Reporting complete", run_id=self._run.get("run_id"))

    # ------------------------------------------------------------------
    # Per-target report
    # ------------------------------------------------------------------

    def _report_target(self, target: str, state: TargetState) -> None:
        target_dir = self._out_root / target
        target_dir.mkdir(parents=True, exist_ok=True)

        findings = state.get("deduped_findings") or state.get("findings") or []
        phases = state.get("phases", {})
        run_id = self._run.get("run_id", "")

        # AI cluster summary (optional)
        ai_summary = ""
        if self._llm and findings:
            ai_summary = self._ai_cluster_summary(findings, target)

        md = _render_target_report(
            target=target,
            run_id=run_id,
            findings=findings,
            phases=phases,
            ai_summary=ai_summary,
            started_at=self._run.get("started_at", ""),
            finished_at=self._run.get("finished_at", ""),
        )
        (target_dir / "report.md").write_text(md, encoding="utf-8")
        self._log.info(f"Report written: {target_dir}/report.md", target=target)

    def _ai_cluster_summary(self, findings: list[Finding], target: str) -> str:
        """Call LLM to generate a cluster summary; returns empty string on failure."""
        from llm.prompts import cluster_summary_prompt
        try:
            messages = cluster_summary_prompt(findings, target)  # type: ignore[arg-type]
            # Convert to LangChain message objects
            from langchain_core.messages import HumanMessage, SystemMessage  # type: ignore[import-untyped]
            lc_messages = []
            for m in messages:
                if m["role"] == "system":
                    lc_messages.append(SystemMessage(content=m["content"]))
                else:
                    lc_messages.append(HumanMessage(content=m["content"]))
            response = self._llm.invoke(lc_messages)
            return getattr(response, "content", str(response))
        except Exception as exc:  # noqa: BLE001
            self._log.warning(f"AI summary failed: {exc}", target=target)
            return ""

    # ------------------------------------------------------------------
    # Global summary
    # ------------------------------------------------------------------

    def _global_summary(self) -> None:
        targets = self._run.get("targets", {})
        summary: dict[str, Any] = {
            "run_id": self._run.get("run_id"),
            "started_at": self._run.get("started_at"),
            "finished_at": self._run.get("finished_at") or _now(),
            "profile": self._run.get("config", {}).get("profile", "quick"),
            "tool_versions": self._run.get("tool_versions", {}),
            "targets": {},
            "totals": {
                "targets": len(targets),
                "findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        for target, state in targets.items():
            findings = state.get("deduped_findings") or state.get("findings") or []
            sev_counts: dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "unknown").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                if sev in summary["totals"]:
                    summary["totals"][sev] += 1

            summary["totals"]["findings"] += len(findings)
            summary["targets"][target] = {
                "status": state.get("status", "unknown"),
                "findings": len(findings),
                "severity_breakdown": sev_counts,
                "phases": {
                    k: v.get("status") for k, v in state.get("phases", {}).items()
                },
            }

        out_file = self._out_root / "global_summary.json"
        out_file.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        self._log.info(f"Global summary: {out_file}")


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def _render_target_report(
    target: str,
    run_id: str,
    findings: list[Finding],
    phases: dict[str, Any],
    ai_summary: str,
    started_at: str,
    finished_at: str,
) -> str:
    now_str = _now()

    sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_table_rows = []
    for sev in sev_order:
        count = sev_counts.get(sev, 0)
        if count:
            sev_table_rows.append(f"| {sev.capitalize()} | {count} |")

    severity_section = "\n".join(sev_table_rows) or "| — | 0 |"

    # Phase table
    phase_rows = []
    for phase, result in phases.items():
        status = result.get("status", "?")
        artifact = result.get("artifact_path", "")
        phase_rows.append(f"| {phase} | {status} | {artifact} |")
    phase_table = "\n".join(phase_rows) or "| — | — | — |"

    # Findings list
    findings_sections = []
    for f in sorted(findings, key=lambda x: _sev_order(x.get("severity", "unknown"))):
        sev = f.get("severity", "?").upper()
        name = f.get("name", "Unknown")
        url = f.get("url", f.get("matched_at", ""))
        desc = f.get("description", "")
        tid = f.get("template_id", "")
        tags = ", ".join(f.get("tags") or [])

        block = (
            f"### [{sev}] {name}\n\n"
            f"- **Template**: `{tid}`\n"
            f"- **URL**: `{url}`\n"
            + (f"- **Tags**: {tags}\n" if tags else "")
            + (f"- **Description**: {desc}\n" if desc else "")
        )
        findings_sections.append(block)

    findings_md = "\n---\n\n".join(findings_sections) or "_No findings._"

    ai_section = f"\n## AI Risk Summary\n\n{ai_summary}\n" if ai_summary else ""

    return f"""# Security Scan Report — {target}

**Run ID**: `{run_id}`
**Generated**: {now_str}
**Scan started**: {started_at}
**Scan finished**: {finished_at}

> ⚠️ This report is for **authorized security testing only**.
> Never use these results for unauthorized access.

---

## Severity Summary

| Severity | Count |
|----------|-------|
{severity_section}

**Total findings**: {len(findings)}
{ai_section}
---

## Pipeline Phases

| Phase | Status | Artifact |
|-------|--------|----------|
{phase_table}

---

## Findings

{findings_md}
"""


def _sev_order(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(sev.lower(), 5)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
