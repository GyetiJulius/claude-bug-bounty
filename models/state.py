"""
TypedDict-based state models for the AppSec multi-agent pipeline.

Using TypedDict keeps the models lightweight and avoids a hard Pydantic
dependency while still giving type-checkers enough information.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, TypedDict


class PhaseStatus(str, Enum):
    """Lifecycle status for an individual pipeline phase."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"


class Finding(TypedDict, total=False):
    """A single vulnerability finding, compatible with nuclei JSON output."""

    template_id: str
    name: str
    severity: str          # critical | high | medium | low | info
    url: str
    matched_at: str
    description: str
    tags: list[str]
    classification: dict[str, Any]
    extracted_results: list[str]
    # Internal metadata added by the pipeline
    target: str
    run_id: str
    deduplicated: bool


class PhaseResult(TypedDict, total=False):
    """Result record for a single pipeline phase."""

    status: str             # PhaseStatus value
    started_at: str         # ISO-8601
    finished_at: str
    artifact_path: str      # primary output file
    error: str


class TargetState(TypedDict, total=False):
    """Per-target pipeline state tracked throughout the run."""

    target: str             # e.g. "example.com"
    authorization_id: str   # required for active-scan phases
    run_id: str

    # Phase results
    phases: dict[str, PhaseResult]  # phase_name → PhaseResult

    # Aggregated artifacts
    subdomains: list[str]
    alive_hosts: list[str]
    all_urls: list[str]
    filtered_urls: list[str]
    param_urls: list[str]
    alive_param_urls: list[str]
    findings: list[Finding]
    deduped_findings: list[Finding]

    # Output paths
    output_dir: str
    checkpoint_file: str

    # Final disposition
    status: str             # PhaseStatus value
    error: Optional[str]


class RunConfig(TypedDict, total=False):
    """Top-level run configuration, populated from CLI args and environment."""

    run_id: str
    targets: list[str]
    authorization_id: str

    # Provider / LLM
    llm_provider: str
    llm_model: str
    llm_fallback_provider: str

    # Scan profile
    profile: str            # quick | deep | nightly
    threads: int
    rate_limit: int         # requests/second
    nuclei_severity: list[str]
    nuclei_templates: list[str]

    # Behaviour flags
    dry_run: bool
    resume: bool
    force: bool             # re-run completed phases even when resuming
    skip_subfinder: bool
    crawl_only: bool

    # Scope
    scope_allowlist: list[str]    # suffixes like ".example.com"
    scope_exact: list[str]        # exact domain matches

    # Paths
    output_dir: str

    # Observability
    log_level: str
    json_log_file: str


class GlobalRunState(TypedDict, total=False):
    """Aggregated state across all targets for a single run."""

    run_id: str
    config: RunConfig
    targets: dict[str, TargetState]   # domain → TargetState
    started_at: str
    finished_at: str
    status: str
    global_summary: dict[str, Any]
    tool_versions: dict[str, str]
