#!/usr/bin/env python3
"""
scanner.py — Advanced AppSec Multi-Agent Framework CLI

A production-grade defensive security automation tool for authorized
bug bounty and security assessment workflows.

IMPORTANT — Authorized use only:
  This tool must only be run against systems you have explicit written
  permission to test.  Unauthorized scanning is illegal.

Usage examples:
  python3 scanner.py example.com
  python3 scanner.py -l targets.txt --profile deep --auth-id AUTH-2024-001
  python3 scanner.py example.com --dry-run
  python3 scanner.py example.com --profile quick --provider groq --resume
  python3 scanner.py example.com --threads 5 --rate-limit 20 --crawl-only
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path when run directly
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from models.state import RunConfig


# ---------------------------------------------------------------------------
# ANSI colours (no external dep)
# ---------------------------------------------------------------------------
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_YELLOW = "\033[1;33m"
_CYAN = "\033[0;36m"
_BOLD = "\033[1m"
_NC = "\033[0m"


def _print_banner() -> None:
    print(
        f"""
{_BOLD}{_CYAN}╔══════════════════════════════════════════════════════╗
║   AppSec Multi-Agent Framework  (authorized use only) ║
╚══════════════════════════════════════════════════════╝{_NC}
"""
    )


def _ok(msg: str) -> None:
    print(f"{_GREEN}{_BOLD}[+]{_NC} {msg}")


def _warn(msg: str) -> None:
    print(f"{_YELLOW}{_BOLD}[!]{_NC} {msg}")


def _err(msg: str) -> None:
    print(f"{_RED}{_BOLD}[-]{_NC} {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"{_CYAN}{_BOLD}[*]{_NC} {msg}")


# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------

def check_python_dependencies() -> None:
    """Warn about missing optional Python packages."""
    optional: list[tuple[str, str]] = [
        ("langchain_groq", "pip install langchain-groq"),
        ("langchain_cerebras", "pip install langchain-cerebras"),
    ]
    for mod, install_cmd in optional:
        try:
            __import__(mod)
        except ImportError:
            _warn(f"Optional package not installed: {mod}  ({install_cmd})")


def check_system_tools() -> list[str]:
    """Check for required system tools; return list of missing ones."""
    import shutil
    required = ["subfinder", "httpx", "nuclei"]
    optional = ["katana", "waybackurls", "gau", "assetfinder"]

    missing_required = [t for t in required if not shutil.which(t)]
    missing_optional = [t for t in optional if not shutil.which(t)]

    if missing_required:
        _warn(f"Missing required tools: {', '.join(missing_required)}")
        _warn("Run: bash install_tools.sh")
    if missing_optional:
        _info(f"Optional tools not found: {', '.join(missing_optional)}")

    return missing_required


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------

def load_targets(args: argparse.Namespace) -> list[str]:
    """Resolve targets from positional args and/or --list file."""
    targets: list[str] = []

    if args.targets:
        for t in args.targets:
            t = t.strip()
            if t:
                targets.append(t)

    if args.list:
        list_path = Path(args.list)
        if not list_path.exists():
            _err(f"Targets file not found: {args.list}")
            sys.exit(1)
        for line in list_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    return unique


# ---------------------------------------------------------------------------
# Config builder
# ---------------------------------------------------------------------------

def build_config(args: argparse.Namespace, targets: list[str]) -> RunConfig:
    """Build a RunConfig from parsed CLI arguments and environment variables."""
    # Scope: if no scope flags given, use the targets themselves as exact scope
    scope_exact = list(targets)
    scope_allowlist: list[str] = []
    if args.scope_allowlist:
        scope_allowlist = [s.strip() for s in args.scope_allowlist.split(",") if s.strip()]
        scope_exact = []  # explicit allowlist overrides auto-scope
    if args.scope_exact:
        scope_exact = [s.strip() for s in args.scope_exact.split(",") if s.strip()]

    # Profile defaults
    profile = args.profile or "quick"
    profile_defaults: dict[str, dict] = {
        "quick": {"threads": 10, "rate_limit": 50, "nuclei_severity": ["critical", "high"]},
        "deep": {"threads": 15, "rate_limit": 30, "nuclei_severity": ["critical", "high", "medium"]},
        "nightly": {"threads": 20, "rate_limit": 20, "nuclei_severity": ["critical", "high", "medium", "low"]},
    }
    defaults = profile_defaults.get(profile, profile_defaults["quick"])

    threads = args.threads if args.threads else defaults["threads"]
    rate_limit = args.rate_limit if args.rate_limit else defaults["rate_limit"]
    nuclei_severity = (
        [s.strip() for s in args.severity.split(",") if s.strip()]
        if args.severity
        else defaults["nuclei_severity"]
    )

    # LLM provider — CLI → env → default
    llm_provider = (
        args.provider
        or os.environ.get("LLM_PROVIDER", "groq")
    )
    llm_model = args.model or os.environ.get("LLM_MODEL", "")
    llm_fallback = os.environ.get("LLM_FALLBACK_PROVIDER", "")

    auth_id = args.auth_id or os.environ.get("AUTHORIZATION_ID", "")

    config: RunConfig = {
        "targets": targets,
        "authorization_id": auth_id,
        "llm_provider": llm_provider,
        "llm_model": llm_model,
        "llm_fallback_provider": llm_fallback,
        "profile": profile,
        "threads": threads,
        "rate_limit": rate_limit,
        "nuclei_severity": nuclei_severity,
        "nuclei_templates": [],
        "dry_run": bool(args.dry_run),
        "resume": bool(args.resume),
        "force": bool(getattr(args, "force", False)),
        "skip_subfinder": bool(getattr(args, "skip_subfinder", False)),
        "crawl_only": bool(args.crawl_only),
        "scope_allowlist": scope_allowlist,
        "scope_exact": scope_exact,
        "output_dir": args.output or "output",
        "log_level": args.log_level or "INFO",
        "json_log_file": "",
    }
    return config


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    _print_banner()

    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "AppSec Multi-Agent Framework — authorized security scanning only.\n"
            "Use --dry-run to validate configuration without making network requests."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py example.com
  python3 scanner.py example.com --auth-id AUTH-2024-001 --profile deep
  python3 scanner.py -l targets.txt --dry-run
  python3 scanner.py example.com --provider cerebras --model llama3.1-70b
  python3 scanner.py example.com --threads 5 --rate-limit 20 --resume
  python3 scanner.py example.com --crawl-only --profile quick
  python3 scanner.py example.com --scope-allowlist .example.com,.sub.example.com

Environment variables:
  GROQ_API_KEY              Groq API key
  CEREBRAS_API_KEY          Cerebras API key
  LLM_PROVIDER              groq | cerebras  (default: groq)
  LLM_MODEL                 Override model name
  LLM_FALLBACK_PROVIDER     Fallback LLM provider
  AUTHORIZATION_ID          Authorization ID for active scans
        """,
    )

    # Targets
    parser.add_argument(
        "targets", nargs="*", metavar="TARGET",
        help="Target domain(s) to scan (e.g. example.com)",
    )
    parser.add_argument(
        "-l", "--list", metavar="FILE",
        help="File containing one target domain per line",
    )

    # Profile
    parser.add_argument(
        "--profile", choices=["quick", "deep", "nightly"], default="quick",
        help="Scan profile (default: quick)",
    )

    # Scope
    parser.add_argument(
        "--scope-allowlist", metavar="SUFFIXES",
        help="Comma-separated in-scope domain suffixes (e.g. .example.com)",
    )
    parser.add_argument(
        "--scope-exact", metavar="DOMAINS",
        help="Comma-separated exact in-scope domains",
    )

    # Auth
    parser.add_argument(
        "--auth-id", metavar="ID",
        help="Authorization ID for active scan phases (required unless --dry-run)",
    )

    # Performance
    parser.add_argument("--threads", type=int, help="Concurrency (default: profile-specific)")
    parser.add_argument("--rate-limit", type=int, help="Max requests/second (default: profile-specific)")
    parser.add_argument("--severity", metavar="LEVELS", help="Comma-separated nuclei severities")

    # LLM
    parser.add_argument(
        "--provider", choices=["groq", "cerebras"],
        help="LLM provider (overrides LLM_PROVIDER env var)",
    )
    parser.add_argument("--model", help="LLM model name (overrides LLM_MODEL env var)")

    # Behaviour
    parser.add_argument("--dry-run", action="store_true", help="Validate config, no network requests")
    parser.add_argument("--resume", action="store_true", help="Resume previous run, skip completed phases")
    parser.add_argument("--force", action="store_true", help="Force re-run of all phases (even if complete)")
    parser.add_argument("--crawl-only", action="store_true", help="Only run recon/crawl phases (no scanning)")
    parser.add_argument("--skip-subfinder", action="store_true", help="Skip subdomain enumeration")

    # Output
    parser.add_argument("-o", "--output", metavar="DIR", default="output", help="Output directory (default: output)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")

    args = parser.parse_args()

    # --- Dependency checks --------------------------------------------------
    check_python_dependencies()
    if not args.dry_run:
        missing = check_system_tools()
        if missing:
            _warn(
                "Some required tools are missing.  "
                "Results may be incomplete.  "
                "Run: bash install_tools.sh"
            )

    # --- Load targets -------------------------------------------------------
    targets = load_targets(args)
    if not targets:
        _err("No targets specified.  Pass a domain or use -l targets.txt")
        parser.print_help()
        return 1

    _info(f"Targets: {', '.join(targets)}")

    # --- Authorization reminder ---------------------------------------------
    if not args.dry_run:
        auth_id = args.auth_id or os.environ.get("AUTHORIZATION_ID", "")
        if not auth_id and not args.crawl_only:
            _warn(
                "No authorization ID provided.  "
                "Active scan phases will be skipped unless you supply --auth-id."
            )
            _warn(
                "Only scan targets you are explicitly authorized to test."
            )

    # --- Build config -------------------------------------------------------
    config = build_config(args, targets)

    if args.dry_run:
        _info("[dry-run] Configuration validated.  No network requests will be made.")

    # --- Run orchestrator ---------------------------------------------------
    from agents.orchestrator import Orchestrator

    orch = Orchestrator(config)

    try:
        final_state = orch.run()
    except KeyboardInterrupt:
        _warn("Interrupted by user.  Partial results saved.")
        return 130

    # --- Print summary ------------------------------------------------------
    _print_summary(final_state)

    return 0


def _print_summary(state) -> None:
    run_id = state.get("run_id", "?")
    targets = state.get("targets", {})
    out_dir = state.get("config", {}).get("output_dir", "output")

    print(f"\n{_BOLD}{'='*55}{_NC}")
    print(f"{_BOLD}  Run complete: {run_id}{_NC}")
    print(f"{_BOLD}{'='*55}{_NC}\n")

    total_findings = 0
    for target, ts in targets.items():
        findings = ts.get("deduped_findings") or ts.get("findings") or []
        status = ts.get("status", "?")
        icon = f"{_GREEN}✓{_NC}" if status == "done" else f"{_RED}✗{_NC}"
        print(f"  {icon}  {target}  —  {len(findings)} finding(s)  [{status}]")
        total_findings += len(findings)

    report_dir = Path(out_dir) / run_id
    print(f"\n  Total findings : {total_findings}")
    print(f"  Reports        : {report_dir}/")
    print(f"  Global summary : {report_dir}/global_summary.json\n")
    print(f"  {_YELLOW}⚠ Always manually verify findings before reporting.{_NC}\n")


if __name__ == "__main__":
    sys.exit(main())
