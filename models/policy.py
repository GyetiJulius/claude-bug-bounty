"""
Policy and scope enforcement models.

IMPORTANT — Defensive / authorized-use only:
  - Active scan phases require an explicit authorization_id.
  - Scope is enforced via allowlists; anything outside is rejected.
  - Guardrails limit concurrency and request rate to avoid inadvertent DoS.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PolicyViolation(Exception):
    """Raised when a requested operation violates policy."""

    reason: str
    target: str = ""
    phase: str = ""

    def __str__(self) -> str:
        parts = [self.reason]
        if self.target:
            parts.append(f"target={self.target!r}")
        if self.phase:
            parts.append(f"phase={self.phase!r}")
        return " | ".join(parts)


@dataclass
class ScopePolicy:
    """
    Scope and safety policy for a scan run.

    Parameters
    ----------
    allowlist_suffixes:
        Domain suffixes that are in-scope (e.g. ``[".example.com", "example.com"]``).
    exact_domains:
        Exact domains that are also in-scope regardless of suffix rules.
    require_authorization:
        When *True* (default), ``authorization_id`` must be non-empty before
        any active-scan phase can execute.
    authorization_id:
        Opaque string supplied by the operator to attest authorization.
    max_threads:
        Maximum concurrent threads / workers for scanning operations.
    max_rate:
        Maximum HTTP requests per second across all workers.
    dry_run:
        When *True*, tools are invoked in a read-only / no-traffic mode and
        no network requests are sent.
    approval_required_severities:
        Severities that require human approval before the finding is acted on.
    """

    allowlist_suffixes: list[str] = field(default_factory=list)
    exact_domains: list[str] = field(default_factory=list)
    require_authorization: bool = True
    authorization_id: str = ""
    max_threads: int = 10
    max_rate: int = 50          # req/s
    dry_run: bool = False
    approval_required_severities: list[str] = field(
        default_factory=lambda: ["critical"]
    )

    # ------------------------------------------------------------------
    # Scope enforcement
    # ------------------------------------------------------------------

    def is_in_scope(self, domain: str) -> bool:
        """Return *True* if *domain* is within the declared scope."""
        if not self.allowlist_suffixes and not self.exact_domains:
            # No scope declared — everything is rejected by default (safe default)
            return False

        domain = domain.lower().strip()

        if domain in (d.lower() for d in self.exact_domains):
            return True

        for suffix in self.allowlist_suffixes:
            suffix = suffix.lower()
            if not suffix.startswith("."):
                suffix = "." + suffix
            if domain == suffix.lstrip(".") or domain.endswith(suffix):
                return True

        return False

    def assert_in_scope(self, domain: str, phase: str = "") -> None:
        """Raise :class:`PolicyViolation` if *domain* is not in scope."""
        if not self.is_in_scope(domain):
            raise PolicyViolation(
                reason=(
                    f"Domain '{domain}' is not in the declared scope.  "
                    "Add it to --scope-allowlist or --scope-exact."
                ),
                target=domain,
                phase=phase,
            )

    # ------------------------------------------------------------------
    # Authorization enforcement
    # ------------------------------------------------------------------

    def assert_authorized(self, phase: str = "") -> None:
        """
        Raise :class:`PolicyViolation` if an authorization ID is required but
        not present.  Must be called before any active-scan phase.
        """
        if self.require_authorization and not self.authorization_id:
            raise PolicyViolation(
                reason=(
                    "Active scan phases require an authorization ID.  "
                    "Supply one with --auth-id or the AUTHORIZATION_ID env var."
                ),
                phase=phase,
            )

    # ------------------------------------------------------------------
    # Guardrails
    # ------------------------------------------------------------------

    def requires_approval(self, severity: str) -> bool:
        """Return *True* if a finding of *severity* needs human approval."""
        return severity.lower() in (s.lower() for s in self.approval_required_severities)

    # ------------------------------------------------------------------
    # URL / domain extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """Extract the hostname from a URL string."""
        pattern = re.compile(r"https?://([^/:?#\s]+)", re.IGNORECASE)
        match = pattern.search(url)
        return match.group(1).lower() if match else None

    def filter_urls_in_scope(self, urls: list[str]) -> list[str]:
        """Return only URLs whose hostname is in scope."""
        result = []
        for url in urls:
            host = self.extract_domain(url)
            if host and self.is_in_scope(host):
                result.append(url)
        return result
