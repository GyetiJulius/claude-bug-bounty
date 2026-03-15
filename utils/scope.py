"""
Scope matching utility.

Wraps ``ScopePolicy`` with a cleaner interface for the pipeline agents so
they don't need to import ``models`` directly.
"""

from __future__ import annotations

from models.policy import ScopePolicy, PolicyViolation

__all__ = ["ScopeMatcher", "PolicyViolation"]


class ScopeMatcher:
    """
    Helper class for checking whether domains / URLs are in scope.

    Parameters
    ----------
    allowlist_suffixes:
        Domain suffixes considered in-scope (e.g. ``[".example.com"]``).
    exact_domains:
        Exact domains that are in-scope.
    """

    def __init__(
        self,
        allowlist_suffixes: list[str] | None = None,
        exact_domains: list[str] | None = None,
    ) -> None:
        self._policy = ScopePolicy(
            allowlist_suffixes=allowlist_suffixes or [],
            exact_domains=exact_domains or [],
            require_authorization=False,  # ScopeMatcher is scope-only
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, domain: str) -> bool:
        """Return *True* if *domain* is within scope."""
        return self._policy.is_in_scope(domain)

    def filter_domains(self, domains: list[str]) -> list[str]:
        """Return only domains that are in scope."""
        return [d for d in domains if self.is_in_scope(d)]

    def filter_urls(self, urls: list[str]) -> list[str]:
        """Return only URLs whose hostname is in scope."""
        return self._policy.filter_urls_in_scope(urls)

    def assert_in_scope(self, domain: str, phase: str = "") -> None:
        """Raise :class:`PolicyViolation` if *domain* is out of scope."""
        self._policy.assert_in_scope(domain, phase=phase)
