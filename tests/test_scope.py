"""
Tests for scope matching logic (utils/scope.py and models/policy.py).
"""

import pytest
import sys
import os

# Ensure repo root on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.scope import ScopeMatcher
from models.policy import ScopePolicy, PolicyViolation


# ---------------------------------------------------------------------------
# ScopeMatcher tests
# ---------------------------------------------------------------------------

class TestScopeMatcherSuffixes:
    def test_exact_suffix_match(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        assert sm.is_in_scope("api.example.com")
        assert sm.is_in_scope("sub.api.example.com")

    def test_root_domain_match(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        assert sm.is_in_scope("example.com")

    def test_suffix_without_leading_dot(self):
        """Suffix provided without leading dot should still work."""
        sm = ScopeMatcher(allowlist_suffixes=["example.com"])
        assert sm.is_in_scope("api.example.com")
        assert sm.is_in_scope("example.com")

    def test_out_of_scope_domain(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        assert not sm.is_in_scope("evil.com")
        assert not sm.is_in_scope("notexample.com")

    def test_partial_suffix_not_matched(self):
        """Should NOT match domains that only partially contain the suffix."""
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        assert not sm.is_in_scope("xample.com")
        assert not sm.is_in_scope("fakeexample.com")


class TestScopeMatcherExactDomains:
    def test_exact_match(self):
        sm = ScopeMatcher(exact_domains=["special.io"])
        assert sm.is_in_scope("special.io")

    def test_subdomain_not_matched_by_exact(self):
        sm = ScopeMatcher(exact_domains=["special.io"])
        assert not sm.is_in_scope("api.special.io")

    def test_case_insensitive(self):
        sm = ScopeMatcher(exact_domains=["Example.COM"])
        assert sm.is_in_scope("example.com")


class TestScopeMatcherEmpty:
    def test_empty_scope_rejects_everything(self):
        """With no scope declared, everything should be out of scope."""
        sm = ScopeMatcher()
        assert not sm.is_in_scope("example.com")


class TestScopeMatcherFilterDomains:
    def test_filter_list(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        domains = ["api.example.com", "evil.com", "sub.example.com", "other.org"]
        filtered = sm.filter_domains(domains)
        assert filtered == ["api.example.com", "sub.example.com"]

    def test_filter_empty_list(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        assert sm.filter_domains([]) == []


class TestScopeMatcherFilterURLs:
    def test_filter_urls_in_scope(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        urls = [
            "https://api.example.com/path?id=1",
            "https://evil.com/steal",
            "https://sub.example.com/login",
        ]
        filtered = sm.filter_urls(urls)
        assert "https://api.example.com/path?id=1" in filtered
        assert "https://sub.example.com/login" in filtered
        assert "https://evil.com/steal" not in filtered


class TestScopeMatcherAssertInScope:
    def test_raises_for_out_of_scope(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        with pytest.raises(PolicyViolation) as exc_info:
            sm.assert_in_scope("evil.com", phase="recon")
        # The error message should reference the rejected domain
        assert exc_info.value.target == "evil.com"

    def test_no_raise_for_in_scope(self):
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        sm.assert_in_scope("api.example.com")  # Should not raise


# ---------------------------------------------------------------------------
# ScopePolicy authorization tests
# ---------------------------------------------------------------------------

class TestScopePolicyAuthorization:
    def test_assert_authorized_raises_when_missing(self):
        policy = ScopePolicy(require_authorization=True, authorization_id="")
        with pytest.raises(PolicyViolation) as exc_info:
            policy.assert_authorized(phase="scan")
        assert "authorization" in str(exc_info.value).lower()

    def test_assert_authorized_passes_with_id(self):
        policy = ScopePolicy(require_authorization=True, authorization_id="AUTH-001")
        policy.assert_authorized(phase="scan")  # Should not raise

    def test_authorization_not_required_when_disabled(self):
        policy = ScopePolicy(require_authorization=False, authorization_id="")
        policy.assert_authorized(phase="scan")  # Should not raise


class TestScopePolicyGuardrails:
    def test_approval_required_for_critical(self):
        policy = ScopePolicy(approval_required_severities=["critical"])
        assert policy.requires_approval("critical")
        assert policy.requires_approval("CRITICAL")

    def test_approval_not_required_for_high(self):
        policy = ScopePolicy(approval_required_severities=["critical"])
        assert not policy.requires_approval("high")

    def test_custom_approval_severities(self):
        policy = ScopePolicy(approval_required_severities=["critical", "high"])
        assert policy.requires_approval("high")
        assert not policy.requires_approval("medium")


class TestScopePolicyURLFilter:
    def test_filter_urls_in_scope(self):
        policy = ScopePolicy(
            allowlist_suffixes=[".example.com"],
            require_authorization=False,
        )
        urls = [
            "https://api.example.com/data?id=1",
            "https://attacker.com/evil",
        ]
        filtered = policy.filter_urls_in_scope(urls)
        assert len(filtered) == 1
        assert filtered[0] == "https://api.example.com/data?id=1"

    def test_extract_domain(self):
        assert ScopePolicy.extract_domain("https://example.com/path") == "example.com"
        assert ScopePolicy.extract_domain("http://sub.example.com:8080/p") == "sub.example.com"
        assert ScopePolicy.extract_domain("not-a-url") is None
