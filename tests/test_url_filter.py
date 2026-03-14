"""
Tests for URL filtering utility (utils/url_filter.py).
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.url_filter import URLFilter


class TestURLFilterBasic:
    def setup_method(self):
        self.f = URLFilter()

    def test_removes_static_css(self):
        urls = ["https://example.com/style.css", "https://example.com/page?id=1"]
        result = self.f.filter(urls)
        assert "https://example.com/style.css" not in result
        assert "https://example.com/page?id=1" in result

    def test_removes_static_js(self):
        urls = ["https://example.com/app.js", "https://example.com/api/v1"]
        result = self.f.filter(urls)
        assert "https://example.com/app.js" not in result
        assert "https://example.com/api/v1" in result

    def test_removes_image_extensions(self):
        for ext in ["png", "jpg", "gif", "svg", "webp", "ico"]:
            url = f"https://example.com/image.{ext}"
            assert self.f.is_static(url), f".{ext} should be static"

    def test_removes_font_extensions(self):
        for ext in ["woff", "woff2", "ttf", "eot"]:
            url = f"https://example.com/font.{ext}"
            assert self.f.is_static(url)

    def test_removes_source_maps(self):
        assert self.f.is_static("https://example.com/bundle.js.map")

    def test_keeps_html_endpoint(self):
        assert not self.f.is_static("https://example.com/page.html")

    def test_keeps_php_endpoint(self):
        assert not self.f.is_static("https://example.com/index.php")

    def test_keeps_bare_path(self):
        assert not self.f.is_static("https://example.com/api/users")


class TestURLFilterDeduplication:
    def setup_method(self):
        self.f = URLFilter()

    def test_deduplicates_identical_urls(self):
        urls = [
            "https://example.com/page",
            "https://example.com/page",
            "https://example.com/page",
        ]
        result = self.f.filter(urls)
        assert result.count("https://example.com/page") == 1

    def test_deduplicates_case_normalised_scheme(self):
        urls = ["HTTPS://example.com/page", "https://example.com/page"]
        result = self.f.deduplicate(urls)
        assert len(result) == 1

    def test_deduplicates_case_normalised_host(self):
        urls = ["https://EXAMPLE.COM/page", "https://example.com/page"]
        result = self.f.deduplicate(urls)
        assert len(result) == 1

    def test_preserves_different_paths(self):
        urls = ["https://example.com/a", "https://example.com/b"]
        result = self.f.deduplicate(urls)
        assert len(result) == 2

    def test_empty_input(self):
        assert self.f.filter([]) == []


class TestURLFilterParamExtraction:
    def setup_method(self):
        self.f = URLFilter()

    def test_extracts_param_urls(self):
        urls = [
            "https://example.com/page?id=1",
            "https://example.com/page?name=test&val=2",
            "https://example.com/no-params",
            "https://example.com/path/only",
        ]
        params = self.f.extract_param_urls(urls)
        assert "https://example.com/page?id=1" in params
        assert "https://example.com/page?name=test&val=2" in params
        assert "https://example.com/no-params" not in params
        assert "https://example.com/path/only" not in params

    def test_empty_query_string_excluded(self):
        urls = ["https://example.com/page?", "https://example.com/page?id=1"]
        params = self.f.extract_param_urls(urls)
        assert "https://example.com/page?id=1" in params
        # page? with empty query — should not count
        assert "https://example.com/page?" not in params

    def test_empty_list(self):
        assert self.f.extract_param_urls([]) == []


class TestURLFilterWithScope:
    def test_scope_filters_out_of_scope_urls(self):
        from utils.scope import ScopeMatcher
        sm = ScopeMatcher(allowlist_suffixes=[".example.com"])
        f = URLFilter(scope_matcher=sm)

        urls = [
            "https://api.example.com/data",
            "https://evil.com/attack",
            "https://sub.example.com/endpoint",
        ]
        result = f.filter(urls)
        from urllib.parse import urlparse
        result_hosts = {urlparse(u).hostname for u in result}
        assert result_hosts == {"api.example.com", "sub.example.com"}
        assert "evil.com" not in result_hosts

    def test_no_scope_keeps_all_non_static(self):
        f = URLFilter()  # no scope matcher
        urls = [
            "https://api.example.com/data",
            "https://other.com/path",
            "https://third.io/endpoint",
        ]
        result = f.filter(urls)
        assert len(result) == 3


class TestURLFilterEdgeCases:
    def setup_method(self):
        self.f = URLFilter()

    def test_whitespace_stripped(self):
        urls = ["  https://example.com/page  ", "\thttps://example.com/api\n"]
        result = self.f.filter(urls)
        assert "https://example.com/page" in result
        assert "https://example.com/api" in result

    def test_empty_strings_ignored(self):
        urls = ["", "  ", "\n", "https://example.com/valid"]
        result = self.f.filter(urls)
        assert result == ["https://example.com/valid"]

    def test_invalid_urls_ignored(self):
        urls = ["not-a-url", "ftp://example.com/file", "https://example.com/valid"]
        result = self.f.filter(urls)
        # Only valid HTTP(S) URLs should survive
        assert "https://example.com/valid" in result
