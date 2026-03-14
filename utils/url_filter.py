"""
URL filtering utility.

Filters raw URL lists to keep only interesting targets for scanning:
  - URLs with query parameters (for injection testing)
  - Unique URLs (deduplication)
  - In-scope domains only (delegated to ScopeMatcher)
  - Removes static asset extensions unlikely to carry vulnerabilities
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse, parse_qs

__all__ = ["URLFilter"]


# Extensions that are almost never directly exploitable
_STATIC_EXTENSIONS = frozenset(
    {
        "css", "js", "mjs", "jsx", "ts", "tsx",
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tiff",
        "woff", "woff2", "ttf", "eot", "otf",
        "mp4", "webm", "ogg", "mp3", "wav",
        "pdf", "zip", "tar", "gz", "rar", "7z",
        "map",          # source maps
    }
)


class URLFilter:
    """
    Stateless helper for filtering and categorizing URL lists.

    Parameters
    ----------
    scope_matcher:
        Optional ``ScopeMatcher`` instance.  When provided, URLs whose
        hostname is not in scope are excluded.
    """

    def __init__(self, scope_matcher=None) -> None:
        self._scope = scope_matcher

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter(self, urls: list[str]) -> list[str]:
        """
        Return a deduplicated list of non-static, in-scope URLs.

        Processing order:
        1. Normalize (strip whitespace, lowercase scheme+host).
        2. Remove static assets.
        3. Apply scope filter.
        4. Deduplicate.
        """
        seen: set[str] = set()
        result: list[str] = []

        for raw in urls:
            url = raw.strip()
            if not url:
                continue
            try:
                normalized = _normalize(url)
            except Exception:
                continue

            if _is_static(normalized):
                continue

            if self._scope and not self._scope.is_in_scope(_hostname(normalized)):
                continue

            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)

        return result

    def extract_param_urls(self, urls: list[str]) -> list[str]:
        """
        Return only URLs that contain at least one query parameter.

        These are the highest-value URLs for injection testing.
        """
        return [u for u in urls if _has_params(u)]

    def deduplicate(self, urls: list[str]) -> list[str]:
        """Return a list of unique, normalized URLs (order-preserving)."""
        seen: set[str] = set()
        result: list[str] = []
        for raw in urls:
            url = raw.strip()
            try:
                normalized = _normalize(url)
            except Exception:
                continue
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result

    def is_static(self, url: str) -> bool:
        """Return *True* if the URL points to a static asset."""
        return _is_static(url)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize(url: str) -> str:
    """Normalize a URL: lowercase scheme and host, strip trailing slash."""
    parsed = urlparse(url)
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
    )
    result = urlunparse(normalized)
    return result.rstrip("/") if result.endswith("/") and not parsed.path.endswith("//") else result


def _hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def _extension(url: str) -> str:
    """Return the file extension of the URL path (without the dot), lowercase."""
    path = urlparse(url).path
    if "." in path:
        ext = path.rsplit(".", 1)[-1]
        # Strip anything after a query char that might have snuck in
        return re.split(r"[?#]", ext)[0].lower()
    return ""


def _is_static(url: str) -> bool:
    return _extension(url) in _STATIC_EXTENSIONS


def _has_params(url: str) -> bool:
    qs = urlparse(url).query
    return bool(qs and parse_qs(qs))
