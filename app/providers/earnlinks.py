"""Safe adapter for authorized earnlinks.in URLs.

The adapter only reads an explicit HTML meta-refresh target. It does not
execute JavaScript, click buttons, solve challenges, skip timers, or scrape
arbitrary links from a page.
"""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

SUPPORTED_HOSTS = {"earnlinks.in", "www.earnlinks.in"}
_REFRESH_RE = re.compile(r"^\s*\d+\s*;\s*url\s*=\s*[\"']?([^\"']+?)\s*[\"']?\s*$", re.IGNORECASE)


def is_earnlinks_url(url: str) -> bool:
    """Return True only for the exact supported earnlinks.in hostnames."""
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower().rstrip(".") in SUPPORTED_HOSTS


def extract_earnlinks_html_redirect(html: str, base_url: str) -> str | None:
    """Extract an explicit meta-refresh target, or None if unsupported.

    Arbitrary anchors, scripts, forms, countdowns, and access-control markup
    are deliberately ignored.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("meta"):
        http_equiv = str(tag.get("http-equiv", "")).strip().lower()
        if http_equiv != "refresh":
            continue
        content = str(tag.get("content", ""))
        match = _REFRESH_RE.match(content)
        if match:
            return urljoin(base_url, unescape(match.group(1).strip()))
    return None
