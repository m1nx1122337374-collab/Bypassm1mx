"""Generic, conservative HTML redirect parsing helpers."""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin

from bs4 import BeautifulSoup

_REFRESH_RE = re.compile(r"^\s*\d+\s*;\s*url\s*=\s*[\"']?([^\"']+?)\s*[\"']?\s*$", re.IGNORECASE)


def extract_standard_html_redirect(html: str, base_url: str) -> str | None:
    """Return an explicit meta-refresh target, or None.

    This does not execute JavaScript or scrape arbitrary links. It only handles
    the standard HTML meta-refresh redirect form.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("meta"):
        if str(tag.get("http-equiv", "")).strip().lower() != "refresh":
            continue
        match = _REFRESH_RE.match(str(tag.get("content", "")))
        if match:
            return urljoin(base_url, unescape(match.group(1).strip()))
    return None
