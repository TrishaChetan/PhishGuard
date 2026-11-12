"""Trusted-domain allow-list.

Every organisation has domains it fully trusts (its own site, SSO provider,
intranet) whose long tokenised URLs can look "phishy" to a model. Listing them
here stops those false positives.

Matching is on the *registered domain* only, so allow-listing ``example.com``
trusts ``login.example.com`` but NOT ``example.com.evil.xyz`` or
``example-login.com``.

Sources (merged):
  * ``PHISHGUARD_ALLOWLIST``       — comma-separated domains
  * ``PHISHGUARD_ALLOWLIST_FILE``  — path to a file, one domain per line (# comments)
  * ``allowlist.txt`` in the project root, if it exists
  * an explicit path passed to :func:`load_allowlist` (CLI ``--allowlist``)
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from .url_features import _is_ip, _normalise, registered_domain

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "allowlist.txt"


def _clean(entry: str) -> str | None:
    entry = entry.split("#", 1)[0].strip().lower()
    if not entry:
        return None
    entry = re.sub(r"^[a-z][a-z0-9+.-]*://", "", entry).split("/")[0].split(":")[0]
    entry = entry.lstrip("*.").removeprefix("www.")
    return registered_domain(entry) if "." in entry else None


def parse_entries(lines) -> set[str]:
    return {d for d in (_clean(l) for l in lines) if d}


def load_allowlist(path: str | Path | None = None) -> set[str]:
    domains: set[str] = set()
    env = os.getenv("PHISHGUARD_ALLOWLIST")
    if env:
        domains |= parse_entries(env.split(","))
    files = [os.getenv("PHISHGUARD_ALLOWLIST_FILE"), path]
    if DEFAULT_FILE.exists():
        files.append(DEFAULT_FILE)
    for f in files:
        if f and Path(f).exists():
            domains |= parse_entries(Path(f).read_text(encoding="utf-8").splitlines())
    return domains


def match(url: str, allowlist: set[str]) -> str | None:
    """Return the allow-listed registered domain the URL belongs to, or None."""
    if not allowlist:
        return None
    host = _normalise(url).host
    if not host or _is_ip(host):
        return None
    dom = registered_domain(host)
    return dom if dom in allowlist else None
