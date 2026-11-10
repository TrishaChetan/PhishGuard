"""Lexical and host-based feature extraction for URLs.

Every feature here is computed from the URL string alone (no network calls),
so the detector works offline and in real time. Each feature is grounded in a
known phishing technique; see docs/ARCHITECTURE.md for the mapping.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "country", "kim", "loan", "men", "review", "rest", "support", "cam", "icu",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy",
}
SENSITIVE_WORDS = (
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "wallet", "webscr", "suspend", "unlock", "billing",
    "invoice", "recover", "authenticate", "validation",
)
BRANDS = (
    "paypal", "apple", "microsoft", "office365", "outlook", "google", "amazon",
    "netflix", "facebook", "instagram", "linkedin", "dropbox", "docusign",
    "chase", "wellsfargo", "bankofamerica", "hdfcbank", "icicibank", "sbi",
    "paytm", "phonepe", "flipkart", "github", "adobe", "whatsapp",
)
# Characters commonly swapped in typosquats (leet / homoglyph style)
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "7": "t"})

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots",
    "num_hyphens_host", "num_subdomains", "num_digits", "digit_ratio",
    "num_special", "has_at", "has_double_slash_redirect", "is_ip_host",
    "has_port", "is_https", "suspicious_tld", "is_shortener", "num_params",
    "sensitive_word_count", "brand_in_subdomain_or_path", "brand_typosquat",
    "host_entropy", "url_entropy", "has_punycode", "longest_token",
    "has_hex_encoding", "num_path_segments", "has_file_extension_exec",
]


# Threat-intel feeds, tickets and chat usually share malicious URLs "defanged"
# so nobody clicks them by accident: hxxps://paypa1[.]com/login
_REFANG_RULES = [
    (re.compile(r"^\s*h(?:xx|XX|\*\*)p(s?)(?:\[:\]|:)//", re.I), lambda m: f"http{m.group(1).lower()}://"),
    (re.compile(r"^\s*fxp(?:\[:\]|:)//", re.I), "ftp://"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*(?:@|at)\s*\]", re.I), "@"),
    (re.compile(r"\[/\]"), "/"),
]


def refang(url: str) -> str:
    """Turn a defanged indicator back into a parseable URL.

    >>> refang("hxxps://paypa1[.]com/login")
    'https://paypa1.com/login'
    """
    out = url.strip()
    for pattern, repl in _REFANG_RULES:
        out = pattern.sub(repl, out)
    return out


def is_defanged(url: str) -> bool:
    return refang(url) != url.strip()


def defang(url: str) -> str:
    """Make a URL safe to paste into reports/chat (not clickable).

    >>> defang("https://paypa1.com/login")
    'hxxps://paypa1[.]com/login'
    """
    url = refang(url)
    url = re.sub(r"^http", "hxxp", url, flags=re.I)
    scheme, sep, rest = url.partition("://")
    if not sep:
        scheme, rest = "", url
    host, slash, tail = rest.partition("/")
    host = host.replace(".", "[.]")
    return f"{scheme}{sep}{host}{slash}{tail}"


@dataclass
class ParsedURL:
    raw: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str


def _normalise(url: str) -> ParsedURL:
    url = refang(url)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    return ParsedURL(url, p.scheme.lower(), host, port, p.path or "", p.query or "")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host: str) -> str:
    """Approximate eTLD+1 (good enough without the public-suffix list)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # decimal / hex encoded IPs, e.g. http://3232235777/
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def brand_typosquat(host: str) -> int:
    """1 if the registered domain label is 1-2 edits away from a known brand
    (or equal after homoglyph substitution) but is not the brand itself."""
    label = registered_domain(host).split(".")[0]
    if not label or label in BRANDS:
        return 0
    deglyphed = label.translate(HOMOGLYPHS)
    for b in BRANDS:
        if deglyphed == b:
            return 1
        if len(b) >= 5 and levenshtein(label, b) <= (1 if len(b) < 8 else 2):
            return 1
        if b in label and label != b and len(label) <= len(b) + 12:
            return 1  # e.g. paypal-secure, appleid-support
    return 0


def extract(url: str) -> dict[str, float]:
    u = _normalise(url)
    host, path, query, raw = u.host, u.path, u.query, u.raw
    reg = registered_domain(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    lower = raw.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    digits = sum(ch.isdigit() for ch in raw)
    tokens = re.split(r"[/.?=&_\-:]+", lower)
    brand_elsewhere = int(
        any(b in sub or b in path.lower() for b in BRANDS) and not any(reg.startswith(b + ".") for b in BRANDS)
    )
    return {
        "url_length": len(raw),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_hyphens_host": host.count("-"),
        "num_subdomains": max(0, host.count(".") - reg.count(".")),
        "num_digits": digits,
        "digit_ratio": digits / max(1, len(raw)),
        "num_special": len(re.findall(r"[~!#$%^*()+=\[\]{}|;,<>]", raw)),
        "has_at": int("@" in raw.split("://", 1)[-1]),
        "has_double_slash_redirect": int("//" in raw.split("://", 1)[-1]),
        "is_ip_host": int(_is_ip(host)),
        "has_port": int(u.port is not None and u.port not in (80, 443)),
        "is_https": int(u.scheme == "https"),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(reg in SHORTENERS or host in SHORTENERS),
        "num_params": len(parse_qs(query)),
        "sensitive_word_count": sum(lower.count(w) for w in SENSITIVE_WORDS),
        "brand_in_subdomain_or_path": brand_elsewhere,
        "brand_typosquat": brand_typosquat(host),
        "host_entropy": shannon_entropy(host),
        "url_entropy": shannon_entropy(raw),
        "has_punycode": int("xn--" in host),
        "longest_token": max((len(t) for t in tokens), default=0),
        "has_hex_encoding": int(bool(re.search(r"%[0-9a-fA-F]{2}", raw))),
        "num_path_segments": len([s for s in path.split("/") if s]),
        "has_file_extension_exec": int(bool(re.search(r"\.(exe|scr|js|vbs|bat|apk|msi|php)(\?|$)", path.lower()))),
    }


def explain(features: dict[str, float]) -> list[str]:
    """Human-readable red flags, used in the UI and the email analyser."""
    f = features
    reasons = []
    if f["is_ip_host"]:
        reasons.append("Host is a raw IP address instead of a domain name")
    if f["has_at"]:
        reasons.append("'@' in URL — browser ignores everything before it")
    if f["brand_typosquat"]:
        reasons.append("Domain imitates a well-known brand (typosquatting)")
    if f["brand_in_subdomain_or_path"]:
        reasons.append("Brand name appears in subdomain/path but not in the real domain")
    if f["has_punycode"]:
        reasons.append("Punycode (xn--) domain — possible homograph attack")
    if f["suspicious_tld"]:
        reasons.append("Top-level domain frequently abused for phishing")
    if f["is_shortener"]:
        reasons.append("URL shortener hides the real destination")
    if f["sensitive_word_count"] >= 2:
        reasons.append("Multiple credential-related words (login, verify, account…)")
    if f["num_subdomains"] >= 3:
        reasons.append("Unusually deep subdomain nesting")
    if f["has_double_slash_redirect"]:
        reasons.append("Embedded '//' suggests an open redirect")
    if f["has_port"]:
        reasons.append("Non-standard port")
    if f["url_length"] > 100:
        reasons.append("Very long URL (used to hide the real domain)")
    if f["has_file_extension_exec"]:
        reasons.append("Links directly to an executable/script file")
    if not f["is_https"]:
        reasons.append("Not using HTTPS")
    return reasons
