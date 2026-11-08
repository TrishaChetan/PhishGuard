"""Phishing analysis for raw emails (.eml / RFC 5322 text).

Combines three signal families:
  1. Header forensics  — sender spoofing, SPF/DKIM/DMARC results, Reply-To tricks
  2. Content NLP       — urgency, credential requests, threats, generic greetings
  3. Embedded URLs     — every link is scored by the URL model; deceptive
                         anchor text (shows one domain, links to another) is flagged
The final score is a weighted fusion so each component stays explainable.
"""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

from .url_features import registered_domain

URGENCY = [
    "urgent", "immediately", "within 24 hours", "action required", "suspended",
    "final notice", "verify your account", "unusual activity", "locked",
    "expire", "limited time", "last warning", "act now", "deactivat",
]
CREDENTIAL = [
    "password", "login", "log in", "sign in", "credentials", "ssn", "otp",
    "pin", "card number", "cvv", "bank details", "confirm your identity",
]
REWARD = ["you have won", "lottery", "prize", "gift card", "refund", "claim your", "bonus"]
GENERIC_GREETING = re.compile(r"^\s*(dear (customer|user|client|member|account holder|sir/madam)|hello user)", re.I | re.M)
RISKY_ATTACHMENTS = re.compile(r"\.(exe|scr|js|vbs|bat|cmd|iso|img|lnk|hta|docm|xlsm|zip|rar|html?)$", re.I)
URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self.forms = 0
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        if tag == "form":
            self.forms += 1

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


@dataclass
class EmailReport:
    subject: str
    sender: str
    score: float
    verdict: str
    header_flags: list[str] = field(default_factory=list)
    content_flags: list[str] = field(default_factory=list)
    url_results: list[dict] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    components: dict[str, float] = field(default_factory=dict)


def _domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def _auth_results(msg) -> dict[str, str]:
    raw = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", raw, re.I)
        if m:
            out[mech] = m.group(1).lower()
    rs = msg.get("Received-SPF")
    if rs and "spf" not in out:
        out["spf"] = str(rs).split()[0].lower()
    return out


def _bodies(msg) -> tuple[str, str]:
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            payload = part.get_content()
        except Exception:
            payload = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/plain":
            text.append(payload)
        elif ctype == "text/html":
            html.append(payload)
    return "\n".join(text), "\n".join(html)


def analyze_email(raw: str | bytes, url_scorer=None) -> EmailReport:
    """url_scorer: callable(url)->(probability, reasons). Injected so the email
    analyser can be unit-tested without a trained model."""
    msg = email.message_from_bytes(raw, policy=policy.default) if isinstance(raw, bytes) \
        else email.message_from_string(raw, policy=policy.default)

    subject = str(msg.get("Subject", ""))
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    from_dom = _domain_of(from_addr)

    header_flags: list[str] = []
    h = 0.0
    if reply_addr and registered_domain(_domain_of(reply_addr)) != registered_domain(from_dom):
        header_flags.append(f"Reply-To ({reply_addr}) differs from sender domain"); h += 0.25
    if return_path and registered_domain(_domain_of(return_path)) != registered_domain(from_dom):
        header_flags.append(f"Return-Path domain ({_domain_of(return_path)}) differs from From"); h += 0.15
    if from_name and re.search(r"@|\b[a-z0-9-]+\.(com|net|org|in)\b", from_name, re.I):
        shown = re.search(r"[a-z0-9-]+\.(com|net|org|in)", from_name, re.I)
        if shown and registered_domain(shown.group(0).lower()) != registered_domain(from_dom):
            header_flags.append(f"Display name shows '{shown.group(0)}' but real sender is {from_dom}"); h += 0.3
    auth = _auth_results(msg)
    for mech, res in auth.items():
        if res in {"fail", "softfail", "none", "permerror"}:
            header_flags.append(f"{mech.upper()} check: {res}"); h += 0.2 if mech != "dmarc" else 0.3
    if not auth:
        header_flags.append("No SPF/DKIM/DMARC results present"); h += 0.05

    text, html = _bodies(msg)
    parser = _LinkParser()
    if html:
        parser.feed(html)
    plain_for_nlp = (text or re.sub(r"<[^>]+>", " ", html)).lower()
    full_lower = (subject + " " + plain_for_nlp).lower()

    content_flags: list[str] = []
    c = 0.0
    hits = [w for w in URGENCY if w in full_lower]
    if hits:
        content_flags.append("Urgency/threat language: " + ", ".join(hits[:4])); c += min(0.35, 0.12 * len(hits))
    hits = [w for w in CREDENTIAL if re.search(rf"\b{re.escape(w)}\b", full_lower)]
    if hits:
        content_flags.append("Asks for sensitive data: " + ", ".join(hits[:4])); c += min(0.35, 0.12 * len(hits))
    hits = [w for w in REWARD if w in full_lower]
    if hits:
        content_flags.append("Reward/bait language: " + ", ".join(hits[:3])); c += 0.15
    if GENERIC_GREETING.search(plain_for_nlp):
        content_flags.append("Generic greeting (not addressed by name)"); c += 0.1
    if parser.forms:
        content_flags.append("Email contains an HTML form"); c += 0.25

    # URLs
    urls = {href for href, _ in parser.links if href.lower().startswith("http")}
    urls |= set(URL_RE.findall(text))
    url_results, u = [], 0.0
    for href, anchor in parser.links:
        shown = URL_RE.search(anchor) or re.search(r"\b[a-z0-9-]+\.(com|net|org|in|co)\b", anchor, re.I)
        if shown and href.lower().startswith("http"):
            shown_dom = registered_domain(re.sub(r"^https?://", "", shown.group(0)).split("/")[0].lower())
            real_dom = registered_domain(re.sub(r"^https?://", "", href).split("/")[0].split(":")[0].lower())
            if shown_dom != real_dom:
                content_flags.append(f"Link text shows {shown_dom} but points to {real_dom}"); c += 0.3
    for url in sorted(urls)[:25]:
        if url_scorer:
            p, reasons = url_scorer(url)
            url_results.append({"url": url, "probability": round(p, 3), "reasons": reasons})
            u = max(u, p)

    attachments = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    a = 0.0
    for fn in attachments:
        if RISKY_ATTACHMENTS.search(fn):
            content_flags.append(f"Risky attachment type: {fn}"); a = 0.4
        if re.search(r"\.(pdf|docx?|xlsx?)\.(exe|js|scr|html?)$", fn, re.I):
            content_flags.append(f"Double extension trick: {fn}"); a = 0.6

    components = {
        "headers": round(min(1.0, h), 3),
        "content": round(min(1.0, c), 3),
        "urls": round(u, 3),
        "attachments": a,
    }
    # Weighted fusion; max() term ensures one very strong signal is never diluted.
    weighted = 0.25 * components["headers"] + 0.3 * components["content"] + 0.3 * components["urls"] + 0.15 * a
    score = round(min(1.0, max(weighted * 1.6, max(components.values()) * 0.85)), 3)
    verdict = "phishing" if score >= 0.6 else "suspicious" if score >= 0.35 else "likely safe"
    return EmailReport(subject, from_addr, score, verdict, header_flags, content_flags, url_results, attachments, components)
