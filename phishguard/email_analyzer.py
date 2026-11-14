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

from .url_features import BRANDS, HOMOGLYPHS, levenshtein, registered_domain

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
# Unicode bidi controls let "invoice\u202efdp.exe" display as "invoiceexe.pdf"
BIDI_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]")
DECOY_EXT = r"(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif|mp3|mp4|wav)"
EXEC_EXT = r"(exe|scr|com|pif|js|jse|vbs|vbe|wsf|bat|cmd|ps1|hta|lnk|msi|jar|iso|img|html?|svg)"
HTML_FORM = re.compile(r"<form\b|type\s*=\s*[\"']?password|\.(?:submit|send)\s*\(|fetch\s*\(|XMLHttpRequest|"
                       r"atob\s*\(|window\.location\s*=|document\.write\s*\(\s*(?:unescape|atob)", re.I)


def inspect_attachment(filename: str, payload: bytes | None) -> tuple[list[str], float]:
    """Flags and a 0-1 risk score for one attachment."""
    flags: list[str] = []
    score = 0.0
    shown = BIDI_CHARS.sub("", filename)
    if BIDI_CHARS.search(filename):
        # what the user sees vs. what Windows runs
        flags.append(f"Hidden text-direction characters disguise the real file type: {shown!r}")
        score = max(score, 0.8)
    if re.search(r"\s{5,}\.\w+$", shown) or re.search(r"[_.\-]{8,}\.\w+$", shown):
        flags.append(f"Long padding pushes the real extension out of view: {shown.strip()}")
        score = max(score, 0.6)
    if re.search(rf"\.{DECOY_EXT}\s*\.{EXEC_EXT}$", shown, re.I):
        flags.append(f"Double extension trick: {shown}")
        score = max(score, 0.6)
    elif RISKY_ATTACHMENTS.search(shown):
        flags.append(f"Risky attachment type: {shown}")
        score = max(score, 0.4)
    if re.search(r"\.(html?|svg|xhtml)$", shown, re.I) and payload:
        text = payload[:500_000].decode("utf-8", "ignore")
        if HTML_FORM.search(text):
            flags.append(f"HTML attachment contains a login form or script that sends data: {shown}")
            score = max(score, 0.75)
    return flags, score


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


# Brands that legitimately send from a domain whose name differs from the brand
BRAND_SENDER_LABELS = {
    "office365": {"microsoft", "office", "office365", "outlook", "live", "hotmail"},
    "outlook": {"microsoft", "outlook", "live", "hotmail", "office"},
    "microsoft": {"microsoft", "office", "outlook", "live", "hotmail", "microsoftonline"},
    "facebook": {"facebook", "facebookmail", "meta"},
    "instagram": {"instagram", "facebookmail", "meta"},
    "whatsapp": {"whatsapp", "facebookmail", "meta"},
    "google": {"google", "gmail", "youtube"},
    "amazon": {"amazon", "amazonses", "aws"},
    "sbi": {"sbi", "onlinesbi", "sbicard"},
}


def brands_in_display_name(name: str) -> list[str]:
    """Brands named in a From display name ("PayPal Support", "HDFC Bank").

    Matches whole words and adjacent word pairs/triples, so "HDFC Bank" finds
    hdfcbank but "Pineapple Deals" does not find apple.
    """
    words = re.findall(r"[a-z0-9]+", name.lower())
    candidates = set(words)
    for n in (2, 3):
        candidates |= {"".join(words[i:i + n]) for i in range(len(words) - n + 1)}
    return [b for b in BRANDS if b in candidates]


def sender_lookalike(domain: str) -> str | None:
    """Brand a sender domain imitates, or None.

    Stricter than the URL feature: a brand merely appearing inside a longer
    word (pineapple-deals.com) is fine; homoglyphs (paypa1), 1-2 typos
    (micosoft) or brand-plus-hyphen (paypal-security) are not.
    """
    label = registered_domain(domain).split(".")[0]
    if not label or label in BRANDS:
        return None
    deglyphed = label.translate(HOMOGLYPHS)
    for b in BRANDS:
        if deglyphed == b:
            return b
        if len(b) >= 5 and levenshtein(label, b) <= (1 if len(b) < 8 else 2):
            return b
        if re.match(rf"^{b}-|-{b}$", label):
            return b
    return None


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
    # Lookalike sender domain, e.g. service@paypa1.com or alerts@micr0soft.com
    imitated = sender_lookalike(from_dom) if from_dom else None
    if imitated:
        header_flags.append(f"Sender domain {from_dom} imitates {imitated} (lookalike domain)"); h += 0.4
    # Brand in the display name but mail comes from an unrelated domain,
    # e.g. "PayPal Support" <alerts@random-mailer.xyz>
    if from_name and from_dom:
        label = registered_domain(from_dom).split(".")[0]
        for brand in brands_in_display_name(from_name):
            allowed = BRAND_SENDER_LABELS.get(brand, {brand})
            if label not in allowed and not any(a in label for a in allowed):
                header_flags.append(f"Display name claims to be {brand} but sender domain is {from_dom}"); h += 0.35
                break
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

    attachments = []
    a = 0.0
    for part in msg.iter_attachments():
        fn = part.get_filename()
        if not fn:
            continue
        attachments.append(fn)
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        flags, risk = inspect_attachment(fn, payload)
        content_flags.extend(flags)
        a = max(a, risk)

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
