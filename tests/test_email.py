from pathlib import Path

from phishguard.email_analyzer import analyze_email

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def fake_scorer(url):
    bad = any(x in url for x in ("paypa1", ".xyz", "login"))
    return (0.95 if bad else 0.05), []


def test_phishing_email_flagged():
    r = analyze_email((SAMPLES / "phish.eml").read_bytes(), url_scorer=fake_scorer)
    assert r.verdict == "phishing"
    assert any("Reply-To" in f for f in r.header_flags)
    assert any("SPF" in f for f in r.header_flags)
    assert any("points to" in f for f in r.content_flags)  # deceptive anchor text
    assert any("attachment" in f.lower() or "extension" in f.lower() for f in r.content_flags)


def test_legit_email_safe():
    r = analyze_email((SAMPLES / "legit.eml").read_bytes(), url_scorer=fake_scorer)
    assert r.verdict == "likely safe", (r.score, r.header_flags, r.content_flags)


def _eml(from_header):
    return (f"From: {from_header}\nTo: you@example.com\nSubject: Hello\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nHi Sam, see you soon.").encode()


def test_lookalike_sender_domain_flagged():
    r = analyze_email(_eml("PayPal <service@paypa1.com>"), url_scorer=fake_scorer)
    assert any("imitates paypal" in f for f in r.header_flags)
    r = analyze_email(_eml("Security <alerts@paypal-security.com>"), url_scorer=fake_scorer)
    assert any("imitates paypal" in f for f in r.header_flags)


def test_display_name_brand_mismatch_flagged():
    r = analyze_email(_eml('"PayPal Support" <alerts@random-mailer.xyz>'), url_scorer=fake_scorer)
    assert any("claims to be paypal" in f for f in r.header_flags)
    r = analyze_email(_eml('"HDFC Bank" <noreply@secure-update.top>'), url_scorer=fake_scorer)
    assert any("claims to be hdfcbank" in f for f in r.header_flags)


def test_genuine_brand_senders_not_flagged():
    for sender in ['"PayPal" <service@paypal.com>', '"Microsoft 365" <no-reply@microsoft.com>',
                   '"Office 365" <alerts@outlook.com>', '"Instagram" <security@mail.instagram.com>',
                   '"Pineapple Deals" <hi@pineapple-deals.com>', '"Sam" <sam@example.com>']:
        r = analyze_email(_eml(sender), url_scorer=fake_scorer)
        assert not any("imitates" in f or "claims to be" in f for f in r.header_flags), (sender, r.header_flags)


# ---- attachments ----
from email.message import EmailMessage

from phishguard.email_analyzer import inspect_attachment


def _with_attachment(name, data, subtype="octet-stream"):
    m = EmailMessage()
    m["From"] = "Sam <sam@example.com>"
    m["To"] = "you@example.com"
    m["Subject"] = "Invoice"
    m.set_content("Please see attached.")
    m.add_attachment(data, maintype="application" if subtype == "octet-stream" else "text",
                     subtype=subtype, filename=name) if isinstance(data, bytes) and subtype == "octet-stream" \
        else m.add_attachment(data.decode(), subtype=subtype, filename=name)
    return m.as_bytes()


def test_rtlo_disguise():
    flags, score = inspect_attachment("invoice\u202efdp.exe", b"MZ")
    assert score >= 0.8 and "Hidden text-direction" in flags[0]


def test_double_extension_and_padding():
    assert inspect_attachment("scan.jpg.scr", b"")[1] >= 0.6
    assert inspect_attachment("report.pdf          .exe", b"")[1] >= 0.6


def test_html_login_form_attachment():
    html = b'<html><form action="https://evil.xyz/c"><input type="password" name="p"></form></html>'
    flags, score = inspect_attachment("Secure_Message.html", html)
    assert score >= 0.75 and any("login form" in f for f in flags)
    assert inspect_attachment("newsletter.html", b"<html><p>Hello</p></html>")[1] == 0.4


def test_benign_attachment_not_flagged():
    assert inspect_attachment("minutes.pdf", b"%PDF") == ([], 0.0)


def test_email_with_html_phishing_attachment_scores_high():
    raw = _with_attachment("Voicemail.html", b'<input type="password"><script>fetch("x")</script>', "html")
    r = analyze_email(raw, url_scorer=fake_scorer)
    assert r.components["attachments"] >= 0.75
    assert any("login form" in f for f in r.content_flags)
