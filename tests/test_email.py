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
