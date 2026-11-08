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
