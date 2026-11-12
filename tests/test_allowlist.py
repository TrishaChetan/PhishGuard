import pytest

from phishguard import allowlist as al


def test_parse_entries_normalises():
    got = al.parse_entries([
        "https://www.Example.com/path", "*.corp.example.org", "# comment", "",
        "intranet.acme.co.in  # internal", "not-a-domain",
    ])
    assert got == {"example.com", "example.org", "acme.co.in"}


@pytest.mark.parametrize("url, expected", [
    ("https://login.example.com/oauth?token=abc", "example.com"),
    ("example.com", "example.com"),
    ("hxxps://portal[.]example[.]com", "example.com"),
    ("https://example.com.evil.xyz/login", None),
    ("https://example-login.com", None),
    ("https://evil.xyz/?next=example.com", None),
    ("https://user@evil.xyz", None),
    ("http://93.184.216.34/", None),
])
def test_match_only_registered_domain(url, expected):
    assert al.match(url, {"example.com"}) == expected


def test_load_from_env_and_file(tmp_path, monkeypatch):
    f = tmp_path / "allow.txt"
    f.write_text("acme.com\n")
    monkeypatch.setenv("PHISHGUARD_ALLOWLIST", "example.com, other.org")
    assert al.load_allowlist(f) >= {"acme.com", "example.com", "other.org"}


def test_model_marks_allowlisted(trained_model=None):
    from phishguard.model import DEFAULT_MODEL_PATH, HybridURLModel
    if not DEFAULT_MODEL_PATH.exists():
        pytest.skip("model not trained")
    m = HybridURLModel.load()
    r = m.analyse("https://sso.example.com/a8f9e7d6c5b4a3/verify-account-login", {"example.com"})
    assert r["allowlisted"] == "example.com"
    assert r["verdict"] == "legitimate"
    assert r["reasons"][0].startswith("Domain example.com is on your allow-list")
    assert m.analyse("https://example.com.evil.xyz/login", {"example.com"})["allowlisted"] is None
