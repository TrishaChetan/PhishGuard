import pytest

from phishguard.url_features import defang, extract, is_defanged, refang


@pytest.mark.parametrize("defanged, expected", [
    ("hxxps://paypa1[.]com/login", "https://paypa1.com/login"),
    ("hxxp://evil(.)example[.]xyz/a", "http://evil.example.xyz/a"),
    ("HXXPS[:]//bank{dot}secure-login[.]top", "https://bank.secure-login.top"),
    ("paypal[.]com[/]signin", "paypal.com/signin"),
    ("user[@]host[.]com", "user@host.com"),
    ("https://normal.example.com/x", "https://normal.example.com/x"),
])
def test_refang(defanged, expected):
    assert refang(defanged) == expected


def test_is_defanged():
    assert is_defanged("hxxp://a[.]b")
    assert not is_defanged("http://a.b")


def test_defang_round_trip():
    url = "https://login.paypa1.com/verify?next=a.b"
    d = defang(url)
    assert d == "hxxps://login[.]paypa1[.]com/verify?next=a.b"
    assert refang(d) == url


def test_features_identical_for_defanged_input():
    assert extract("hxxps://paypa1[.]com/login") == extract("https://paypa1.com/login")
