from phishguard.url_features import brand_typosquat, extract, levenshtein, registered_domain, shannon_entropy


def test_registered_domain():
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("www.bbc.co.uk") == "bbc.co.uk"


def test_levenshtein():
    assert levenshtein("paypal", "paypa1") == 1
    assert levenshtein("same", "same") == 0


def test_entropy_bounds():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2


def test_ip_and_at_detection():
    f = extract("http://paypal.com@192.168.10.5/login")
    assert f["has_at"] == 1
    f = extract("http://192.168.10.5/login")
    assert f["is_ip_host"] == 1


def test_typosquat():
    assert brand_typosquat("paypa1.com") == 1
    assert brand_typosquat("paypal-secure.xyz") == 1
    assert brand_typosquat("paypal.com") == 0
    assert brand_typosquat("github.com") == 0


def test_brand_in_subdomain():
    f = extract("http://paypal.com.verify-center.top/x/login.php")
    assert f["brand_in_subdomain_or_path"] == 1
    assert f["suspicious_tld"] == 1
    assert extract("https://www.paypal.com/signin")["brand_in_subdomain_or_path"] == 0


def test_scheme_less_url():
    f = extract("example.com/path")
    assert f["host_length"] == len("example.com")
