"""End-to-end: train a small model, then exercise the REST API."""
import pytest
from fastapi.testclient import TestClient

from phishguard import api, dataset, model as model_mod


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    df = dataset.generate(2500, seed=3)
    m = model_mod.HybridURLModel().fit(df.url, df.label)
    original = api.get_model
    api.get_model = lambda: m  # type: ignore[assignment]
    yield TestClient(api.app)
    api.get_model = original


def test_model_separates_obvious_cases(client):
    bad = client.post("/api/url", json={"url": "http://paypa1-secure.xyz/login/verify"}).json()
    good = client.post("/api/url", json={"url": "https://github.com/explore"}).json()
    assert bad["probability"] > 0.7 > good["probability"]
    assert bad["reasons"]


def test_batch(client):
    r = client.post("/api/urls", json={"urls": ["https://python.org/", "http://192.168.1.4/paypal/login.html"]}).json()
    assert r[0]["phishing"] is False and r[1]["phishing"] is True


def test_email_endpoint(client):
    raw = open("samples/phish.eml").read()
    r = client.post("/api/email", json={"raw": raw}).json()
    assert r["verdict"] == "phishing"
    assert r["url_results"]


def test_ui(client):
    assert "PhishGuard" in client.get("/").text
