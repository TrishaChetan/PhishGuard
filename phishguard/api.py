"""FastAPI service + web UI.

    uvicorn phishguard.api:app --reload      -> http://127.0.0.1:8000
"""
from __future__ import annotations

from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import allowlist as _allow
from .email_analyzer import analyze_email
from .model import DEFAULT_MODEL_PATH, HybridURLModel

app = FastAPI(title="PhishGuard", version="1.0.0",
              description="Hybrid ML phishing detection for URLs and emails")
TEMPLATE = Path(__file__).parent / "templates" / "index.html"


@lru_cache(maxsize=1)
def get_model() -> HybridURLModel:
    if not DEFAULT_MODEL_PATH.exists():
        raise HTTPException(503, "Model not trained yet. Run: python -m phishguard.train")
    return HybridURLModel.load()


class URLRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=4096, examples=["http://paypa1-secure.xyz/login"])


class BatchRequest(BaseModel):
    urls: list[str] = Field(..., max_length=500)


class EmailRequest(BaseModel):
    raw: str = Field(..., min_length=10, max_length=2_000_000, description="Full raw email incl. headers")


@lru_cache(maxsize=1)
def get_allowlist() -> frozenset:
    return frozenset(_allow.load_allowlist())


def _scorer(url: str):
    r = get_model().analyse(url, get_allowlist())
    return (0.0 if r["allowlisted"] else r["probability"]), r["reasons"]


@app.get("/", response_class=HTMLResponse)
def index():
    return TEMPLATE.read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    m = get_model()
    return {"status": "ok", "threshold": m.threshold, "fusion_weight_features": m.w_features}


@app.post("/api/url")
def check_url(req: URLRequest):
    return get_model().analyse(req.url, get_allowlist())


@app.post("/api/urls")
def check_urls(req: BatchRequest):
    m = get_model()
    probs = m.predict_proba(req.urls)
    allow = get_allowlist()
    out = []
    for u, p in zip(req.urls, probs):
        trusted = _allow.match(u, allow)
        out.append({"url": u, "probability": round(float(p), 4),
                    "phishing": bool(p >= m.threshold) and not trusted, "allowlisted": trusted})
    return out


@app.get("/api/allowlist")
def show_allowlist():
    """Domains currently trusted (from PHISHGUARD_ALLOWLIST / allowlist.txt)."""
    return sorted(get_allowlist())


@app.post("/api/email")
def check_email(req: EmailRequest):
    return asdict(analyze_email(req.raw, url_scorer=_scorer))


@app.post("/api/email/upload")
async def upload_email(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > 5_000_000:
        raise HTTPException(413, "File too large")
    return asdict(analyze_email(data, url_scorer=_scorer))


@app.get("/api/model")
def model_info():
    m = get_model()
    return {"top_features": m.top_features(15), "threshold": m.threshold, "fusion_weight_features": m.w_features}
