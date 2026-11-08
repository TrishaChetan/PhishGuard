"""Dataset loading + a realistic synthetic generator.

For the final evaluation use a real public dataset, e.g.
  * PhiUSIIL Phishing URL Dataset (UCI, 235k URLs)   -> columns URL,label
  * Kaggle "Malicious URLs dataset" (malicious_phish.csv) -> url,type
`load_csv` auto-detects both formats.

The synthetic generator exists so the project runs end-to-end offline and so
tests are deterministic. It deliberately includes HARD cases (legit login
pages, phishing on compromised clean-looking domains) so the model cannot
score 100% by memorising trivial patterns.
"""
from __future__ import annotations

import random
import string

import pandas as pd

LEGIT_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.in", "flipkart.com",
    "stackoverflow.com", "microsoft.com", "apple.com", "paypal.com", "netflix.com",
    "linkedin.com", "nytimes.com", "bbc.co.uk", "hdfcbank.com", "irctc.co.in",
    "python.org", "mozilla.org", "medium.com", "reddit.com", "zomato.com",
    "swiggy.com", "nptel.ac.in", "coursera.org", "youtube.com", "dropbox.com",
    "adobe.com", "icicibank.com", "onlinesbi.sbi", "gov.in", "uidai.gov.in",
]
LEGIT_SUBS = ["", "", "", "www.", "docs.", "support.", "accounts.", "mail.", "blog.", "developer."]
LEGIT_PATHS = [
    "", "/", "/about", "/search?q={w}", "/wiki/{W}", "/questions/{n}/{w}-{w}",
    "/products/{w}/{n}", "/{w}/{w}", "/signin", "/login", "/account/settings",
    "/blog/{y}/{m}/{w}-{w}-{w}", "/docs/{w}/index.html", "/watch?v={id}",
    "/en-us/{w}/{w}", "/help/article/{n}", "/courses/{w}-{n}",
]
WORDS = ["python", "security", "network", "cloud", "pricing", "news", "india",
         "laptop", "phone", "guide", "release", "api", "data", "travel", "music",
         "learning", "photo", "student", "report", "health", "sports", "career"]
BRANDS = ["paypal", "apple", "microsoft", "office365", "amazon", "netflix", "hdfcbank",
          "icicibank", "sbi", "paytm", "google", "dropbox", "docusign", "linkedin", "chase"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "click", "icu", "cam", "support", "work", "com", "net", "info"]
CLEAN_LOOKING = ["greenvalleybakery.com", "rkconsultants.in", "mysite-portfolio.net",
                 "sunrisedental.org", "localgarage.co.uk", "bluewaterhotel.com", "techblog99.com"]


def _fill(tpl: str, rnd: random.Random) -> str:
    out = tpl
    while "{w}" in out:
        out = out.replace("{w}", rnd.choice(WORDS), 1)
    while "{W}" in out:
        out = out.replace("{W}", rnd.choice(WORDS).capitalize(), 1)
    while "{n}" in out:
        out = out.replace("{n}", str(rnd.randint(1, 99999)), 1)
    return (out.replace("{y}", str(rnd.randint(2015, 2026)))
               .replace("{m}", f"{rnd.randint(1, 12):02d}")
               .replace("{id}", "".join(rnd.choices(string.ascii_letters + string.digits + "_-", k=11))))


def _typo(brand: str, rnd: random.Random) -> str:
    ops = [
        lambda b: b.replace("o", "0", 1) if "o" in b else b + "s",
        lambda b: b.replace("l", "1", 1) if "l" in b else b[:-1],
        lambda b: b[:2] + b[1:],
        lambda b: b + "-" + rnd.choice(["secure", "login", "verify", "support", "help", "id"]),
        lambda b: rnd.choice(["secure-", "my", "login-", "update-"]) + b,
        lambda b: b.replace("a", "@" if rnd.random() < 0.2 else "4", 1) if "a" in b else b + "1",
    ]
    return rnd.choice(ops)(brand)


def legit_url(rnd: random.Random) -> str:
    scheme = "https://" if rnd.random() < 0.95 else "http://"
    return scheme + rnd.choice(LEGIT_SUBS) + rnd.choice(LEGIT_DOMAINS) + _fill(rnd.choice(LEGIT_PATHS), rnd)


def phishing_url(rnd: random.Random) -> str:
    brand = rnd.choice(BRANDS)
    kw = rnd.choice(["login", "verify", "account", "secure", "update", "signin", "billing", "unlock"])
    token = "".join(rnd.choices(string.ascii_lowercase + string.digits, k=rnd.randint(6, 24)))
    scheme = "https://" if rnd.random() < 0.55 else "http://"
    kind = rnd.random()
    if kind < 0.25:   # typosquat
        host = _typo(brand, rnd) + "." + rnd.choice(BAD_TLDS)
        path = f"/{kw}/{token}"
    elif kind < 0.45:  # brand in subdomain of attacker domain
        host = f"{brand}.com.{kw}-{rnd.choice(['center','portal','service'])}.{rnd.choice(BAD_TLDS)}"
        path = f"/{token}/{kw}.php"
    elif kind < 0.55:  # raw IP
        host = ".".join(str(rnd.randint(1, 254)) for _ in range(4))
        if rnd.random() < 0.3:
            host += f":{rnd.choice([8080, 8443, 2096])}"
        path = f"/{brand}/{kw}.html"
    elif kind < 0.7:   # compromised legit-looking site (hard case)
        host = rnd.choice(CLEAN_LOOKING)
        path = f"/wp-content/{rnd.choice(['uploads','plugins','themes'])}/{token}/{brand}/{kw}.php"
    elif kind < 0.8:   # @ trick / redirect
        host = f"{brand}.com@{rnd.randint(1,254)}.{rnd.randint(1,254)}.{rnd.randint(1,254)}.{rnd.randint(1,254)}"
        path = f"/{kw}"
    elif kind < 0.9:   # random DGA-like host
        host = "".join(rnd.choices(string.ascii_lowercase + string.digits, k=rnd.randint(12, 22))) + "." + rnd.choice(BAD_TLDS)
        path = f"/{kw}?id={token}&session={rnd.randint(10**6, 10**9)}"
    else:              # punycode / homograph
        host = "xn--" + "".join(rnd.choices(string.ascii_lowercase + string.digits, k=rnd.randint(5, 10))) + "-" + brand[:3] + ".com"
        path = f"/{kw}"
    return scheme + host + path


def generate(n: int = 6000, phishing_ratio: float = 0.45, seed: int = 42) -> pd.DataFrame:
    rnd = random.Random(seed)
    rows = []
    for _ in range(n):
        is_phish = rnd.random() < phishing_ratio
        rows.append({"url": phishing_url(rnd) if is_phish else legit_url(rnd), "label": int(is_phish)})
    # label noise (~1.5%) to mimic imperfect real-world labelling
    for r in rnd.sample(rows, k=int(0.015 * n)):
        r["label"] = 1 - r["label"]
    return pd.DataFrame(rows).drop_duplicates("url").reset_index(drop=True)


def load_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    cols = {c.lower(): c for c in df.columns}
    url_col = cols.get("url")
    if url_col is None:
        raise ValueError("CSV needs a 'url' column")
    if "label" in cols:
        y = df[cols["label"]]
        # PhiUSIIL uses 1 = legitimate, 0 = phishing; allow override via env or flag in train.py
        y = y.astype(int)
    elif "type" in cols:  # Kaggle malicious_phish: benign/phishing/defacement/malware
        y = (df[cols["type"]].str.lower() != "benign").astype(int)
    else:
        raise ValueError("CSV needs a 'label' or 'type' column")
    return pd.DataFrame({"url": df[url_col].astype(str), "label": y}).dropna()
