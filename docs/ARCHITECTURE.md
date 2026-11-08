# PhishGuard — Architecture & Design Rationale

## 1. Threat model

| Attack technique | MITRE ATT&CK | How PhishGuard detects it |
|---|---|---|
| Spearphishing link | T1566.002 | URL model, deceptive anchor text, link scoring |
| Spearphishing attachment | T1566.001 | Risky extension list, double-extension check |
| Domain typosquatting / homographs | T1583.001 | Levenshtein + homoglyph map, punycode flag |
| Sender spoofing | T1656 / T1566 | SPF/DKIM/DMARC results, Reply-To & Return-Path mismatch, display-name spoof |
| URL obfuscation | T1027 | `@` trick, IP hosts, hex encoding, shorteners, long URLs |

## 2. URL feature set (28 features)

| Group | Features | Why |
|---|---|---|
| Length/structure | url/host/path/query length, dots, path segments, longest token | Phishing URLs pad length to hide the real domain |
| Host | IP host, port, subdomain depth, hyphens, entropy, punycode, suspicious TLD | Attackers use cheap TLDs, nested subdomains, random (DGA-like) names |
| Obfuscation | `@`, `//` redirect, hex encoding, special chars, digit ratio | Browser parsing tricks |
| Semantics | sensitive words, brand in subdomain/path, typosquat | Social-engineering lures |
| Payload | executable/script extension, shortener | Malware delivery |

## 3. Model design

Two complementary branches:

* **Random Forest on engineered features** — robust to new brands, explainable through feature importance.
* **Logistic Regression on character 2–5-grams** — learns token patterns (e.g. `wp-content/…/login.php`) without hand-written rules.

Their probabilities are fused as `p = w·p_RF + (1−w)·p_LR`. Both `w` and the decision threshold are grid-searched on a held-out validation split (70/15/15 split, stratified) to maximise F1, so the test set is never touched during tuning.

## 4. Email score fusion

```
weighted = 0.25·headers + 0.30·content + 0.30·urls + 0.15·attachments
score    = min(1, max(1.6·weighted, 0.85·max(component)))
```

The `max` term guarantees that a single decisive signal (e.g. a 99% phishing link) is never diluted by clean headers.
Verdict bands: ≥0.60 phishing, ≥0.35 suspicious, otherwise likely safe.

## 5. Security of the service itself

* Input size limits on every endpoint (URL ≤ 4 KB, email ≤ 2 MB, upload ≤ 5 MB, batch ≤ 500).
* No network fetches of submitted URLs — analysis is purely static, so the server can't be used for SSRF.
* UI escapes all output (XSS-safe rendering of attacker-controlled email content).
* Docker image runs as a non-root user.
