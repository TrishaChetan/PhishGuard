# Project Report Outline — PhishGuard

Use this as the skeleton of the final-year report. Replace the bracketed parts with your own results.

## Abstract
Phishing remains the most common initial-access vector in cyber attacks. This project presents PhishGuard,
a hybrid system that detects phishing URLs and emails. URLs are classified by fusing a Random Forest trained on
28 engineered lexical and host features with a logistic-regression model on character n-grams. Emails are analysed
through header forensics (SPF, DKIM, DMARC, sender mismatches), content heuristics and per-link URL scoring.
On the [PhiUSIIL] dataset the hybrid model achieves [F1 = …, ROC-AUC = …] with an average latency of [… ms] per URL.

## 1. Introduction
- Problem statement and motivation (statistics from APWG / CERT-In reports)
- Objectives: real-time, offline, explainable detection; email + URL coverage
- Scope and assumptions

## 2. Literature survey
- Blacklist-based detection (Google Safe Browsing, PhishTank) — fast but cannot catch zero-day URLs
- Heuristic / feature-based ML (Random Forest, SVM on URL features)
- Deep learning on raw URLs (URLNet, character CNNs)
- Visual-similarity approaches (screenshot comparison)
- Gap addressed: explainable hybrid with email forensics in one tool

## 3. System design
- Architecture diagram (README)
- Module descriptions (docs/ARCHITECTURE.md)
- Feature table and threat mapping

## 4. Implementation
- Tech stack: Python, scikit-learn, FastAPI, HTML/JS
- Dataset preparation and splits (70/15/15 stratified)
- Hyper-parameters (RF: 300 trees, min_samples_leaf=2; TF-IDF char 2–5, 60k features; LR C=4)

## 5. Results
- Table from `reports/metrics.md` (5 models compared)
- Confusion matrix, ROC curve, feature importance figures
- Latency measurement
- Case studies: run `samples/phish.eml` and a few real URLs, show the red flags

## 6. Conclusion & future work
- WHOIS/domain-age and DNS features, visual similarity, transformer-based email text model, browser extension

## References
[List the datasets and papers you cite]
