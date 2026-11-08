"""Hybrid URL classifier.

Branch A: 28 engineered lexical/host features -> Random Forest
Branch B: character 2-5-gram TF-IDF of the URL -> Logistic Regression
Fusion  : weighted average of both probabilities (weights tuned on validation)

Engineered features generalise to unseen brands/patterns and are explainable;
character n-grams catch token-level patterns the features miss. The fusion is
more robust than either branch alone (see reports/metrics.json).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .url_features import FEATURE_NAMES, explain, extract

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishguard.joblib"


def featurize(urls) -> pd.DataFrame:
    return pd.DataFrame([extract(u) for u in urls], columns=FEATURE_NAMES)


@dataclass
class HybridURLModel:
    w_features: float = 0.5
    threshold: float = 0.5
    rf: RandomForestClassifier = field(default_factory=lambda: RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=7))
    text: Pipeline = field(default_factory=lambda: Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=2, max_features=60000, sublinear_tf=True)),
        ("lr", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ]))

    def fit(self, urls, y):
        self.rf.fit(featurize(urls), y)
        self.text.fit(list(urls), y)
        return self

    def branch_proba(self, urls) -> tuple[np.ndarray, np.ndarray]:
        urls = list(urls)
        return self.rf.predict_proba(featurize(urls))[:, 1], self.text.predict_proba(urls)[:, 1]

    def predict_proba(self, urls) -> np.ndarray:
        a, b = self.branch_proba(urls)
        return self.w_features * a + (1 - self.w_features) * b

    def predict(self, urls) -> np.ndarray:
        return (self.predict_proba(urls) >= self.threshold).astype(int)

    def tune(self, urls, y):
        """Grid-search fusion weight and decision threshold on a validation set (maximise F1)."""
        from sklearn.metrics import f1_score
        a, b = self.branch_proba(urls)
        best = (-1, 0.5, 0.5)
        for w in np.linspace(0, 1, 11):
            p = w * a + (1 - w) * b
            for t in np.linspace(0.3, 0.7, 9):
                # tiny penalty breaks ties toward a balanced fusion and a 0.5 threshold
                f = f1_score(y, (p >= t).astype(int)) - 1e-4 * (abs(w - 0.5) + abs(t - 0.5))
                if f > best[0]:
                    best = (f, w, t)
        _, self.w_features, self.threshold = best
        return self

    def top_features(self, k: int = 10) -> list[tuple[str, float]]:
        imp = sorted(zip(FEATURE_NAMES, self.rf.feature_importances_), key=lambda x: -x[1])
        return [(n, round(float(v), 4)) for n, v in imp[:k]]

    def analyse(self, url: str) -> dict:
        a, b = self.branch_proba([url])
        p = float(self.w_features * a[0] + (1 - self.w_features) * b[0])
        feats = extract(url)
        return {
            "url": url,
            "probability": round(p, 4),
            "verdict": "phishing" if p >= self.threshold else ("suspicious" if p >= self.threshold * 0.6 else "legitimate"),
            "branches": {"feature_model": round(float(a[0]), 4), "char_ngram_model": round(float(b[0]), 4)},
            "reasons": explain(feats),
            "features": feats,
        }

    def save(self, path: Path | str = DEFAULT_MODEL_PATH):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path | str = DEFAULT_MODEL_PATH) -> "HybridURLModel":
        return joblib.load(path)
