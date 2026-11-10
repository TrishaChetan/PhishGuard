"""Train + evaluate PhishGuard.

    python -m phishguard.train                      # synthetic data (offline)
    python -m phishguard.train --data PhiUSIIL.csv --invert-labels

Outputs:
    models/phishguard.joblib
    reports/metrics.json, reports/metrics.md
    reports/confusion_matrix.png, reports/roc_curve.png, reports/feature_importance.png
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split

from . import dataset
from .model import DEFAULT_MODEL_PATH, HybridURLModel, featurize

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"


def metrics(y, pred, proba) -> dict:
    return {
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, proba), 4),
        "false_positive_rate": round(float(((pred == 1) & (y == 0)).sum() / max(1, (y == 0).sum())), 4),
    }


def _plots(y, proba, pred, model: HybridURLModel):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = confusion_matrix(y, pred)
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, str(v), ha="center", va="center", color="white" if v > cm.max() / 2 else "black")
    ax.set_xticks([0, 1], ["Legit", "Phish"]); ax.set_yticks([0, 1], ["Legit", "Phish"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion matrix (test)")
    fig.tight_layout(); fig.savefig(REPORTS / "confusion_matrix.png", dpi=140); plt.close(fig)

    fpr, tpr, _ = roc_curve(y, proba)
    fig, ax = plt.subplots(figsize=(4.2, 3.6))
    ax.plot(fpr, tpr, label=f"Hybrid (AUC={roc_auc_score(y, proba):.3f})")
    ax.plot([0, 1], [0, 1], "--", color="grey")
    ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate"); ax.set_title("ROC curve"); ax.legend()
    fig.tight_layout(); fig.savefig(REPORTS / "roc_curve.png", dpi=140); plt.close(fig)

    top = model.top_features(12)[::-1]
    fig, ax = plt.subplots(figsize=(5.5, 4))
    ax.barh([n for n, _ in top], [v for _, v in top], color="#3b6ea5")
    ax.set_title("Random-forest feature importance"); fig.tight_layout()
    fig.savefig(REPORTS / "feature_importance.png", dpi=140); plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="CSV with url + label/type columns (default: synthetic)")
    ap.add_argument("--invert-labels", action="store_true", help="for datasets where 1 = legitimate (PhiUSIIL)")
    ap.add_argument("--n", type=int, default=8000, help="synthetic sample size")
    ap.add_argument("--max-rows", type=int, default=200000)
    ap.add_argument("--out", default=str(DEFAULT_MODEL_PATH))
    args = ap.parse_args(argv)

    df = dataset.load_csv(args.data) if args.data else dataset.generate(args.n)
    if args.invert_labels:
        df["label"] = 1 - df["label"]
    if len(df) > args.max_rows:
        df = df.sample(args.max_rows, random_state=1)
    # to_numpy(dtype=object) keeps this working on pandas 3, where .values
    # returns an Arrow-backed string array that sklearn cannot index
    X, y = df["url"].to_numpy(dtype=object), df["label"].to_numpy(dtype=int)
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.3, stratify=y, random_state=1)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.5, stratify=y_tmp, random_state=1)
    print(f"[data] {len(df)} URLs  train={len(X_tr)} val={len(X_val)} test={len(X_te)}  phishing={y.mean():.1%}")

    results = {}
    # Baselines for the comparison table in the report
    F_tr, F_te = featurize(X_tr), featurize(X_te)
    for name, clf in {
        "LogisticRegression (features)": LogisticRegression(max_iter=3000, class_weight="balanced"),
        "GradientBoosting (features)": GradientBoostingClassifier(random_state=7),
    }.items():
        t = time.time(); clf.fit(F_tr, y_tr)
        p = clf.predict_proba(F_te)[:, 1]
        results[name] = metrics(y_te, (p >= 0.5).astype(int), p) | {"train_seconds": round(time.time() - t, 2)}

    t = time.time()
    model = HybridURLModel().fit(X_tr, y_tr).tune(X_val, y_val)
    train_s = round(time.time() - t, 2)
    a, b = model.branch_proba(X_te)
    results["RandomForest (features)"] = metrics(y_te, (a >= 0.5).astype(int), a)
    results["LogReg (char n-grams)"] = metrics(y_te, (b >= 0.5).astype(int), b)
    proba = model.predict_proba(X_te)
    pred = (proba >= model.threshold).astype(int)
    results["Hybrid fusion (PhishGuard)"] = metrics(y_te, pred, proba) | {"train_seconds": train_s}

    t = time.time(); model.predict_proba(X_te[:500]); lat = (time.time() - t) / min(500, len(X_te)) * 1000

    REPORTS.mkdir(exist_ok=True)
    summary = {
        "dataset": args.data or f"synthetic (n={args.n})",
        "n_urls": int(len(df)),
        "fusion_weight_features": round(float(model.w_features), 2),
        "threshold": round(float(model.threshold), 2),
        "avg_latency_ms_per_url": round(lat, 3),
        "models": results,
        "top_features": model.top_features(10),
    }
    (REPORTS / "metrics.json").write_text(json.dumps(summary, indent=2))
    lines = ["| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |", "|---|---|---|---|---|---|---|"]
    for k, m in results.items():
        lines.append(f"| {k} | {m['accuracy']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['roc_auc']} | {m['false_positive_rate']} |")
    (REPORTS / "metrics.md").write_text(f"Dataset: {summary['dataset']}\n\n" + "\n".join(lines) + "\n")
    _plots(y_te, proba, pred, model)
    model.save(args.out)
    print("\n".join(lines))
    print(f"[model] saved -> {args.out}  (w={model.w_features:.2f}, threshold={model.threshold:.2f}, {lat:.2f} ms/url)")


if __name__ == "__main__":
    main()
