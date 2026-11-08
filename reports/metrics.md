Dataset: synthetic (n=8000)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR |
|---|---|---|---|---|---|---|
| LogisticRegression (features) | 0.9892 | 0.9874 | 0.991 | 0.9892 | 0.989 | 0.0125 |
| GradientBoosting (features) | 0.9892 | 0.9874 | 0.991 | 0.9892 | 0.9877 | 0.0125 |
| RandomForest (features) | 0.9892 | 0.9874 | 0.991 | 0.9892 | 0.9903 | 0.0125 |
| LogReg (char n-grams) | 0.9892 | 0.9874 | 0.991 | 0.9892 | 0.9893 | 0.0125 |
| Hybrid fusion (PhishGuard) | 0.9892 | 0.9874 | 0.991 | 0.9892 | 0.9901 | 0.0125 |
