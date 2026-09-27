"""
Train phishing classifier and save model + metrics.
"""

import json
import joblib
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support, confusion_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
import sys
sys.path.insert(0, str(Path(__file__).parent))

from features import extract_features, features_to_vector
from generate_data import generate_dataset


class StructuralFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        # X is list of dicts with subject, body, sender, headers
        vectors = []
        for item in X:
            res = extract_features(
                item.get("subject", ""),
                item.get("body", ""),
                item.get("sender", ""),
                item.get("headers", "")
            )
            vectors.append(features_to_vector(res["features"]))
        return np.array(vectors)


class TextContent(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return [f"{item.get('subject','')} {item.get('body','')}" for item in X]


def train():
    print("Generating synthetic dataset...")
    data = generate_dataset(n_phishing=500, n_safe=500)
    y = np.array([d["label"] for d in data])

    X_train, X_test, y_train, y_test = train_test_split(
        data, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"Train: {len(X_train)}, Test: {len(X_test)}")

    # TF-IDF on text + structural features
    tfidf = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), stop_words="english")
    struct = StructuralFeatures()

    # Fit text transformer
    text_train = TextContent().transform(X_train)
    text_test = TextContent().transform(X_test)
    X_tfidf_train = tfidf.fit_transform(text_train)
    X_tfidf_test = tfidf.transform(text_test)

    X_struct_train = struct.fit_transform(X_train)
    X_struct_test = struct.transform(X_test)

    # Combine
    from scipy.sparse import hstack
    X_train_combined = hstack([X_tfidf_train, X_struct_train])
    X_test_combined = hstack([X_tfidf_test, X_struct_test])

    print("Training RandomForest...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train_combined, y_train)

    y_pred = clf.predict(X_test_combined)
    y_proba = clf.predict_proba(X_test_combined)[:, 1]

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    print(f"\nPrecision (Phishing): {prec:.4f}")
    print(f"Recall (Phishing):    {rec:.4f}")
    print(f"F1-Score:             {f1:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)

    # Save artifacts
    models_dir = Path(__file__).parent.parent / "models"
    models_dir.mkdir(exist_ok=True)

    joblib.dump({
        "clf": clf,
        "tfidf": tfidf,
        "feature_names": list(range(X_train_combined.shape[1]))
    }, models_dir / "phishing_model.joblib")

    metrics = {
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "support_phishing": int((y_test == 1).sum()),
        "support_safe": int((y_test == 0).sum()),
        "confusion_matrix": cm.tolist()
    }
    with open(models_dir / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved to {models_dir / 'phishing_model.joblib'}")
    print(f"Metrics: {metrics}")
    return metrics


if __name__ == "__main__":
    train()
