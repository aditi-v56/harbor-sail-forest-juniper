"""
Core prediction engine with risk score, confidence, and explanations.
"""

import joblib
import numpy as np
from pathlib import Path
from scipy.sparse import hstack
from features import extract_features, features_to_vector


class PhishingPredictor:
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = Path(__file__).parent.parent / "models" / "phishing_model.joblib"
        artifacts = joblib.load(model_path)
        self.clf = artifacts["clf"]
        self.tfidf = artifacts["tfidf"]

    def predict(self, subject: str, body: str, sender: str = "", headers: str = "") -> dict:
        """
        Returns full verdict:
        - label: "phishing" | "safe"
        - risk_score: 0-100
        - confidence: 0-1
        - needs_human: bool (low confidence)
        - red_flags: list[str]
        - urls: list
        - explanation: str
        """
        item = {"subject": subject, "body": body, "sender": sender, "headers": headers}

        # Structural features + red flags
        feat_result = extract_features(subject, body, sender, headers)
        struct_vec = features_to_vector(feat_result["features"]).reshape(1, -1)

        # TF-IDF
        text = f"{subject} {body}"
        tfidf_vec = self.tfidf.transform([text])

        X = hstack([tfidf_vec, struct_vec])

        proba = self.clf.predict_proba(X)[0]
        phishing_prob = float(proba[1])
        safe_prob = float(proba[0])

        risk_score = int(round(phishing_prob * 100))
        confidence = float(max(phishing_prob, safe_prob))

        # Decision thresholds (enterprise-grade)
        # High confidence phishing: >= 0.85
        # High confidence safe: >= 0.80
        # Everything else -> human review
        if phishing_prob >= 0.85:
            label = "phishing"
            needs_human = False
        elif safe_prob >= 0.80:
            label = "safe"
            needs_human = False
        else:
            label = "phishing" if phishing_prob > 0.5 else "safe"
            needs_human = True

        # Boost risk if many strong red flags even if model is less certain
        strong_flags = len(feat_result["red_flags"])
        if strong_flags >= 3 and risk_score < 70:
            risk_score = min(95, risk_score + 20)
            needs_human = True

        explanation_parts = []
        if label == "phishing":
            explanation_parts.append(f"Classified as PHISHING (risk {risk_score}/100).")
        else:
            explanation_parts.append(f"Classified as SAFE (risk {risk_score}/100).")

        if feat_result["red_flags"]:
            explanation_parts.append("Key red flags:")
            for rf in feat_result["red_flags"][:5]:
                explanation_parts.append(f"  • {rf}")
        else:
            explanation_parts.append("No major structural red flags detected.")

        if needs_human:
            explanation_parts.append("⚠ Low confidence → flagged for human review.")

        return {
            "label": label,
            "risk_score": risk_score,
            "confidence": round(confidence, 3),
            "phishing_probability": round(phishing_prob, 3),
            "needs_human": needs_human,
            "red_flags": feat_result["red_flags"],
            "urls": feat_result["urls"],
            "features": feat_result["features"],
            "explanation": "\n".join(explanation_parts)
        }


if __name__ == "__main__":
    pred = PhishingPredictor()
    sample = pred.predict(
        subject="URGENT: Your Microsoft account will be suspended in 24 hours",
        body="Dear Customer, We detected unusual activity. Verify now: https://micros0ft-support.xyz/login",
        sender="security@micros0ft-support.com",
        headers="Authentication-Results: spf=fail dkim=none"
    )
    print(sample["explanation"])
    print("Risk:", sample["risk_score"], "Human:", sample["needs_human"])
