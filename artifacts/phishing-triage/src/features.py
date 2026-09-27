"""
Feature extraction for phishing email detection.
Extracts both content-based and structural red-flag features.
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple
import numpy as np

# Common urgency / phishing keywords
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "within 24 hours", "account suspended",
    "verify your account", "confirm your identity", "password expired",
    "security alert", "unusual activity", "click here", "login now",
    "limited time", "final notice", "action required", "suspended",
    "locked", "compromised", "verify now", "update payment"
]

# Suspicious TLDs / patterns
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".info", ".online"}

# Common brand domains for lookalike detection
TRUSTED_BRANDS = [
    "microsoft", "google", "apple", "amazon", "paypal", "bankofamerica",
    "chase", "wellsfargo", "citibank", "hsbc", "icici", "hdfc", "sbi",
    "axisbank", "kotak", "outlook", "office365", "linkedin", "dropbox"
]


def extract_urls(text: str) -> List[str]:
    """Extract URLs from email body/subject."""
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def is_lookalike_domain(domain: str, brands: List[str] = TRUSTED_BRANDS) -> Tuple[bool, str]:
    """Simple lookalike detection using character distance / common substitutions."""
    domain = domain.lower().replace("www.", "")
    base = domain.split(".")[0] if "." in domain else domain

    for brand in brands:
        if brand in base and base != brand:
            # Check for common substitutions
            if any(c.isdigit() for c in base) or "-" in base or len(base) > len(brand) + 3:
                return True, f"Lookalike of {brand}: {domain}"
        # Levenshtein-like simple check
        if abs(len(base) - len(brand)) <= 2:
            diffs = sum(1 for a, b in zip(base, brand) if a != b)
            if diffs <= 2 and base != brand:
                return True, f"Possible lookalike of {brand}: {domain}"
    return False, ""


def extract_features(subject: str, body: str, sender: str = "", headers: str = "") -> Dict:
    """
    Extract a rich feature vector + human-readable red flags.
    Returns dict with numeric features and list of red_flag strings.
    """
    text = f"{subject} {body}".lower()
    full = f"{subject}\n{body}\n{sender}\n{headers}".lower()

    red_flags = []
    features = {}

    # 1. Urgency keywords
    urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in text)
    features["urgency_score"] = min(urgency_count / 3.0, 1.0)
    if urgency_count >= 2:
        red_flags.append(f"High urgency language detected ({urgency_count} indicators)")

    # 2. URLs
    urls = extract_urls(full)
    features["num_urls"] = len(urls)
    features["has_url"] = 1 if urls else 0

    suspicious_url = False
    lookalike_found = False
    for url in urls:
        try:
            parsed = urlparse(url if url.startswith("http") else "http://" + url)
            domain = parsed.netloc.lower()
            tld = "." + domain.split(".")[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                suspicious_url = True
                red_flags.append(f"Suspicious TLD in URL: {domain}")
            is_look, reason = is_lookalike_domain(domain)
            if is_look:
                lookalike_found = True
                red_flags.append(reason)
            # IP address in URL
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                red_flags.append(f"IP address used in URL instead of domain: {domain}")
                suspicious_url = True
        except Exception:
            pass

    features["suspicious_url"] = 1 if suspicious_url else 0
    features["lookalike_domain"] = 1 if lookalike_found else 0

    # 3. Sender analysis
    sender_lower = sender.lower()
    features["sender_has_noreply"] = 1 if "noreply" in sender_lower or "no-reply" in sender_lower else 0
    features["sender_mismatch"] = 0
    if sender and "@" in sender:
        display = sender.split("<")[0].strip().lower() if "<" in sender else ""
        actual = sender.split("<")[-1].replace(">", "").strip().lower() if "<" in sender else sender_lower
        domain = actual.split("@")[-1] if "@" in actual else ""
        # Simple display name vs domain mismatch heuristic
        if display and domain and not any(b in domain for b in TRUSTED_BRANDS):
            if any(b in display for b in TRUSTED_BRANDS):
                features["sender_mismatch"] = 1
                red_flags.append(f"Display name suggests trusted brand but domain is: {domain}")

    # 4. Header authentication simulation (from provided headers text)
    features["spf_fail"] = 1 if "spf=fail" in headers.lower() or "spf=softfail" in headers.lower() else 0
    features["dkim_fail"] = 1 if "dkim=fail" in headers.lower() or "dkim=none" in headers.lower() else 0
    features["dmarc_fail"] = 1 if "dmarc=fail" in headers.lower() else 0
    if features["spf_fail"] or features["dkim_fail"] or features["dmarc_fail"]:
        red_flags.append("Email authentication (SPF/DKIM/DMARC) failed or missing")

    # 5. Content length / structure
    features["subject_len"] = len(subject)
    features["body_len"] = len(body)
    features["has_attachment_mention"] = 1 if any(w in text for w in ["attachment", "invoice", "document", ".pdf", ".doc", ".zip"]) else 0
    if features["has_attachment_mention"] and features["urgency_score"] > 0.3:
        red_flags.append("Mentions attachment + urgency (common malware vector)")

    # 6. Generic greeting / poor personalization
    features["generic_greeting"] = 1 if any(g in text for g in ["dear customer", "dear user", "dear valued", "hello sir", "dear account holder"]) else 0
    if features["generic_greeting"]:
        red_flags.append("Generic / non-personalized greeting")

    # 7. Request for credentials / money
    cred_keywords = ["password", "otp", "pin", "cvv", "credit card", "bank account", "ssn", "login credentials"]
    features["asks_credentials"] = 1 if any(k in text for k in cred_keywords) else 0
    if features["asks_credentials"]:
        red_flags.append("Requests sensitive credentials or financial information")

    # 8. HTML / form indicators (simplified)
    features["has_form_or_button"] = 1 if any(w in text for w in ["submit", "click here", "verify now", "confirm"]) else 0

    return {
        "features": features,
        "red_flags": red_flags,
        "urls": urls
    }


def features_to_vector(feat_dict: Dict) -> np.ndarray:
    """Convert feature dict to ordered numeric vector for ML."""
    order = [
        "urgency_score", "num_urls", "has_url", "suspicious_url", "lookalike_domain",
        "sender_has_noreply", "sender_mismatch", "spf_fail", "dkim_fail", "dmarc_fail",
        "subject_len", "body_len", "has_attachment_mention", "generic_greeting",
        "asks_credentials", "has_form_or_button"
    ]
    return np.array([feat_dict.get(k, 0) for k in order], dtype=float)
