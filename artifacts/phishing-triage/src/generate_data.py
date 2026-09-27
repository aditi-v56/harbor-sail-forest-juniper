"""
Generate realistic synthetic phishing and legitimate emails for training/demo.
"""

import random
import json
from pathlib import Path

PHISHING_TEMPLATES = [
    {
        "subject": "URGENT: Your {brand} account will be suspended in 24 hours",
        "body": "Dear Customer,\n\nWe detected unusual activity on your {brand} account. To avoid permanent suspension, please verify your identity immediately by clicking the link below:\n\n{url}\n\nIf you do not verify within 24 hours your account will be locked.\n\nSecurity Team\n{brand}",
        "sender": "security@{brand_lookalike}.com",
        "flags": ["urgency", "lookalike", "credentials"]
    },
    {
        "subject": "Action Required: Password Expired - {brand}",
        "body": "Hello User,\n\nYour password has expired. Click here to reset it now or lose access:\n{url}\n\nThis is your final notice.\n\nIT Support",
        "sender": "noreply@{brand_lookalike}.net",
        "flags": ["urgency", "credentials"]
    },
    {
        "subject": "Invoice #{num} - Payment Overdue",
        "body": "Dear Valued Customer,\n\nYour invoice is overdue. Please download the attached invoice and process payment immediately to avoid late fees.\n\nClick to view: {url}\n\nAccounts Payable",
        "sender": "billing@secure-payments-{brand}.xyz",
        "flags": ["urgency", "attachment", "suspicious_tld"]
    },
    {
        "subject": "Your package could not be delivered - Reschedule now",
        "body": "Hi,\n\nWe attempted to deliver your package but failed. Reschedule delivery within 48 hours or it will be returned:\n{url}\n\nCourier Services",
        "sender": "delivery@track-package.info",
        "flags": ["urgency", "suspicious_tld"]
    },
    {
        "subject": "Security Alert: New sign-in from unknown device",
        "body": "We noticed a new sign-in to your account from an unrecognized device. If this wasn't you, secure your account immediately:\n{url}\n\nMicrosoft Account Team",
        "sender": "account-security@micros0ft-support.com",
        "flags": ["urgency", "lookalike", "credentials"]
    },
]

LEGIT_TEMPLATES = [
    {
        "subject": "Your monthly statement is ready",
        "body": "Hi {name},\n\nYour account statement for this month is now available in the mobile app or online banking portal.\n\nNo action is required.\n\nThank you for banking with us.\nCustomer Service",
        "sender": "statements@realbank.com",
        "flags": []
    },
    {
        "subject": "Meeting reminder: Project sync tomorrow at 10 AM",
        "body": "Hi team,\n\nJust a quick reminder about our project sync tomorrow at 10:00 AM in the main conference room / Teams link.\n\nAgenda attached in the calendar invite.\n\nBest,\n{name}",
        "sender": "colleague@company.com",
        "flags": []
    },
    {
        "subject": "Welcome to our newsletter",
        "body": "Hello,\n\nThank you for subscribing. Here's what we covered this week...\n\nYou can manage your preferences anytime in settings.\n\nCheers,\nThe Team",
        "sender": "newsletter@legitbrand.com",
        "flags": []
    },
    {
        "subject": "Password reset request",
        "body": "Hi {name},\n\nWe received a request to reset your password. If this was you, use the link below (valid for 1 hour):\nhttps://accounts.realbrand.com/reset?token=abc123\n\nIf you did not request this, you can safely ignore this email.\n\nSecurity Team",
        "sender": "security@realbrand.com",
        "flags": []
    },
    {
        "subject": "Your order #ORD-{num} has shipped",
        "body": "Hi {name},\n\nGreat news! Your order has shipped and is on its way.\n\nTrack it here: https://www.realshop.com/track/{num}\n\nExpected delivery: 3-5 business days.\n\nThank you for shopping with us!",
        "sender": "orders@realshop.com",
        "flags": []
    },
]

BRANDS = ["Microsoft", "PayPal", "Amazon", "HDFC Bank", "ICICI", "Google", "Apple"]
LOOKALIKES = {
    "Microsoft": ["micros0ft", "microsoft-support", "office365-secure"],
    "PayPal": ["paypa1", "paypal-secure", "paypal-verify"],
    "Amazon": ["amaz0n", "amazon-support", "amzn-secure"],
    "HDFC Bank": ["hdfc-bank-secure", "hdfcbank-verify"],
    "ICICI": ["icici-bank-alert", "icicibank-secure"],
    "Google": ["go0gle", "google-accounts", "g00gle"],
    "Apple": ["app1e", "apple-id-support", "icloud-secure"],
}

NAMES = ["Alex", "Priya", "Rahul", "Sarah", "Amit", "Jennifer", "Vikram"]


def generate_email(is_phishing: bool) -> dict:
    if is_phishing:
        tmpl = random.choice(PHISHING_TEMPLATES)
        brand = random.choice(BRANDS)
        look = random.choice(LOOKALIKES.get(brand, ["secure-" + brand.lower()]))
        url = f"https://{look}.xyz/verify?id={random.randint(10000,99999)}"
        subject = tmpl["subject"].format(brand=brand, num=random.randint(1000,9999))
        body = tmpl["body"].format(brand=brand, url=url, num=random.randint(1000,9999))
        sender = tmpl["sender"].format(brand_lookalike=look, brand=brand.lower().replace(" ", ""))
        # Add some failed auth headers for phishing
        headers = "Authentication-Results: spf=fail dkim=none dmarc=fail"
        label = 1
    else:
        tmpl = random.choice(LEGIT_TEMPLATES)
        name = random.choice(NAMES)
        num = random.randint(10000, 99999)
        subject = tmpl["subject"].format(name=name, num=num)
        body = tmpl["body"].format(name=name, num=num)
        sender = tmpl["sender"]
        headers = "Authentication-Results: spf=pass dkim=pass dmarc=pass"
        label = 0

    return {
        "subject": subject,
        "body": body,
        "sender": sender,
        "headers": headers,
        "label": label  # 1 = phishing, 0 = safe
    }


def generate_dataset(n_phishing=400, n_safe=400, seed=42):
    random.seed(seed)
    data = []
    for _ in range(n_phishing):
        data.append(generate_email(True))
    for _ in range(n_safe):
        data.append(generate_email(False))
    random.shuffle(data)
    return data


if __name__ == "__main__":
    data = generate_dataset()
    out = Path(__file__).parent.parent / "data" / "synthetic_emails.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {len(data)} emails -> {out}")
    print(f"Phishing: {sum(1 for d in data if d['label']==1)}, Safe: {sum(1 for d in data if d['label']==0)}")
