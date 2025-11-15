#!/usr/bin/env python3
"""Test the heuristics with known phishing and legitimate URLs"""

from url_heuristics import detect_phishing_heuristics

test_urls = [
    ("https://www.hskonline.com", "Phishing (HSBC impersonation)"),
    ("https://www.google.com", "Legitimate (known)"),
    ("https://www.amazon.com", "Legitimate (known)"),
    ("https://www.paypa1.com", "Phishing (PayPal look-alike)"),
    ("https://login-verify-account.com/login/verify", "Phishing (suspicious)"),
    ("https://github.com", "Legitimate (known)"),
]

print("\n" + "="*80)
print("PHISHING DETECTION HEURISTICS TEST")
print("="*80 + "\n")

for url, expected in test_urls:
    result, confidence, features = detect_phishing_heuristics(url)
    
    print(f"URL: {url}")
    print(f"Expected: {expected}")
    print(f"Result: {result}")
    print(f"Confidence: Phishing={confidence['phishing']}% | Legitimate={confidence['legitimate']}%")
    
    # Show detection factors
    if features.get('KnownPhishingPattern'):
        print(f"  ⚠️  Known Phishing: {features['KnownPhishingPattern']}")
    if features.get('ImpersonationAttempt'):
        print(f"  ⚠️  Impersonation: {features['ImpersonationAttempt']}")
    if features.get('RiskFactors'):
        risk_summary = ", ".join([f[0] for f in features['RiskFactors'][:3]])
        print(f"  Risk Factors: {risk_summary}")
    if features.get('TrustFactors'):
        trust_summary = ", ".join([f[0] for f in features['TrustFactors'][:2]])
        print(f"  Trust Factors: {trust_summary}")
    
    print("-" * 80 + "\n")

print("="*80)
