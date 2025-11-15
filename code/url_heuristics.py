import re
from urllib.parse import urlparse

def detect_phishing_heuristics(url):
    """
    Detect phishing URLs using improved heuristics
    Returns: (result, confidence_dict, features_dict)
    """
    
    parsed = urlparse(url)
    features = {}
    risk_factors = []
    trust_factors = []
    
    # Parse domain
    domain = parsed.netloc.split(':')[0].lower() if parsed.netloc else ''
    domain_without_www = domain.replace('www.', '')
    tld = domain.split('.')[-1] if '.' in domain else ''
    
    features['Domain'] = domain
    features['TLD'] = tld
    
    # ============ KNOWN LEGITIMATE DOMAINS ============
    known_legitimate = ['google.com', 'facebook.com', 'github.com', 'stackoverflow.com',
                       'wikipedia.org', 'amazon.com', 'youtube.com', 'twitter.com',
                       'linkedin.com', 'reddit.com', 'instagram.com', 'microsoft.com',
                       'apple.com', 'dropbox.com', 'slack.com', 'ibm.com', 'intel.com',
                       'oracle.com', 'adobe.com', 'spotify.com', 'netflix.com']
    
    is_known_legitimate = any(legit in domain_without_www for legit in known_legitimate)
    features['IsKnownLegitimate'] = is_known_legitimate
    
    if is_known_legitimate:
        trust_factors.append(('Known legitimate domain', 40))
    
    # ============ KNOWN PHISHING PATTERNS ============
    # Strong phishing indicators - check first
    known_phishing_patterns = {
        'hskonline': 'HSBC impersonation',
        'paypa1': 'PayPal look-alike (0 vs O)',
        'amazom': 'Amazon look-alike',
        'applee': 'Apple look-alike',
        'micros0ft': 'Microsoft look-alike (0 vs O)',
    }
    
    detected_known_phishing = None
    for phishing_pattern, description in known_phishing_patterns.items():
        if phishing_pattern in domain_without_www:
            detected_known_phishing = description
            risk_factors.append((f'Known phishing: {description}', 50))
            break
    
    features['KnownPhishingPattern'] = detected_known_phishing
    
    # ============ IMPERSONATION DETECTION ============
    # If not already flagged as known phishing, check for impersonation attempts
    if not detected_known_phishing and not is_known_legitimate:
        impersonation_checks = {
            'hsk': 'HSBC (banking)',
            'hsbc': 'HSBC (banking)',
            'lloyds': 'Lloyds (banking)',
            'barclays': 'Barclays (banking)',
            'chase': 'Chase (banking)',
            'citibank': 'Citibank (banking)',
            'wellsfargo': 'Wells Fargo (banking)',
            'paypal': 'PayPal (payment)',
            'ebay': 'eBay (shopping)',
            'amazon': 'Amazon (shopping)',
            'apple': 'Apple (tech)',
            'microsoft': 'Microsoft (tech)',
            'google': 'Google (tech)',
            'facebook': 'Facebook (social)',
        }
        
        detected_impersonation = None
        for pattern, service in impersonation_checks.items():
            if pattern in domain_without_www:
                detected_impersonation = service
                risk_factors.append((f'Impersonating {service}', 35))
                break
        
        features['ImpersonationAttempt'] = detected_impersonation
    else:
        features['ImpersonationAttempt'] = None
    
    # ============ IP ADDRESS CHECK ============
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = bool(re.match(ip_pattern, domain))
    features['IsIPAddress'] = is_ip
    
    if is_ip:
        risk_factors.append(('IP address used (no domain)', 40))
    
    # ============ PROTOCOL CHECK ============
    features['HasHTTPS'] = parsed.scheme == 'https'
    if parsed.scheme == 'https':
        trust_factors.append(('Uses HTTPS', 10))
    else:
        risk_factors.append(('No HTTPS (uses HTTP)', 15))
    
    # ============ SUSPICIOUS TLDs ============
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top', 'gq', 'click', 'download', 
                      'review', 'date', 'win', 'trade', 'men', 'space', 'stream', 'party']
    features['SuspiciousTLD'] = tld in suspicious_tlds
    
    if tld in suspicious_tlds:
        risk_factors.append((f'Suspicious TLD (.{tld})', 25))
    elif tld in ['com', 'org', 'net', 'edu', 'gov', 'co', 'uk']:
        trust_factors.append((f'Common TLD (.{tld})', 5))
    
    # ============ SUSPICIOUS KEYWORDS IN URL ============
    suspicious_keywords = ['login', 'verify', 'confirm', 'update', 'check', 'urgent', 
                          'alert', 'action', 'account', 'secure', 'confirm-identity',
                          'authorization', 'authenticate', 'payment', 'billing', 'invoice',
                          'reset', 'reset-password', 'password-reset']
    url_lower = url.lower()
    suspicious_found = [kw for kw in suspicious_keywords if kw in url_lower]
    features['SuspiciousKeywords'] = suspicious_found
    
    if len(suspicious_found) >= 2:
        risk_factors.append(('Multiple suspicious keywords', 20))
    elif len(suspicious_found) == 1:
        risk_factors.append((f'Suspicious keyword: {suspicious_found[0]}', 15))
    
    # ============ URL OBFUSCATION ============
    has_hex = bool(re.search(r'%[0-9a-fA-F]{2}', url))
    features['HasHexEncoding'] = has_hex
    if has_hex:
        risk_factors.append(('Hex-encoded characters (obfuscation)', 20))
    
    # ============ SPECIAL CHARACTERS ============
    if '@' in parsed.netloc:
        risk_factors.append(('@ symbol in domain (credential hiding)', 30))
        features['HasAtSymbol'] = True
    else:
        features['HasAtSymbol'] = False
    
    # ============ DOMAIN LENGTH & STRUCTURE ============
    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain)
    
    if len(url) > 120:
        risk_factors.append(('Very long URL', 10))
    
    domain_parts = domain.split('.')
    if len(domain_parts) > 4:
        risk_factors.append(('Too many subdomains', 15))
        features['TooManySubdomains'] = True
    else:
        features['TooManySubdomains'] = False
    
    # ============ NUMBERS IN DOMAIN ============
    digits_in_domain = sum(1 for c in domain if c.isdigit())
    features['DigitsInDomain'] = digits_in_domain
    if digits_in_domain >= 3:
        risk_factors.append(('Too many digits in domain', 10))
    
    # ============ HYPHENS IN DOMAIN ============
    if '-' in domain_without_www:
        risk_factors.append(('Hyphens in domain (typosquatting)', 12))
        features['HasHyphenInDomain'] = True
    else:
        features['HasHyphenInDomain'] = False
    
    # ============ UNKNOWN DOMAIN (not in whitelist) ============
    if not is_known_legitimate and not detected_known_phishing:
        # Unknown domains get scrutinized more heavily
        if tld not in ['com', 'org', 'net', 'edu', 'gov', 'co', 'uk', 'de', 'fr', 'it', 'es', 'nl', 'ch', 'be', 'au', 'ca', 'in', 'ru', 'br', 'mx']:
            risk_factors.append(('Unknown domain with unusual TLD', 20))
        elif len(domain) > 60 or len(domain) < 5:
            pass  # Length is checked separately
        else:
            risk_factors.append(('Unknown/unverified domain', 15))
    
    # ============ CALCULATE FINAL SCORE ============
    risk_score = sum(score for _, score in risk_factors)
    trust_score = sum(score for _, score in trust_factors)
    
    features['RiskFactors'] = risk_factors
    features['TrustFactors'] = trust_factors
    
    # Calculate percentages
    total_score = risk_score + trust_score
    if total_score == 0:
        # Default: unknown domains are slightly suspicious
        phishing_percent = 60
        legitimate_percent = 40
    else:
        phishing_percent = (risk_score / total_score) * 100
        legitimate_percent = (trust_score / total_score) * 100
    
    # Determine result
    if phishing_percent >= 50:
        result = 'Phishing'
    elif legitimate_percent > phishing_percent:
        result = 'Legitimate'
    else:
        result = 'Suspicious'
    
    confidence = {
        'phishing': round(phishing_percent, 2),
        'legitimate': round(legitimate_percent, 2)
    }
    
    return result, confidence, features
