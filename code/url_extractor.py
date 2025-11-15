import re
from urllib.parse import urlparse

class URLFeatureExtractor:
    """Extract features from a URL that match the dataset"""
    
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
        self.features = {}
    
    def extract_all_features(self):
        """Extract all features matching the dataset"""
        # Use default values for features we can extract from URL
        # For features that need page content (LineOfCode, HasTitle, etc.), use 0
        
        self.features = {
            'URLLength': len(self.url),
            'DomainLength': len(self.parsed.netloc),
            'IsDomainIP': 1 if self._is_domain_ip() else 0,
            'URLSimilarityIndex': 0.5,
            'CharContinuationRate': self._char_continuation_rate(),
            'TLDLegitimateProb': self._tld_legitimate_prob(),
            'URLCharProb': self._calculate_char_prob(),
            'TLDLength': len(self._get_tld()),
            'NoOfSubDomain': self._count_subdomains(),
            'HasObfuscation': 1 if self._detect_obfuscation() else 0,
            'NoOfObfuscatedChar': self._count_obfuscated_chars(),
            'ObfuscationRatio': 0.0,
            'NoOfLettersInURL': sum(1 for c in self.url if c.isalpha()),
            'LetterRatioInURL': sum(1 for c in self.url if c.isalpha()) / max(len(self.url), 1),
            'NoOfDegitsInURL': sum(1 for c in self.url if c.isdigit()),
            'DegitRatioInURL': sum(1 for c in self.url if c.isdigit()) / max(len(self.url), 1),
            'NoOfEqualsInURL': self.url.count('='),
            'NoOfQMarkInURL': self.url.count('?'),
            'NoOfAmpersandInURL': self.url.count('&'),
            'NoOfOtherSpecialCharsInURL': sum(1 for c in self.url if c in '!@#$%^*()_+-[]{}|;:,.<>~/'),
            'SpacialCharRatioInURL': 0.1,
            'IsHTTPS': 1 if self.parsed.scheme == 'https' else 0,
            'LineOfCode': 0,
            'LargestLineLength': 0,
            'HasTitle': 0,
            'DomainTitleMatchScore': 0,
            'URLTitleMatchScore': 0,
            'HasFavicon': 0,
            'Robots': 0,
            'IsResponsive': 0,
            'NoOfURLRedirect': 1 if '//' in self.parsed.path else 0,
            'NoOfSelfRedirect': 0,
            'HasDescription': 0,
            'NoOfPopup': 0,
            'NoOfiFrame': 0,
            'HasExternalFormSubmit': 0,
            'HasSocialNet': 1 if any(s in self.url.lower() for s in ['facebook', 'twitter', 'instagram', 'linkedin']) else 0,
            'HasSubmitButton': 0,
            'HasHiddenFields': 0,
            'HasPasswordField': 0,
            'Bank': 1 if any(b in self.url.lower() for b in ['bank', 'banking', 'finance']) else 0,
            'Pay': 1 if any(p in self.url.lower() for p in ['pay', 'paypal', 'payment', 'checkout']) else 0,
            'Crypto': 1 if any(c in self.url.lower() for c in ['bitcoin', 'crypto', 'ethereum', 'wallet']) else 0,
            'HasCopyrightInfo': 0,
            'NoOfImage': 0,
            'NoOfCSS': 0,
            'NoOfJS': 0,
            'NoOfSelfRef': 0,
            'NoOfEmptyRef': 0,
            'NoOfExternalRef': 0,
        }
        
        return self.features
    
    def _is_domain_ip(self):
        """Check if domain is an IP address"""
        domain = self.parsed.netloc.split(':')[0]
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _count_subdomains(self):
        """Count number of subdomains"""
        domain = self.parsed.netloc
        return max(0, domain.count('.') - 1)
    
    def _get_tld(self):
        """Get Top Level Domain"""
        domain = self.parsed.netloc
        parts = domain.split('.')
        return parts[-1] if parts else ''
    
    def _detect_obfuscation(self):
        """Detect obfuscation techniques"""
        obfuscation_indicators = ['%', 'javascript:', 'data:', '&#', '&lt;', '&gt;']
        return any(indicator in self.url.lower() for indicator in obfuscation_indicators)
    
    def _count_obfuscated_chars(self):
        """Count obfuscated characters"""
        hex_pattern = r'%[0-9a-fA-F]{2}'
        return len(re.findall(hex_pattern, self.url))
    
    def _char_continuation_rate(self):
        """Calculate character continuation rate"""
        if len(self.url) < 2:
            return 0
        
        continuations = 0
        for i in range(len(self.url) - 1):
            if self.url[i] == self.url[i+1]:
                continuations += 1
        
        return min(continuations / len(self.url), 1.0)
    
    def _calculate_char_prob(self):
        """Calculate character probability (entropy)"""
        char_count = {}
        for char in self.url:
            char_count[char] = char_count.get(char, 0) + 1
        
        entropy = 0
        for count in char_count.values():
            prob = count / len(self.url)
            entropy -= prob * (prob ** 0.5)
        
        return min(entropy / 10, 1.0)
    
    def _tld_legitimate_prob(self):
        """Probability of TLD being legitimate"""
        tld = self._get_tld().lower()
        legitimate_tlds = {'com': 0.95, 'org': 0.90, 'net': 0.85, 'edu': 0.99, 'gov': 0.99}
        return legitimate_tlds.get(tld, 0.5)
