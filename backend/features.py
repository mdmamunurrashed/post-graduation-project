# ============================================================
# WebSentinel ML — Feature Extraction Engine
# Extracts 30+ features from any URL for ML model input
# Used by both training scripts and Flask API
# ============================================================

import re
import math
import tldextract
from urllib.parse import urlparse

# ── Known brand names (for impersonation detection) ──────────
BRANDS = [
    'paypal', 'google', 'facebook', 'amazon', 'microsoft', 'apple',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'gmail',
    'outlook', 'yahoo', 'bank', 'wellsfargo', 'chase', 'citibank',
    'hsbc', 'barclays', 'ebay', 'steam', 'discord', 'whatsapp'
]

# ── Suspicious TLDs ──────────────────────────────────────────
SUSPICIOUS_TLDS = [
    'xyz', 'top', 'club', 'online', 'site', 'icu', 'live',
    'stream', 'gq', 'ml', 'cf', 'tk', 'pw', 'cc', 'work',
    'click', 'loan', 'win', 'download', 'review'
]

# ── Suspicious keywords ──────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'banking', 'password', 'credential', 'authenticate',
    'suspend', 'unusual', 'limited', 'urgent', 'alert', 'warning'
]


def extract_features(url):
    """
    Extract 30 numerical features from a URL.
    Returns a list of numbers that the ML model uses for prediction.
    """
    features = {}

    try:
        parsed   = urlparse(url)
        extracted = tldextract.extract(url)
        hostname  = parsed.netloc.lower()
        path      = parsed.path.lower()
        full_url  = url.lower()
        domain    = extracted.domain.lower()
        suffix    = extracted.suffix.lower()
        subdomain = extracted.subdomain.lower()
    except Exception:
        # Return all zeros if URL can't be parsed
        return [0] * 30

    # ── Feature 1: URL Length ────────────────────────────────
    features['url_length'] = len(url)

    # ── Feature 2: Hostname Length ───────────────────────────
    features['hostname_length'] = len(hostname)

    # ── Feature 3: Path Length ───────────────────────────────
    features['path_length'] = len(path)

    # ── Feature 4: Number of Dots ────────────────────────────
    features['num_dots'] = url.count('.')

    # ── Feature 5: Number of Hyphens ─────────────────────────
    features['num_hyphens'] = url.count('-')

    # ── Feature 6: Number of Slashes ─────────────────────────
    features['num_slashes'] = url.count('/')

    # ── Feature 7: Number of @ Symbols ───────────────────────
    features['num_at'] = url.count('@')

    # ── Feature 8: Number of ? ───────────────────────────────
    features['num_question'] = url.count('?')

    # ── Feature 9: Number of = ───────────────────────────────
    features['num_equals'] = url.count('=')

    # ── Feature 10: Number of Underscores ────────────────────
    features['num_underscores'] = url.count('_')

    # ── Feature 11: Has HTTPS ────────────────────────────────
    features['has_https'] = 1 if parsed.scheme == 'https' else 0

    # ── Feature 12: Has IP Address ───────────────────────────
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    features['has_ip'] = 1 if ip_pattern.match(hostname) else 0

    # ── Feature 13: Subdomain Count ──────────────────────────
    features['subdomain_count'] = len(subdomain.split('.')) if subdomain else 0

    # ── Feature 14: Suspicious TLD ───────────────────────────
    features['suspicious_tld'] = 1 if suffix in SUSPICIOUS_TLDS else 0

    # ── Feature 15: Brand in Subdomain (impersonation) ───────
    brand_in_sub = any(brand in subdomain for brand in BRANDS)
    brand_in_domain = any(brand in domain for brand in BRANDS)
    features['brand_impersonation'] = 1 if (brand_in_sub and not brand_in_domain) else 0

    # ── Feature 16: Suspicious Keywords Count ────────────────
    features['suspicious_keywords'] = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url
    )

    # ── Feature 17: URL Entropy (randomness measure) ─────────
    # High entropy = random looking domain = suspicious
    features['url_entropy'] = _calculate_entropy(domain)

    # ── Feature 18: Digit Ratio in URL ───────────────────────
    digits = sum(c.isdigit() for c in url)
    features['digit_ratio'] = digits / len(url) if len(url) > 0 else 0

    # ── Feature 19: Letter Ratio in URL ──────────────────────
    letters = sum(c.isalpha() for c in url)
    features['letter_ratio'] = letters / len(url) if len(url) > 0 else 0

    # ── Feature 20: Has Double HTTP ──────────────────────────
    features['has_double_http'] = 1 if full_url.count('http') > 1 else 0

    # ── Feature 21: Has URL Shortener ────────────────────────
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
    features['is_shortened'] = 1 if any(s in full_url for s in shorteners) else 0

    # ── Feature 22: Has Hex Encoding ─────────────────────────
    hex_matches = re.findall(r'%[0-9a-fA-F]{2}', url)
    features['has_hex_encoding'] = 1 if len(hex_matches) > 3 else 0

    # ── Feature 23: Number of Subdomains ─────────────────────
    features['num_subdomains'] = hostname.count('.') - 1 if hostname.count('.') > 1 else 0

    # ── Feature 24: Domain Length ────────────────────────────
    features['domain_length'] = len(domain)

    # ── Feature 25: Has Port Number ──────────────────────────
    features['has_port'] = 1 if parsed.port else 0

    # ── Feature 26: Has Fragment (#) ─────────────────────────
    features['has_fragment'] = 1 if parsed.fragment else 0

    # ── Feature 27: Special Char Ratio ───────────────────────
    special = sum(1 for c in url if not c.isalnum() and c not in ['/', '.', ':'])
    features['special_char_ratio'] = special / len(url) if len(url) > 0 else 0

    # ── Feature 28: Path Depth ───────────────────────────────
    features['path_depth'] = path.count('/')

    # ── Feature 29: Has Typosquatting Pattern ────────────────
    # Check if domain is 1-2 chars different from a known brand
    features['typosquatting'] = 1 if _check_typosquatting(domain) else 0

    # ── Feature 30: Query Parameter Count ───────────────────
    features['query_param_count'] = len(parsed.query.split('&')) if parsed.query else 0

    return list(features.values())


def get_feature_names():
    """Returns the names of all 30 features — used for model explainability."""
    return [
        'url_length', 'hostname_length', 'path_length', 'num_dots',
        'num_hyphens', 'num_slashes', 'num_at', 'num_question',
        'num_equals', 'num_underscores', 'has_https', 'has_ip',
        'subdomain_count', 'suspicious_tld', 'brand_impersonation',
        'suspicious_keywords', 'url_entropy', 'digit_ratio',
        'letter_ratio', 'has_double_http', 'is_shortened',
        'has_hex_encoding', 'num_subdomains', 'domain_length',
        'has_port', 'has_fragment', 'special_char_ratio',
        'path_depth', 'typosquatting', 'query_param_count'
    ]


def _calculate_entropy(text):
    """Calculate Shannon entropy of a string — measures randomness."""
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _check_typosquatting(domain):
    """Check if domain is suspiciously similar to a known brand."""
    for brand in BRANDS:
        if brand == domain:
            return False  # exact match is fine
        distance = _levenshtein(domain, brand)
        if 0 < distance <= 2 and len(domain) > 3:
            return True
    return False


def _levenshtein(a, b):
    """Calculate edit distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (ca != cb)
            ))
        prev = curr
    return prev[len(b)]


# ── Quick test ───────────────────────────────────────────────
if __name__ == '__main__':
    test_urls = [
        'https://www.google.com',
        'http://paypal-secure-login.xyz/verify?account=123',
        'http://192.168.1.1/login',
        'https://www.facebook.com',
        'http://bit.ly/suspicious123'
    ]

    print(f"{'URL':<50} {'Features':>10}")
    print("-" * 70)
    for url in test_urls:
        feats = extract_features(url)
        print(f"{url[:48]:<50} {len(feats)} features extracted")

    print("\nFeature names:")
    for i, name in enumerate(get_feature_names()):
        print(f"  {i+1:2}. {name}")
