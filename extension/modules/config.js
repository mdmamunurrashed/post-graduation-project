// ============================================================
// WebSentinel — config.example.js
// Copy this file to config.js and fill in your OWN API keys.
// config.js is gitignored — never commit real keys.
// ============================================================

export const WEBSENTINEL_CONFIG = {
  VIRUSTOTAL_API_KEY:           'YOUR_VIRUSTOTAL_API_KEY',
  VIRUSTOTAL_URL_ENDPOINT:      'https://www.virustotal.com/api/v3/urls',
  GOOGLE_SAFE_BROWSING_API_KEY: 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY',
  GOOGLE_SAFE_BROWSING_ENDPOINT:'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  OPENPHISH_FEED:               'https://openphish.com/feed.txt',
  AUTH_ENDPOINT:                'http://localhost:5000/auth',
  EXTENSION_API_KEY:            'YOUR_EXTENSION_API_KEY',
  ML_API_ENDPOINT:              'http://localhost:5000/predict',
  ML_API_ENABLED:               true,
  ML_API_TIMEOUT:               8000,
  TRANCO_ENDPOINT:              'http://localhost:5000/check-tranco',
  QR_SCAN_ENDPOINT:             'http://localhost:5000/scan-qr',
  WEIGHTS: {
    heuristic:          0.10,
    behavior:           0.05,
    virusTotal:         0.20,
    googleSafeBrowsing: 0.15,
    tranco:             0.05,
    mlModel:            0.45
  },
  CACHE_DURATION_MS:  10 * 60 * 1000,
  SCORE_THRESHOLDS: { PHISHING: 70, SUSPICIOUS: 45, LOW_RISK: 20 }
};
