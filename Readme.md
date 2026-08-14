# WebSentinel

**WebSentinel** is a lightweight Chrome (Manifest V3) browser extension that detects phishing websites, blocks malicious redirects and ads, and warns users about spam pages in real time combining local heuristics with a machine learning ensemble (Random Forest, Gradient Boosting, LSTM, and a fine-tuned BERT model).

---

## Features

-  Real-time phishing detection with badge scoring (SAFE / LOW RISK / SUSPICIOUS / PHISHING)
-  ML ensemble scoring — Random Forest + Gradient Boosting + LSTM + HuggingFace BERT
-  15-check local URL heuristic engine (brand impersonation, homograph attacks, suspicious TLDs, obfuscation, etc.)
-  SSL & WHOIS domain age inspection
-  Behavioral page analysis (hidden iframes, urgency language, credential fields)
-  Cross-origin redirect blocker & new-tab hijack prevention
-  Declarative ad/tracker blocker (64+ rules, toggleable)
-  QR code scanning (hover + manual upload)
-  Domain whitelist support
-  Full dashboard with scan history, risk timeline, and ML performance stats
-  Works even when the backend is offline (falls back to heuristics + external APIs)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Extension | Chrome Manifest V3, Vanilla JS (ES Modules) |
| Ad Blocking | Chrome `declarativeNetRequest` API |
| ML Models | scikit-learn (Random Forest, Gradient Boosting), TensorFlow/Keras (LSTM), HuggingFace BERT |
| Backend | Python 3.11, FastAPI, Uvicorn |
| Auth | JWT (PyJWT, HS256) |
| QR Decoding | OpenCV |
| External APIs | VirusTotal v3, Google Safe Browsing v4, OpenPhish, Tranco |
| Storage | `chrome.storage.local` |

---

## Architecture

```
┌─────────────────────────────┐
│        Chrome Browser       │
│  content.js ─ background.js │
│         ─ popup.js          │
└──────────────┬───────────────┘
               │
     ┌─────────┼─────────────┐
     ▼         ▼             ▼
┌──────────┐ ┌────────────┐ ┌────────────────┐
│  Local   │ │  External  │ │ Chrome Native   │
│ Backend  │ │    APIs    │ │      APIs       │
│ (FastAPI)│ │ VT / GSB / │ │ declarativeNet  │
│ RF+GB+   │ │ Tranco /   │ │ Request (ads)   │
│ LSTM+BERT│ │ OpenPhish  │ │                 │
└──────────┘ └────────────┘ └────────────────┘
```

---

## Installation

### Offline / Local Setup (full local ML backend)

Use this if you want everything including the ML models running on your own machine.

1. **Clone the repo**
   ```bash
   git clone https://github.com/mdmamunurrashed/post-graduation-project.git
   ```

2. **Set up the backend**
   ```bash
   cd backend
   pip install -r libs.txt
   ```
   Open `.env` and fill in your own `JWT_SECRET_KEY`, `EXTENSION_API_KEY`, and `HF_API_TOKEN`. This file is gitignored and must never be committed.

3. **Run the backend**
   ```bash
   python api.py
   ```
   Backend runs at `http://localhost:5000`.

4. **Set up the extension config**
   ```bash
   cd extension/modules
   ```
   Open `config.js` and fill in your own `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, and `EXTENSION_API_KEY` (must match the one in `backend/.env`). `config.js` is gitignored your real keys stay local.

5. **Load the extension**
   - Open `chrome://extensions`
   - Enable **Developer Mode**
   - Click **Load unpacked** → select the `extension/` folder

The extension will now talk to your local backend for full ML-based scoring.

---

### ☁️ Online Setup (no local backend required)

Use this if you just want to try the extension quickly without running Python locally.

1. Download or clone the repo and grab the `extension/` folder.
2. In `extension/modules/`, modify `config.js` placing the API Keys.
3. In `backend/`, modify `.env` placing the API Keys.
4. Open `chrome://extensions` → enable **Developer Mode** → **Load unpacked** → select the `extension/` folder.

The extension will work immediately using the hosted backend no Python setup needed. Heuristics, ad blocking, and redirect protection work even if the backend is unreachable.

---

## Project Structure

```
websentinel/
├── .gitignore
├── backend/
│   ├── api.py
│   ├── features.py
│   ├── train_rf.py
│   ├── train_lstm.py
│   ├── .env        
│   └── models/
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html / popup.js
│   ├── dashboard.html / dashboard.js
│   ├── modules/
│   │   └── config.js
│   └── ad_rules.json
└── README.md
```

---

## Keeping Your API Keys Private

This project uses two files that hold real secrets:

| File | Holds |
|---|---|
| `backend/.env` | JWT secret, extension API key, HuggingFace Space token
| `extension/modules/config.js` | VirusTotal key, Google Safe Browsing key, extension API key

---
## Academic Information

**Prepared by:**
*Md. Mamun Ur Rashed, Executive Master in Information Technology, Institute of Information Technology, University of Dhaka.*

**Supervised by:**
*Professor Dr. Md. Shariful Islam, Institute of Information Technology, University of Dhaka.*

---

## Disclaimer

This is an academic project. Never commit real API keys or secrets to a public repository. For detailed information on the project, including architecture diagrams and explanations, please refer to the full project report. The report is available for review and anyone interested can check it out.
