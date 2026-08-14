# ============================================================
# WebSentinel ML — FastAPI  (v4)
# FastAPI + async/await + Pydantic + JWT authentication
# ============================================================

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
import asyncio, base64, csv, json, os, traceback
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv()

import httpx
import jwt
import joblib
import numpy as np
import cv2
from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from features import extract_features, get_feature_names


# ════════════════════════════════════════════════════════════
# JWT CONFIG  (values loaded from backend/.env)
# ════════════════════════════════════════════════════════════

JWT_SECRET_KEY    = os.getenv("JWT_SECRET_KEY",    "change-me-in-env")
JWT_ALGORITHM     = "HS256"
JWT_EXPIRE_HOURS  = int(os.getenv("JWT_EXPIRE_HOURS", "1"))
EXTENSION_API_KEY = os.getenv("EXTENSION_API_KEY", "change-me-in-env")


def _create_token() -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": "websentinel-ext", "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


security = HTTPBearer()

async def require_auth(credentials: HTTPAuthorizationCredentials = Security(security)):
    _verify_token(credentials.credentials)


# ════════════════════════════════════════════════════════════
# HuggingFace CONFIG
# ════════════════════════════════════════════════════════════

HF_API_TOKEN      = os.getenv("HF_API_TOKEN", "")
HF_PHISHING_MODEL = "ealvaradob/bert-finetuned-phishing"
HF_API_URL        = "https://router.huggingface.co/hf-inference/models/{model}"
HF_TIMEOUT        = 12.0

HF_SKIP_DOMAINS = {
    'google.com','mail.google.com','drive.google.com','docs.google.com',
    'accounts.google.com','notebooklm.google.com','meet.google.com',
    'photos.google.com','classroom.google.com','play.google.com',
    'youtube.com','gmail.com','facebook.com','instagram.com',
    'twitter.com','x.com','linkedin.com','whatsapp.com','web.whatsapp.com',
    'messenger.com','telegram.org','web.telegram.org',
    'microsoft.com','outlook.com','office.com','live.com',
    'login.microsoftonline.com','microsoftonline.com','azure.com',
    'office365.com','sharepoint.com','teams.microsoft.com',
    'apple.com','icloud.com','appleid.apple.com',
    'github.com','gitlab.com','bitbucket.org','stackoverflow.com',
    'amazon.com','aws.amazon.com','console.aws.amazon.com',
    'cloud.google.com','digitalocean.com','heroku.com',
    'ebay.com','etsy.com','shopify.com','stripe.com','paypal.com',
    'reddit.com','wikipedia.org','netflix.com','spotify.com',
    'twitch.tv','medium.com','substack.com',
    'discord.com','slack.com','notion.so','figma.com',
    'canva.com','dropbox.com','zoom.us','atlassian.com',
    'trello.com','asana.com','hubspot.com','salesforce.com',
}

PHISHING_WEIGHTS = {'rf_gb': 0.35, 'lstm': 0.35, 'hf_phishing': 0.30}
PHISHING_THRESHOLD   = 0.55
SUSPICIOUS_THRESHOLD = 0.35


# ════════════════════════════════════════════════════════════
# PYDANTIC REQUEST MODELS
# ════════════════════════════════════════════════════════════

class AuthRequest(BaseModel):
    api_key: str

class PredictRequest(BaseModel):
    url: str
    skip_hf: bool = False

class TrancoRequest(BaseModel):
    url: str

class QRScanRect(BaseModel):
    x: float; y: float; w: float; h: float
    sw: float = 0.0; sh: float = 0.0

class QRScanRequest(BaseModel):
    image: str
    rect:  Optional[QRScanRect] = None


# ════════════════════════════════════════════════════════════
# APPLICATION STATE  (populated at startup)
# ════════════════════════════════════════════════════════════

class AppState:
    rf_model       = None
    gb_model       = None
    scaler         = None
    lstm_model     = None
    lstm_tokenizer = None
    lstm_config    = {}
    rf_metrics     = {}
    tranco_domains: set = set()
    tranco_loaded: bool = False
    http_client: httpx.AsyncClient = None

state = AppState()


# ════════════════════════════════════════════════════════════
# LIFESPAN  (startup / shutdown)
# ════════════════════════════════════════════════════════════

TRANCO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'tranco_9WXQ2.csv')

def _load_models_sync():
    """Blocking model load — called via asyncio.to_thread."""
    print("=" * 55)
    print("  WebSentinel ML API v4 — Starting...")
    print("=" * 55)

    try:
        state.rf_model = joblib.load('models/random_forest.pkl')
        state.scaler   = joblib.load('models/scaler_rf.pkl')
        print("  ✅ Random Forest loaded")
    except Exception as e:
        print(f"  ⚠️  RF: {e}")

    try:
        state.gb_model = joblib.load('models/gradient_boosting.pkl')
        print("  ✅ Gradient Boosting loaded")
    except Exception as e:
        print(f"  ⚠️  GB: {e}")

    try:
        from tensorflow.keras.models import load_model
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        state.lstm_model     = load_model('models/lstm_model.keras')
        state.lstm_tokenizer = joblib.load('models/lstm_tokenizer.pkl')
        with open('models/lstm_config.json') as f:
            state.lstm_config = json.load(f)
        print("  ✅ LSTM loaded")
    except Exception as e:
        print(f"  ⚠️  LSTM: {e}")

    try:
        with open('models/rf_metrics.json') as f:
            state.rf_metrics = json.load(f)
    except:
        pass

    print(f"  HuggingFace token: ✅ {HF_API_TOKEN[:12]}...")
    print("=" * 55)


def _load_tranco_sync():
    try:
        with open(TRANCO_PATH, 'r', encoding='utf-8') as f:
            for row in csv.reader(f):
                if len(row) >= 2:
                    state.tranco_domains.add(row[1].strip().lower())
        state.tranco_loaded = True
        print(f"  ✅ Tranco list loaded: {len(state.tranco_domains):,} domains")
    except Exception as e:
        print(f"  ⚠️  Tranco load failed: {e}")
        state.tranco_loaded = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — load models and Tranco list concurrently
    state.http_client = httpx.AsyncClient()
    await asyncio.gather(
        asyncio.to_thread(_load_models_sync),
        asyncio.to_thread(_load_tranco_sync),
    )
    yield
    # Shutdown
    await state.http_client.aclose()


# ════════════════════════════════════════════════════════════
# APP
# ════════════════════════════════════════════════════════════

app = FastAPI(title="WebSentinel ML API", version="4.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ════════════════════════════════════════════════════════════
# HELPERS — domain / URL utils
# ════════════════════════════════════════════════════════════

def _is_trusted_domain(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or '').lower().replace('www.', '')
        return any(host == d or host.endswith('.' + d) for d in HF_SKIP_DOMAINS)
    except:
        return False

def _extract_domain_for_hf(url: str) -> str:
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except:
        return url

def _is_in_tranco(url: str) -> bool:
    try:
        host  = (urlparse(url).hostname or '').lower().replace('www.', '')
        parts = host.split('.')
        root  = '.'.join(parts[-2:]) if len(parts) >= 2 else host
        return host in state.tranco_domains or root in state.tranco_domains
    except:
        return False


# ════════════════════════════════════════════════════════════
# HELPERS — HuggingFace  (async)
# ════════════════════════════════════════════════════════════

async def _hf_post(model: str, text: str):
    url     = HF_API_URL.format(model=model)
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}", "Content-Type": "application/json"}
    for attempt in range(2):
        try:
            resp = await state.http_client.post(url, json={"inputs": text}, headers=headers, timeout=HF_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 503 and attempt == 0:
                print("  [HF] Model loading — waiting 4s...")
                await asyncio.sleep(4)
                continue
            print(f"  [HF:{model.split('/')[-1]}] HTTP {resp.status_code}: {resp.text[:150]}")
            return None
        except Exception as e:
            print(f"  [HF:{model.split('/')[-1]}] Error: {e}")
            return None
    return None

def _parse_labels(data) -> dict:
    if not isinstance(data, list) or not data:
        return {}
    inner = data[0] if isinstance(data[0], list) else data
    return {i['label'].lower(): float(i['score']) for i in inner if 'label' in i and 'score' in i}


# ════════════════════════════════════════════════════════════
# HELPERS — local ML  (sync, run in thread)
# ════════════════════════════════════════════════════════════

def _predict_rf_sync(url: str):
    if not state.rf_model or not state.scaler:
        return None
    try:
        feats  = extract_features(url)
        scaled = state.scaler.transform([feats])
        rf_p   = float(state.rf_model.predict_proba(scaled)[0][1])
        if state.gb_model:
            gb_p = float(state.gb_model.predict_proba(scaled)[0][1])
            return round(rf_p * 0.6 + gb_p * 0.4, 4)
        return round(rf_p, 4)
    except Exception as e:
        print(f"  RF error: {e}")
        return None

def _predict_lstm_sync(url: str):
    if not state.lstm_model or not state.lstm_tokenizer:
        return None
    try:
        from tensorflow.keras.preprocessing.sequence import pad_sequences
        max_len = state.lstm_config.get('max_url_length', 200)
        seq     = state.lstm_tokenizer.texts_to_sequences([url])
        padded  = pad_sequences(seq, maxlen=max_len, padding='post', truncating='post')
        return round(float(state.lstm_model.predict(padded, verbose=0)[0][0]), 4)
    except Exception as e:
        print(f"  LSTM error: {e}")
        return None


async def predict_rf(url: str):
    return await asyncio.to_thread(_predict_rf_sync, url)

async def predict_lstm(url: str):
    return await asyncio.to_thread(_predict_lstm_sync, url)

async def predict_hf_phishing(url: str):
    if _is_trusted_domain(url):
        print("  [HF-Phishing] Trusted domain — skipping")
        return None
    domain_only = _extract_domain_for_hf(url)
    print(f"  [HF-Phishing] Sending: {domain_only}")
    data = await _hf_post(HF_PHISHING_MODEL, domain_only)
    if data is None:
        return None
    ls   = _parse_labels(data)
    if not ls:
        return None
    prob = (ls.get('phishing') or ls.get('label_1') or
            (1.0 - ls.get('benign', 1.0)) or
            (1.0 - ls.get('legitimate', 1.0)) or
            (1.0 - ls.get('label_0', 1.0)) or 0.0)
    prob = round(float(prob), 4)
    print(f"  [HF-Phishing] ✅ labels={ls} → prob={prob:.4f}")
    return prob

def ensemble_phishing_predict(rf_prob, lstm_prob, hf_prob):
    sources = []
    if rf_prob   is not None: sources.append((rf_prob,   PHISHING_WEIGHTS['rf_gb']))
    if lstm_prob is not None: sources.append((lstm_prob, PHISHING_WEIGHTS['lstm']))
    if hf_prob   is not None: sources.append((hf_prob,   PHISHING_WEIGHTS['hf_phishing']))
    if not sources:
        return None, 'unknown'
    total_w  = sum(w for _, w in sources)
    combined = round(sum(p * w for p, w in sources) / total_w, 4)
    label = ('phishing'   if combined >= PHISHING_THRESHOLD   else
             'suspicious' if combined >= SUSPICIOUS_THRESHOLD else 'legitimate')
    return combined, label

# ════════════════════════════════════════════════════════════
# ROUTES
# ════════════════════════════════════════════════════════════

@app.post('/auth')
async def auth(body: AuthRequest):
    """Exchange API key for a short-lived JWT token."""
    if body.api_key != EXTENSION_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    token = _create_token()
    return {"token": token, "expires_in": JWT_EXPIRE_HOURS * 3600, "token_type": "bearer"}


@app.get('/health')
async def health():
    return {
        'status': 'running', 'version': '4.0', 'framework': 'FastAPI',
        'hf_token_set': bool(HF_API_TOKEN),
        'models': {
            'random_forest': state.rf_model is not None,
            'lstm': state.lstm_model is not None,
            'hf_phishing': True
        },
        'tranco_loaded': state.tranco_loaded,
        'tranco_size':   len(state.tranco_domains),
        'rf_metrics': state.rf_metrics,
        'weights': {'phishing': PHISHING_WEIGHTS}
    }


@app.get('/info')
async def info():
    return {
        'random_forest': state.rf_metrics,
        'lstm': state.lstm_config,
        'features': get_feature_names(),
        'feature_count': len(get_feature_names()),
        'hf_models': {'phishing': HF_PHISHING_MODEL},
        'weights': {'phishing': PHISHING_WEIGHTS},
        'hf_skip_domains': list(HF_SKIP_DOMAINS)
    }


@app.post('/predict', dependencies=[Depends(require_auth)])
async def predict(body: PredictRequest):
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Empty url")

    print(f"\n  🔍 Predicting: {url[:70]}")
    trusted = _is_trusted_domain(url)
    print(f"  Trusted domain: {trusted}")

    # Run RF/LSTM concurrently; HF only if not skip_hf
    if body.skip_hf:
        rf_prob, lstm_prob, hf_prob = await asyncio.gather(
            predict_rf(url), predict_lstm(url), asyncio.sleep(0, result=None)
        )
        hf_prob = None
    else:
        rf_prob, lstm_prob, hf_prob = await asyncio.gather(
            predict_rf(url), predict_lstm(url), predict_hf_phishing(url)
        )

    print(f"  Scores — RF/GB:{rf_prob}  LSTM:{lstm_prob}  HF:{'skipped' if body.skip_hf else hf_prob}")

    final_prob, final_label = ensemble_phishing_predict(rf_prob, lstm_prob, hf_prob)
    ml_score = round((final_prob or 0) * 100)

    if trusted and ml_score > 15:
        print(f"  [Trust Override] Capping {ml_score} → 15")
        ml_score, final_prob, final_label = 15, 0.15, 'legitimate'

    feature_flags = []
    if state.rf_model and state.scaler:
        try:
            feats      = await asyncio.to_thread(extract_features, url)
            feat_names = get_feature_names()
            imps       = state.rf_model.feature_importances_
            for name, val, imp in zip(feat_names, feats, imps):
                if val > 0 and imp > 0.02:
                    feature_flags.append({'feature': name, 'value': round(float(val), 4), 'importance': round(float(imp), 4)})
            feature_flags.sort(key=lambda x: x['importance'], reverse=True)
            feature_flags = feature_flags[:5]
        except:
            pass

    print(f"  ✅ {final_label} ({ml_score}/100)")
    return {
        'url': url, 'prediction': final_label, 'ml_score': ml_score,
        'confidence': round(final_prob or 0, 4),
        'rf_score':   round((rf_prob   or 0) * 100) if rf_prob   is not None else None,
        'lstm_score': round((lstm_prob or 0) * 100) if lstm_prob is not None else None,
        'hf_score':   round((hf_prob   or 0) * 100) if hf_prob   is not None else None,
        'hf_skipped': trusted, 'trusted_domain': trusted,
        'top_features': feature_flags,
        'models_used': {'random_forest': rf_prob is not None, 'lstm': lstm_prob is not None, 'hf_phishing': hf_prob is not None},
        'weights': PHISHING_WEIGHTS
    }


@app.post('/check-tranco', dependencies=[Depends(require_auth)])
async def check_tranco(body: TrancoRequest):
    url  = body.url.strip()
    host = (urlparse(url).hostname or '').lower().replace('www.', '')
    parts = host.split('.')
    root  = '.'.join(parts[-2:]) if len(parts) >= 2 else host

    in_tranco  = host in state.tranco_domains or root in state.tranco_domains
    risk_score = 0 if in_tranco else 15

    return {
        'domain': host, 'in_tranco': in_tranco,
        'risk_score': risk_score, 'tranco_loaded': state.tranco_loaded,
        'details': 'Tranco top site — high reputation' if in_tranco else 'Not in Tranco top sites (+15 risk)'
    }


@app.post('/scan-qr', dependencies=[Depends(require_auth)])
async def scan_qr(body: QRScanRequest):
    """Decode QR code from a base64 PNG screenshot using OpenCV."""
    try:
        img_b64 = body.image
        if ',' in img_b64:
            img_b64 = img_b64.split(',', 1)[1]

        img_bytes = base64.b64decode(img_b64)

        def _decode_qr() -> Optional[str]:
            nparr  = np.frombuffer(img_bytes, np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img_cv is None:
                return None
            h_full, w_full = img_cv.shape[:2]
            detector = cv2.QRCodeDetector()

            candidates = []
            if body.rect:
                r  = body.rect
                sw = r.sw or w_full; sh = r.sh or h_full
                sx = w_full / sw;    sy = h_full / sh
                x  = int(r.x * sx); y  = int(r.y * sy)
                cw = int(r.w * sx); ch = int(r.h * sy)
                pad_x = int(cw * 0.25); pad_y = int(ch * 0.25)
                x1 = max(0, x - pad_x); y1 = max(0, y - pad_y)
                x2 = min(w_full, x + cw + pad_x); y2 = min(h_full, y + ch + pad_y)
                candidates.append(img_cv[y1:y2, x1:x2])
            candidates.append(img_cv)

            for candidate in candidates:
                text, _, _ = detector.detectAndDecode(candidate)
                if text:
                    print(f'[scan-qr] opencv decoded: {text[:80]}')
                    return text
            print('[scan-qr] no QR code found')
            return None

        decoded = await asyncio.to_thread(_decode_qr)
        return {"decoded": decoded, "method": "opencv"}

    except Exception as e:
        print(f'[scan-qr] ERROR: {e}\n{traceback.format_exc()}')
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/test')
async def test():
    urls = [
        'https://www.google.com',
        'http://paypal-secure-login.xyz/verify',
        'http://192.168.1.1/admin',
        'https://www.amazon.com',
        'https://mail.google.com/mail/u/0/#inbox'
    ]
    results = []
    for url in urls:
        rf_p, lstm_p, hf_p = await asyncio.gather(
            predict_rf(url), predict_lstm(url), predict_hf_phishing(url)
        )
        prob, label = ensemble_phishing_predict(rf_p, lstm_p, hf_p)
        results.append({'url': url, 'prediction': label, 'score': round((prob or 0) * 100),
                        'rf': rf_p, 'lstm': lstm_p, 'hf': hf_p, 'hf_skipped': _is_trusted_domain(url)})
    return {'test_results': results}


# ════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import uvicorn
    print("\n  🚀 WebSentinel API v4 running at http://localhost:5000")
    print("  POST /auth         — get JWT token")
    print("  POST /predict      — phishing detection  [JWT]")
    print("  POST /check-tranco — Tranco lookup        [JWT]")
    print("  POST /scan-qr      — QR code decode       [JWT]")
    print("  GET  /health       — status\n")
    uvicorn.run("api:app", host="0.0.0.0", port=5000, reload=False)
