// ============================================================
// WebSentinel — auth.js
// JWT token management for backend API calls
// ============================================================

import { WEBSENTINEL_CONFIG } from './config.js';

const TOKEN_KEY  = 'ws_jwt_token';
const EXPIRY_KEY = 'ws_jwt_expiry';

/**
 * Returns a valid JWT bearer token, fetching a new one if needed.
 * Caches the token in chrome.storage.local.
 */
export async function getAuthToken() {
  const s = await chrome.storage.local.get([TOKEN_KEY, EXPIRY_KEY]);
  // Return cached token if still valid (60s buffer before expiry)
  if (s[TOKEN_KEY] && s[EXPIRY_KEY] && Date.now() < s[EXPIRY_KEY] - 60_000) {
    return s[TOKEN_KEY];
  }
  return _fetchToken();
}

async function _fetchToken() {
  try {
    const resp = await fetch(WEBSENTINEL_CONFIG.AUTH_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ api_key: WEBSENTINEL_CONFIG.EXTENSION_API_KEY }),
      signal:  AbortSignal.timeout(3000)
    });
    if (!resp.ok) throw new Error(`Auth HTTP ${resp.status}`);
    const data      = await resp.json();
    const expiresMs = (data.expires_in || 3600) * 1000;
    await chrome.storage.local.set({
      [TOKEN_KEY]:  data.token,
      [EXPIRY_KEY]: Date.now() + expiresMs
    });
    return data.token;
  } catch(e) {
    console.warn('[Auth] Token fetch failed:', e.message);
    return null;
  }
}

/**
 * fetch() wrapper that injects Authorization: Bearer <token>.
 * On 401 it clears the cached token, re-authenticates, and retries once.
 */
export async function authFetch(url, options = {}) {
  const token = await getAuthToken();

  const withAuth = (tok, opts) => ({
    ...opts,
    headers: { ...(opts.headers || {}), ...(tok ? { 'Authorization': `Bearer ${tok}` } : {}) }
  });

  const resp = await fetch(url, withAuth(token, options));

  if (resp.status === 401) {
    // Token rejected — clear and re-authenticate once
    await chrome.storage.local.remove([TOKEN_KEY, EXPIRY_KEY]);
    const fresh = await _fetchToken();
    return fetch(url, withAuth(fresh, options));
  }

  return resp;
}
