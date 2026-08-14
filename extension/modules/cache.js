// ============================================================
// WebSentinel — cache.js
// URL scan result caching in chrome.storage.local
// ============================================================

import { WEBSENTINEL_CONFIG } from './config.js';

export const NEVER_CACHE_DOMAINS = [
  'mail.google.com','gmail.com','google.com','accounts.google.com',
  'drive.google.com','docs.google.com','notebooklm.google.com',
  'youtube.com','facebook.com','instagram.com','twitter.com','x.com',
  'linkedin.com','microsoft.com','live.com','outlook.com','office.com',
  'apple.com','icloud.com','amazon.com','github.com','reddit.com','wikipedia.org'
];

export function _cacheKey(url) {
  try { return `cache_${btoa(url).slice(0, 50)}`; } catch(_) { return null; }
}

export function _shouldSkipCache(url) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return NEVER_CACHE_DOMAINS.some(d => host === d || host.endsWith('.' + d));
  } catch(_) { return false; }
}

export async function clearCacheForUrl(url) {
  const key = _cacheKey(url);
  if (key) await chrome.storage.local.remove(key);
}

export async function clearAllCache() {
  const all  = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(k => k.startsWith('cache_'));
  if (keys.length) await chrome.storage.local.remove(keys);
  return keys.length;
}
