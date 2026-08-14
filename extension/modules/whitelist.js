// ============================================================
// WebSentinel — whitelist.js
// User-managed domain whitelist stored in chrome.storage.local
// ============================================================

export async function isWhitelisted(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    const d = await chrome.storage.local.get('userWhitelist');
    return (d.userWhitelist || []).some(e => h === e || h.endsWith('.' + e));
  } catch(_) { return false; }
}

export async function addToWhitelist(hostname) {
  const d  = await chrome.storage.local.get('userWhitelist');
  const wl = d.userWhitelist || [];
  const c  = hostname.toLowerCase().replace(/^www\./, '');
  if (!wl.includes(c)) { wl.push(c); await chrome.storage.local.set({userWhitelist: wl}); }
  return wl;
}

export async function removeFromWhitelist(hostname) {
  const d  = await chrome.storage.local.get('userWhitelist');
  const wl = (d.userWhitelist || []).filter(h => h !== hostname);
  await chrome.storage.local.set({userWhitelist: wl});
  return wl;
}
