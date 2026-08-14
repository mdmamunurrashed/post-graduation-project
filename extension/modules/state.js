// ============================================================
// WebSentinel — state.js
// Extension on/off toggle state
// ============================================================

export async function isExtensionEnabled() {
  const d = await chrome.storage.local.get('extensionEnabled');
  return d.extensionEnabled !== false; // default: enabled
}

export async function isScreenshotEnabled() {
  const d = await chrome.storage.local.get('screenshotEnabled');
  return d.screenshotEnabled === true; // default: off
}
