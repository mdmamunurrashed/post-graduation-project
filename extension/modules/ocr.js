// ============================================================
// WebSentinel — ocr.js
// Screenshot capture and QR screenshot decoding
// ============================================================

import { WEBSENTINEL_CONFIG } from './config.js';
import { URLAnalyzer } from './url-analyzer.js';
import { ThreatIntelEngine } from './threat-intel.js';
import { DecisionFusionEngine } from './fusion-engine.js';
import { authFetch } from './auth.js';

export async function captureScreenshot() {
  try { return await chrome.tabs.captureVisibleTab(null, {format:'png', quality:90}); }
  catch(e) { console.error('[OCR] Screenshot:', e.message); return null; }
}

export async function scanQRFromScreenshot(tabId, screenshotDataUrl) {
  try {
    const resp = await authFetch(WEBSENTINEL_CONFIG.QR_SCAN_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({image: screenshotDataUrl}),
      signal: AbortSignal.timeout(8000)
    });
    if (!resp.ok) return;
    const qrData  = await resp.json();
    const decoded = qrData.decoded;
    if (!decoded || !/^https?:\/\//i.test(decoded.trim())) return;
    const url      = decoded.trim();
    console.log('[QR-Screenshot] Decoded URL:', url);
    const heuristic = new URLAnalyzer(url).analyze();
    const intel     = await new ThreatIntelEngine(url).analyze().catch(() => null);
    const fused     = DecisionFusionEngine.fuse(heuristic, intel, null, null);
    await chrome.storage.local.set({latest_qr_scan:{...fused,url,hostname:heuristic.hostname,scan_type:'qr_screenshot',heuristicResult:heuristic,intelResult:intel,timestamp:new Date().toISOString()}});
    if (fused.level === 'PHISHING' || fused.level === 'SUSPICIOUS') {
      const nId = `qr_sc_${Date.now()}`;
      chrome.notifications.create(nId,{type:'basic',iconUrl:'icons/icon128.png',title:`${fused.emoji} QR in Chat — WebSentinel`,message:`QR → ${fused.level}: ${url.slice(0,60)}\nScore: ${fused.finalScore}/100`,priority:fused.level==='PHISHING'?2:1,requireInteraction:false});
      setTimeout(() => chrome.notifications.clear(nId), fused.level === 'PHISHING' ? 8000 : 5000);
    }
  } catch(e) { console.error('[QR-Screenshot]', e.message); }
}
