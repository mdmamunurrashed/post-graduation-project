// ============================================================
// WebSentinel — message-handler.js
// All chrome.runtime.onMessage handlers in one place
// ============================================================

import { WEBSENTINEL_CONFIG } from './config.js';
import { URLAnalyzer } from './url-analyzer.js';
import { ThreatIntelEngine } from './threat-intel.js';
import { SSLInspector } from './ssl-inspector.js';
import { DecisionFusionEngine } from './fusion-engine.js';
import { clearCacheForUrl, clearAllCache } from './cache.js';
import { isExtensionEnabled, isScreenshotEnabled } from './state.js';
import { getBehaviorData, storeResult, handleThreatResponse, updateBadge } from './helpers.js';
import { isWhitelisted, addToWhitelist, removeFromWhitelist } from './whitelist.js';
import { captureScreenshot } from './ocr.js';
import { authFetch } from './auth.js';

export function registerMessageHandler() {
  chrome.runtime.onMessage.addListener((msg, sender, respond) => {

    if (msg.type === 'OPEN_TAB') {
      chrome.tabs.create({url: msg.url, active: true});
      respond({ok: true});
      return true;
    }

    if (msg.type === 'GET_SCREENSHOT_ENABLED') {
      isScreenshotEnabled().then(e => respond({enabled: e}));
      return true;
    }
    if (msg.type === 'SET_SCREENSHOT_ENABLED') {
      chrome.storage.local.set({screenshotEnabled: msg.enabled}).then(() => respond({ok: true}));
      return true;
    }

    // QR hover scan — screenshot sent to Python backend for OpenCV decoding
    if (msg.type === 'SCAN_QR_HOVER') {
      const tabId = sender.tab?.id;
      if (!tabId) { respond(null); return true; }
      (async () => {
        try {
          if (!await isScreenshotEnabled()) { respond({disabled: true}); return; }
          const screenshot = await captureScreenshot();
          if (!screenshot) { respond(null); return; }

          const resp = await authFetch(WEBSENTINEL_CONFIG.QR_SCAN_ENDPOINT, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({image: screenshot, rect: {x:msg.rect.x,y:msg.rect.y,w:msg.rect.w,h:msg.rect.h,sw:msg.rect.sw||0,sh:msg.rect.sh||0}}),
            signal: AbortSignal.timeout(4000)
          });
          if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            console.error('[QR-Hover] /scan-qr error', resp.status, err);
            respond({notQR: true}); return;
          }
          const qrData  = await resp.json();
          const decoded = qrData.decoded;
          if (!decoded) { respond({notQR: true}); return; }

          let raw = decoded.trim();
          if (!/^https?:\/\//i.test(raw)) {
            if (/^[^\s]+\.[^\s]{2,}/.test(raw)) raw = 'https://' + raw;
            else { respond({text: raw, url: null}); return; }
          }
          const url       = raw;
          const heuristic = new URLAnalyzer(url).analyze();
          const intel     = await new ThreatIntelEngine(url).analyze().catch(() => null);
          const fused     = DecisionFusionEngine.fuse(heuristic, intel, null, null);
          chrome.storage.local.set({latest_qr_scan:{...fused,url,hostname:heuristic.hostname,scan_type:'qr_hover',timestamp:new Date().toISOString()}});
          respond({url, score: fused.finalScore, level: fused.level});
          if (fused.level === 'PHISHING' || fused.level === 'SUSPICIOUS') {
            const nId = `qr_h_${Date.now()}`;
            chrome.notifications.create(nId,{type:'basic',iconUrl:'icons/icon128.png',title:`${fused.emoji} QR in Chat — WebSentinel`,message:`QR → ${fused.level}: ${url.slice(0,60)}\nScore: ${fused.finalScore}/100`,priority:fused.level==='PHISHING'?2:1,requireInteraction:false});
            setTimeout(() => chrome.notifications.clear(nId), 6000);
          }
        } catch(e) { console.error('[QR-Hover]', e.message); respond(null); }
      })();
      return true;
    }

    // ML scan for link tooltip — full pipeline including HF
    if (msg.type === 'ML_SCAN_TOOLTIP') {
      if (!WEBSENTINEL_CONFIG.ML_API_ENABLED) { respond(null); return true; }
      authFetch(WEBSENTINEL_CONFIG.ML_API_ENDPOINT, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:msg.url,skip_hf:false}),signal:AbortSignal.timeout(8000)})
        .then(r => r.ok ? r.json() : null).then(d => respond(d)).catch(() => respond(null));
      return true;
    }

    if (msg.type === 'FULL_MANUAL_SCAN') {
      (async () => {
        try {
          const { url } = msg;
          const heuristic = new URLAnalyzer(url).analyze();
          const [intelRes, sslRes] = await Promise.allSettled([
            new ThreatIntelEngine(url).analyze(),
            new SSLInspector(url).analyze()
          ]);
          const intel = intelRes.status === 'fulfilled' ? intelRes.value : null;
          const ssl   = sslRes.status  === 'fulfilled' ? sslRes.value   : null;
          const final = DecisionFusionEngine.fuse(heuristic, intel, ssl, null);
          respond({...final, url, hostname: heuristic.hostname, heuristicResult: heuristic, intelResult: intel, sslResult: ssl, recommendation: DecisionFusionEngine.getRecommendation(final)});
        } catch(e) { respond({error: e.message}); }
      })();
      return true;
    }

    if (msg.type === 'SCAN_QR_IMAGE') {
      (async () => {
        try {
          const resp = await authFetch(WEBSENTINEL_CONFIG.QR_SCAN_ENDPOINT, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({image: msg.imageData}),
            signal: AbortSignal.timeout(8000)
          });
          if (!resp.ok) { respond({error:'API error'}); return; }
          const data = await resp.json();
          if (!data.decoded) { respond({error:'No QR code found in image'}); return; }
          const raw = data.decoded.trim();
          const url = /^https?:\/\//i.test(raw) ? raw : /^[^\s]+\.[^\s]{2,}/.test(raw) ? 'https://'+raw : null;
          if (!url) { respond({error:'QR does not contain a URL'}); return; }
          const heuristic = new URLAnalyzer(url).analyze();
          const [intelRes, sslRes] = await Promise.allSettled([
            new ThreatIntelEngine(url).analyze(),
            new SSLInspector(url).analyze()
          ]);
          const intel = intelRes.status === 'fulfilled' ? intelRes.value : null;
          const ssl   = sslRes.status  === 'fulfilled' ? sslRes.value   : null;
          const final = DecisionFusionEngine.fuse(heuristic, intel, ssl, null);
          respond({url, ...final, heuristicResult: heuristic, intelResult: intel, sslResult: ssl});
        } catch(e) { respond({error: e.message}); }
      })();
      return true;
    }

    if (msg.type === 'GET_CURRENT_RESULT') {
      const key = msg.tabId ? `tab_${msg.tabId}` : 'currentResult';
      chrome.storage.local.get(key, d => respond(d[key] || null));
      return true;
    }
    if (msg.type === 'GET_HISTORY')        { chrome.storage.local.get('history', d => respond(d.history || [])); return true; }
    if (msg.type === 'MANUAL_SCAN')        { respond(new URLAnalyzer(msg.url).analyze()); return true; }

    if (msg.type === 'CLEAR_CACHE') {
      (msg.url ? clearCacheForUrl(msg.url).then(() => ({cleared:true,url:msg.url})) : clearAllCache().then(n => ({cleared:true,count:n}))).then(r => respond(r));
      return true;
    }

    if (msg.type === 'FORCE_RESCAN') {
      chrome.tabs.query({active:true,currentWindow:true}, async ([tab]) => {
        if (!tab?.url) { respond({error:'No active tab'}); return; }
        await chrome.storage.local.set({extensionEnabled: true});
        const {url, id: tabId} = tab;
        await clearCacheForUrl(url);
        await chrome.storage.local.remove([`tab_${tabId}`, 'currentResult']);
        chrome.action.setBadgeText({text:'...', tabId});
        chrome.action.setBadgeBackgroundColor({color:'#555555', tabId});
        respond({started: true, url});
        try {
          const heuristic = new URLAnalyzer(url).analyze();
          await storeResult({...heuristic, status:'partial', phase:'heuristic'}, tabId);
          const [ir, sr] = await Promise.allSettled([new ThreatIntelEngine(url).analyze(), new SSLInspector(url).analyze()]);
          const intel    = ir.status === 'fulfilled' ? ir.value : null;
          const ssl      = sr.status === 'fulfilled' ? sr.value : null;
          const behavior = await getBehaviorData(url);
          const final    = DecisionFusionEngine.fuse(heuristic, intel, ssl, behavior);
          const result   = {url,hostname:new URL(url).hostname,...final,heuristicResult:heuristic,intelResult:intel,sslResult:ssl,recommendation:DecisionFusionEngine.getRecommendation(final),status:'complete',timestamp:new Date().toISOString(),scanDate:new Date().toLocaleDateString(),forced_rescan:true};
          await storeResult(result, tabId);
          await handleThreatResponse(result, tabId);
          updateBadge(result, tabId);
        } catch(e) { console.error('[RESCAN]', e); chrome.action.setBadgeText({text:'ERR', tabId}); }
      });
      return true;
    }

    if (msg.type === 'SET_EXTENSION_ENABLED') {
      chrome.storage.local.set({extensionEnabled: msg.enabled}).then(() => {
        respond({ok: true, enabled: msg.enabled});
        chrome.tabs.query({}, tabs => {
          tabs.forEach(t => {
            if (msg.enabled) { chrome.action.setBadgeText({text:'', tabId:t.id}); }
            else { chrome.action.setBadgeText({text:'OFF',tabId:t.id}); chrome.action.setBadgeBackgroundColor({color:'#555555',tabId:t.id}); }
          });
        });
      });
      return true;
    }
    if (msg.type === 'GET_EXTENSION_ENABLED') {
      isExtensionEnabled().then(e => respond({enabled: e}));
      return true;
    }

    // Whitelist
    if (msg.type === 'ADD_TO_WHITELIST')    { addToWhitelist(msg.hostname).then(l => respond({success:true,whitelist:l})); return true; }
    if (msg.type === 'REMOVE_FROM_WHITELIST') { removeFromWhitelist(msg.hostname).then(l => respond({success:true,whitelist:l})); return true; }
    if (msg.type === 'GET_WHITELIST')       { chrome.storage.local.get('userWhitelist', d => respond({whitelist:d.userWhitelist||[]})); return true; }

  });
}
