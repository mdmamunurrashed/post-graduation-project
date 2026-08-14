// ============================================================
// WebSentinel — background.js  (entry point — ES module)
// All logic lives in ./modules/; this file wires listeners.
// ============================================================

import { isExtensionEnabled }                          from './modules/state.js';
import { clearCacheForUrl }                            from './modules/cache.js';
import { isWhitelisted }                               from './modules/whitelist.js';
import { URLAnalyzer }                                 from './modules/url-analyzer.js';
import { ThreatIntelEngine }                           from './modules/threat-intel.js';
import { SSLInspector }                                from './modules/ssl-inspector.js';
import { DecisionFusionEngine }                        from './modules/fusion-engine.js';
import { getBehaviorData, storeResult,
         handleThreatResponse, updateBadge }           from './modules/helpers.js';
import { checkForSpam, analyzeAndShowSpam }            from './modules/spam-guard.js';
import { showRedirectWarning,
         showNewTabBlockedBanner }                     from './modules/banners.js';
import { registerMessageHandler }                      from './modules/message-handler.js';

// ════════════════════════════════════════════════════════════
// REDIRECT TRACKER  (cross-origin redirect detection)
// ════════════════════════════════════════════════════════════

const tabOriginalUrls = {};
const tabLoadTimes    = {};   // tabId → ms timestamp of last onCompleted
const pendingNewTabs  = {};   // newTabId → sourceTabId

const rootDomain = h => { try { return h.split('.').slice(-2).join('.'); } catch(_) { return h; } };

chrome.webNavigation.onBeforeNavigate.addListener(d => {
  if (d.frameId !== 0) return;
  // If this is a tracked new tab navigating to a real URL, block it early
  if (pendingNewTabs[d.tabId] !== undefined) {
    const sourceTabId = pendingNewTabs[d.tabId];
    delete pendingNewTabs[d.tabId];
    if (d.url && d.url !== 'about:blank' && !d.url.startsWith('chrome://')) {
      blockNewTab(sourceTabId, d.tabId, d.url);
    }
    return;
  }
  tabOriginalUrls[d.tabId] = d.url;
  chrome.storage.local.remove(`redirect_${d.tabId}`);
});

chrome.webNavigation.onCommitted.addListener(async d => {
  if (d.frameId !== 0) return;
  if (!(await isExtensionEnabled())) return;
  const orig = tabOriginalUrls[d.tabId], newUrl = d.url;
  if (!orig || !newUrl) return;
  if (newUrl.startsWith('chrome://') || newUrl.startsWith('edge://') || newUrl.startsWith('about:')) return;
  try {
    const oH = new URL(orig).hostname, nH = new URL(newUrl).hostname;
    if (oH === nH || rootDomain(oH) === rootDomain(nH)) return;
    if (await isWhitelisted(newUrl)) return;

    // Catch: server/client redirects OR any cross-origin nav within 5s of page load (JS timer redirects)
    const qualifiers   = d.transitionQualifiers || [];
    const isRedirect   = qualifiers.includes('server_redirect') || qualifiers.includes('client_redirect');
    const isQuickNav   = tabLoadTimes[d.tabId] && (Date.now() - tabLoadTimes[d.tabId]) < 5000;
    if (!isRedirect && !isQuickNav) return;

    chrome.scripting.executeScript({ target: { tabId: d.tabId }, func: showRedirectWarning, args: [oH, nH, newUrl, orig] }).catch(() => {});
    chrome.storage.local.set({ [`redirect_${d.tabId}`]: { from: oH, to: nH } });
    delete tabOriginalUrls[d.tabId];
  } catch(e) { console.log('[Redirect]', e); }
});

chrome.tabs.onRemoved.addListener(id => {
  delete tabOriginalUrls[id];
  delete tabLoadTimes[id];
  delete pendingNewTabs[id];
});

// ════════════════════════════════════════════════════════════
// NEW-TAB REDIRECT BLOCKER
// ════════════════════════════════════════════════════════════

chrome.webNavigation.onCreatedNavigationTarget.addListener(async d => {
  if (!(await isExtensionEnabled())) return;
  const { sourceTabId, tabId: newTab, url: newUrl } = d;
  if (newUrl.startsWith('chrome://') || newUrl.startsWith('edge://')) return;
  // Always track; onBeforeNavigate will fire next and close it early
  pendingNewTabs[newTab] = sourceTabId;
  // If URL is already real (not blank), block immediately
  if (newUrl && newUrl !== 'about:blank') {
    delete pendingNewTabs[newTab];
    await blockNewTab(sourceTabId, newTab, newUrl);
  }
});

async function blockNewTab(sourceTabId, newTab, newUrl) {
  try {
    const src = await chrome.tabs.get(sourceTabId).catch(() => null);
    if (!src?.url) return;
    const sH = new URL(src.url).hostname, nH = new URL(newUrl).hostname;
    if (sH === nH || rootDomain(sH) === rootDomain(nH)) return;
    if (await isWhitelisted(newUrl)) return;
    await chrome.tabs.remove(newTab).catch(() => {});
    chrome.scripting.executeScript({ target: { tabId: sourceTabId }, func: showNewTabBlockedBanner, args: [sH, nH, newUrl] }).catch(() => {});
  } catch(e) { console.log('[NewTab]', e); }
}

// ════════════════════════════════════════════════════════════
// MAIN SCAN PIPELINE  (fires when page finishes loading)
// ════════════════════════════════════════════════════════════

chrome.webNavigation.onCompleted.addListener(async d => {
  if (d.frameId !== 0) return;
  const { url, tabId } = d;
  tabLoadTimes[tabId] = Date.now();
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') ||
      url.startsWith('about:')    || url.startsWith('edge://')) return;

  if (!(await isExtensionEnabled())) {
    chrome.action.setBadgeText({ text: 'OFF', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#555555', tabId });
    return;
  }

  if (url.startsWith('file://')) {
    setTimeout(() => chrome.scripting.executeScript({ target: { tabId }, func: analyzeAndShowSpam, args: [null, null, null] }).catch(() => {}), 2500);
    return;
  }

  if (await isWhitelisted(url)) {
    chrome.action.setBadgeText({ text: 'OK', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#4CAF50', tabId });
    await chrome.storage.local.set({ currentResult: { url, hostname: new URL(url).hostname, level: 'WHITELISTED', finalScore: 0, score: 0, allFlags: ['Whitelisted — scanning skipped'], flags: ['Whitelisted — scanning skipped'], status: 'complete', whitelisted: true } });
    return;
  }

  chrome.action.setBadgeText({ text: '...', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#555555', tabId });

  try {
    const heuristic = new URLAnalyzer(url).analyze();
    await storeResult({ ...heuristic, status: 'partial', phase: 'heuristic' }, tabId);

    const [intelRes, sslRes] = await Promise.allSettled([
      new ThreatIntelEngine(url).analyze(),
      new SSLInspector(url).analyze()
    ]);
    const intel    = intelRes.status === 'fulfilled' ? intelRes.value : null;
    const ssl      = sslRes.status  === 'fulfilled' ? sslRes.value   : null;
    const behavior = await getBehaviorData(url);
    const final    = DecisionFusionEngine.fuse(heuristic, intel, ssl, behavior);
    const recommendation = DecisionFusionEngine.getRecommendation(final);

    const result = {
      url, hostname: new URL(url).hostname,
      ...final,
      heuristicResult: heuristic, intelResult: intel, sslResult: ssl,
      recommendation, status: 'complete',
      timestamp: new Date().toISOString(),
      scanDate:  new Date().toLocaleDateString()
    };
    await storeResult(result, tabId);
    await handleThreatResponse(result, tabId);
    updateBadge(result, tabId);
    checkForSpam(url, tabId).catch(() => {});
    console.log(`[WebSentinel] ✅ ${final.level} (${final.finalScore}/100) — ${url}`);
  } catch(err) {
    console.error('[WebSentinel] Scan error:', err);
    chrome.action.setBadgeText({ text: 'ERR', tabId });
  }
});

// ════════════════════════════════════════════════════════════
// MESSAGE HANDLER
// ════════════════════════════════════════════════════════════

registerMessageHandler();
