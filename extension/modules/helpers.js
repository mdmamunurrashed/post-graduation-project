// ============================================================
// WebSentinel — helpers.js
// storeResult, handleThreatResponse, updateBadge, getBehaviorData
// ============================================================

import { injectPhishingWarning, injectSuspiciousBanner } from './banners.js';

export function getBehaviorData(url) {
  return new Promise(resolve => {
    setTimeout(() => {
      chrome.storage.local.get(`behavior_${encodeURIComponent(url)}`).then(d => resolve(d[`behavior_${encodeURIComponent(url)}`] || null));
    }, 2000);
  });
}

export async function storeResult(result, tabId) {
  const d       = await chrome.storage.local.get(['history']);
  const history = d.history || [];
  if (result.status === 'complete') { history.unshift(result); if (history.length > 100) history.pop(); }
  await chrome.storage.local.set({
    currentResult: result,
    [`tab_${tabId}`]: result,
    history: result.status === 'complete' ? history : (d.history || [])
  });
}

export async function handleThreatResponse(result, tabId) {
  const flags = result.allFlags || result.flags || [];
  const score = result.finalScore ?? result.score ?? 0;
  const host  = result.hostname || result.url || 'Unknown';
  const first = flags[0] || '';

  if (result.level === 'PHISHING') {
    const nId = `phishing_${Date.now()}`;
    chrome.notifications.create(nId, {type:'basic',iconUrl:'icons/icon128.png',title:'🚨 PHISHING DETECTED — WebSentinel',message:`BLOCKED: ${host}\nScore: ${score}/100\n${first}`,priority:2,requireInteraction:false});
    setTimeout(() => chrome.notifications.clear(nId), 8000);
    chrome.scripting.executeScript({target:{tabId},func:injectPhishingWarning,args:[{score,hostname:host,flags:flags.slice(0,4),iconURL:chrome.runtime.getURL('icons/icon128.png')}]}).catch(()=>{});

  } else if (result.level === 'SUSPICIOUS') {
    const nId = `suspicious_${Date.now()}`;
    chrome.notifications.create(nId, {type:'basic',iconUrl:'icons/icon128.png',title:'⚠️ Suspicious Site — WebSentinel',message:`Caution: ${host}\nScore: ${score}/100\n${first}`,priority:1,requireInteraction:false});
    setTimeout(() => chrome.notifications.clear(nId), 5000);
    chrome.scripting.executeScript({target:{tabId},func:injectSuspiciousBanner,args:[{score,hostname:host,flag:first}]}).catch(()=>{});
  }
  // LOW RISK & SAFE — silent
}

export function updateBadge(result, tabId) {
  const cfg = {'PHISHING':['!!!','#FF0000'],'SUSPICIOUS':['!','#FF8C00'],'LOW RISK':['?','#FFD700'],'SAFE':['✓','#00C853']};
  const [text, color] = cfg[result.level] || cfg['SAFE'];
  chrome.action.setBadgeText({text, tabId});
  chrome.action.setBadgeBackgroundColor({color, tabId});
}
