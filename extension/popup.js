// ============================================================
// WebSentinel — popup.js
// ============================================================

let currentHostname = '';
let currentTabUrl   = '';

document.addEventListener('DOMContentLoaded', async () => {

  // Dashboard
  document.getElementById('dashboardBtn')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
  });

  // Current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabUrl = tab?.url || '';
  try { currentHostname = new URL(currentTabUrl).hostname.replace(/^www\./, ''); } catch(_) {}

  // Load result
  const result  = await msg({ type: 'GET_CURRENT_RESULT', tabId: tab?.id });
  const history = await msg({ type: 'GET_HISTORY' });

  if (result) { renderResult(result); }
  else {
    document.getElementById('flagsContainer').innerHTML = '<div class="loading">No data yet — navigate to a website first.</div>';
  }
  if (history?.length) renderHistory(history.slice(0, 5));

  await renderWhitelistBar();

  // Whitelist toggle
  document.getElementById('wlToggle').addEventListener('click', async () => {
    const mgr = document.getElementById('whitelistManager');
    const tog = document.getElementById('wlToggle');
    if (mgr.style.display === 'none') {
      mgr.style.display = 'block'; tog.textContent = '▲ Hide';
      await renderWhitelistManager();
    } else {
      mgr.style.display = 'none'; tog.textContent = '▼ Show';
    }
  });

  // ── Extension ON/OFF toggle ───────────────────────────────
  const toggle = document.getElementById('extensionToggle');
  const label  = document.getElementById('toggleLabel');

  const { enabled } = await msg({ type: 'GET_EXTENSION_ENABLED' });
  toggle.checked = enabled;
  updateToggleLabel(enabled);

  toggle.addEventListener('change', async () => {
    const isOn = toggle.checked;
    await msg({ type: 'SET_EXTENSION_ENABLED', enabled: isOn });
    updateToggleLabel(isOn);
    if (!isOn) {
      // Turn off ad blocker
      adBlockToggle.checked = false;
      await chrome.storage.local.set({ adBlockEnabled: false });
      await chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: [], disableRulesetIds: ['ad_blocker'] }).catch(() => {});
      // Turn off deep scan
      screenshotToggle.checked = false;
      await msg({ type: 'SET_SCREENSHOT_ENABLED', enabled: false });
    }
  });

  function updateToggleLabel(on) {
    label.textContent = on ? 'On' : 'Off';
    label.style.color = on ? '#00e5a0' : '#ff4d6d';
  }

  // ── Manual URL scan ──────────────────────────────────────
  const manualUrlInput = document.getElementById('manualUrlInput');
  const manualScanBtn  = document.getElementById('manualScanBtn');

  manualScanBtn.addEventListener('click', async () => {
    const raw = manualUrlInput.value.trim();
    if (!raw) return;
    const url = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw;
    try { new URL(url); } catch(_) { return; }
    manualScanBtn.textContent = '⏳';
    manualScanBtn.disabled = true;
    const result = await msg({type: 'FULL_MANUAL_SCAN', url});
    showManualResult(result);
    manualScanBtn.textContent = 'Scan';
    manualScanBtn.disabled = false;
  });

  manualUrlInput.addEventListener('keydown', e => { if (e.key === 'Enter') manualScanBtn.click(); });

  // ── QR image scan ─────────────────────────────────────────
  const qrImageInput  = document.getElementById('qrImageInput');
  const qrUploadArea  = document.getElementById('qrUploadArea');
  const qrUploadText  = document.getElementById('qrUploadText');

  qrImageInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) processQRFile(file);
  });

  qrUploadArea.addEventListener('dragover', e => { e.preventDefault(); qrUploadArea.classList.add('dragover'); });
  qrUploadArea.addEventListener('dragleave', () => qrUploadArea.classList.remove('dragover'));
  qrUploadArea.addEventListener('drop', e => {
    e.preventDefault();
    qrUploadArea.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) processQRFile(file);
  });

  async function processQRFile(file) {
    qrUploadText.textContent = '⏳ Scanning QR…';
    const reader = new FileReader();
    reader.onload = async ev => {
      const result = await msg({type: 'SCAN_QR_IMAGE', imageData: ev.target.result});
      if (result?.error) {
        qrUploadText.textContent = '❌ ' + result.error;
        setTimeout(() => { qrUploadText.textContent = '📷 Click or drop image to scan QR code'; }, 3000);
      } else {
        const disp = (result.url || '').length > 38 ? result.url.slice(0, 35) + '…' : result.url;
        qrUploadText.textContent = '✓ ' + disp;
        showManualResult(result);
      }
    };
    reader.readAsDataURL(file);
    qrImageInput.value = '';
  }

  function showManualResult(result) {
    const el = document.getElementById('manualResult');
    if (!result || !result.level) { el.style.display = 'none'; return; }
    const colors = {PHISHING:'#ff4d6d', SUSPICIOUS:'#ff9a3c', 'LOW RISK':'#ffd166', SAFE:'#00e5a0', WHITELISTED:'#6c63ff'};
    const col   = colors[result.level] || '#00e5a0';
    const score = result.finalScore ?? result.score ?? 0;
    el.style.cssText = `display:inline-flex;align-items:center;font-size:10px;font-family:monospace;color:${col};background:${col}18;border:1px solid ${col}44;border-radius:5px;padding:3px 8px;`;
    el.textContent = `${result.level}  ${score}/100`;
  }

  // ── Screenshot permission toggle ──────────────────────────
  const screenshotToggle = document.getElementById('screenshotToggle');
  const { enabled: screenshotOn } = await msg({ type: 'GET_SCREENSHOT_ENABLED' });
  screenshotToggle.checked = screenshotOn;

  screenshotToggle.addEventListener('change', async () => {
    if (screenshotToggle.checked && !toggle.checked) {
      toggle.checked = true;
      await msg({ type: 'SET_EXTENSION_ENABLED', enabled: true });
      updateToggleLabel(true);
    }
    await msg({ type: 'SET_SCREENSHOT_ENABLED', enabled: screenshotToggle.checked });
  });

  // ── Ad Blocker toggle ─────────────────────────────────────
  const adBlockToggle = document.getElementById('adBlockToggle');
  const { adBlockEnabled } = await chrome.storage.local.get({ adBlockEnabled: false });
  adBlockToggle.checked = adBlockEnabled;
  renderRedirectStatus(tab?.id);

  adBlockToggle.addEventListener('change', async () => {
    const enabled = adBlockToggle.checked;
    if (enabled && !toggle.checked) {
      toggle.checked = true;
      await msg({ type: 'SET_EXTENSION_ENABLED', enabled: true });
      updateToggleLabel(true);
    }
    await chrome.storage.local.set({ adBlockEnabled: enabled });
    try {
      if (enabled) {
        await chrome.declarativeNetRequest.updateEnabledRulesets({
          enableRulesetIds: ['ad_blocker'],
          disableRulesetIds: []
        });
      } else {
        await chrome.declarativeNetRequest.updateEnabledRulesets({
          enableRulesetIds: [],
          disableRulesetIds: ['ad_blocker']
        });
      }
    } catch(e) {
      console.error('Ad blocker toggle failed:', e);
    }
  });

  // ── Re-scan button ────────────────────────────────────────
  document.getElementById('rescanBtn').addEventListener('click', async () => {
    const btn = document.getElementById('rescanBtn');
    if (btn.classList.contains('scanning')) return;

    btn.textContent = '⏳';
    btn.classList.add('scanning');
    document.getElementById('threatScore').textContent = '...';
    document.getElementById('threatLabel').textContent = 'Re-scanning';
    document.getElementById('flagsContainer').innerHTML = '<div class="loading">Fresh scan in progress...</div>';
    document.getElementById('checksContainer').innerHTML = '';

    try {
      const resp = await msg({ type: 'FORCE_RESCAN' });
      if (resp?.error) { resetRescanBtn(btn); return; }
      toggle.checked = true;
      updateToggleLabel(true);

      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        const fresh = await msg({ type: 'GET_CURRENT_RESULT' });
        if (fresh?.status === 'complete' && fresh?.forced_rescan) {
          clearInterval(poll);
          renderResult(fresh);
          renderRedirectStatus(tab?.id);
          resetRescanBtn(btn);
        }
        if (attempts >= 24) {
          clearInterval(poll);
          const latest = await msg({ type: 'GET_CURRENT_RESULT' });
          if (latest) { renderResult(latest); }
          renderRedirectStatus(tab?.id);
          resetRescanBtn(btn);
        }
      }, 500);
    } catch(_) { resetRescanBtn(btn); }
  });

  function resetRescanBtn(btn) {
    btn.textContent = '🔄';
    btn.classList.remove('scanning');
  }
});

// ════════════════════════════════════════════════════════════
// Scan age
// ════════════════════════════════════════════════════════════
function renderScanAge(result) {
  const el = document.getElementById('scanAge');
  if (!el || !result?.timestamp) { if(el) el.textContent = ''; return; }
  const ageMs  = Date.now() - new Date(result.timestamp).getTime();
  const ageSec = Math.floor(ageMs / 1000);
  const ageMin = Math.floor(ageSec / 60);
  let text, cls;
  if (ageSec < 15)      { text = '✅ Just scanned';            cls = 'scan-age fresh'; }
  else if (ageSec < 60) { text = `Scanned ${ageSec}s ago`;     cls = 'scan-age fresh'; }
  else if (ageMin < 5)  { text = `Scanned ${ageMin}m ago`;     cls = 'scan-age fresh'; }
  else if (ageMin < 10) { text = `Scanned ${ageMin}m ago`;     cls = 'scan-age'; }
  else                  { text = `⚠ ${ageMin}m ago — re-scan?`;cls = 'scan-age stale'; }
  el.textContent = text; el.className = cls;
}

// ════════════════════════════════════════════════════════════
// Helper
// ════════════════════════════════════════════════════════════
function msg(m) {
  return new Promise(resolve => chrome.runtime.sendMessage(m, r => resolve(r)));
}

// ════════════════════════════════════════════════════════════
// Whitelist bar
// ════════════════════════════════════════════════════════════
async function renderWhitelistBar() {
  const { whitelist } = await msg({ type: 'GET_WHITELIST' });
  const isListed = whitelist.includes(currentHostname);
  const statusEl = document.getElementById('whitelistStatus');
  const btn      = document.getElementById('whitelistBtn');
  if (!currentHostname) { statusEl.textContent = 'No site active'; btn.style.display = 'none'; return; }
  if (isListed) {
    statusEl.textContent = `✅ ${currentHostname} whitelisted`;
    btn.textContent = 'Remove'; btn.className = 'wl-btn remove';
    btn.onclick = async () => { await msg({ type: 'REMOVE_FROM_WHITELIST', hostname: currentHostname }); await renderWhitelistBar(); await renderWhitelistManager(); };
  } else {
    statusEl.textContent = currentHostname;
    btn.textContent = '+ Whitelist Site'; btn.className = 'wl-btn add';
    btn.onclick = async () => { await msg({ type: 'ADD_TO_WHITELIST', hostname: currentHostname }); await renderWhitelistBar(); await renderWhitelistManager(); };
  }
}

async function renderWhitelistManager() {
  const { whitelist } = await msg({ type: 'GET_WHITELIST' });
  const listEl = document.getElementById('wlList'), emptyEl = document.getElementById('wlEmpty');
  if (!whitelist?.length) { listEl.innerHTML = ''; emptyEl.style.display = 'block'; return; }
  emptyEl.style.display = 'none';
  listEl.innerHTML = whitelist.map(d => `<div class="wl-item"><span class="wl-item-domain">✓ ${d}</span><button class="wl-remove-btn" data-domain="${d}">Remove</button></div>`).join('');
  listEl.querySelectorAll('.wl-remove-btn').forEach(b => {
    b.addEventListener('click', async () => { await msg({ type: 'REMOVE_FROM_WHITELIST', hostname: b.dataset.domain }); await renderWhitelistBar(); await renderWhitelistManager(); });
  });
}

// ════════════════════════════════════════════════════════════
// Render result
// ════════════════════════════════════════════════════════════
function renderResult(result) {
  const card  = document.getElementById('threatCard');
  const level = result.level || 'SAFE';
  const score = result.finalScore ?? result.score ?? 0;
  const classMap = { 'PHISHING':'phishing','SUSPICIOUS':'suspicious','LOW RISK':'low','SAFE':'safe','WHITELISTED':'whitelisted' };
  card.className = `threat-card ${classMap[level] || 'safe'}`;
  document.getElementById('threatScore').textContent = level === 'WHITELISTED' ? '✓' : score;
  document.getElementById('threatLabel').textContent = level;
  document.getElementById('threatHost').textContent  = result.hostname || result.url || '';
  document.getElementById('scoreBar').style.width    = level === 'WHITELISTED' ? '0%' : `${score}%`;

  // Confidence line
  const existing = document.getElementById('rs-conf');
  if (result.confidence) {
    const el = existing || document.createElement('div');
    el.id = 'rs-conf'; el.style.cssText = 'font-size:10px;color:#888;margin-top:4px';
    el.textContent = `Confidence: ${result.confidence} | ${result.sourcesAvailable||1}/4 sources`;
    if (!existing) document.getElementById('threatHost').insertAdjacentElement('afterend', el);
  } else if (existing) existing.remove();

  // Flags
  const fc   = document.getElementById('flagsContainer');
  const flags = result.allFlags || result.flags || [];
  fc.innerHTML = flags.length
    ? flags.map(f => `<div class="flag-item ${f.includes('🔴')||f.toLowerCase().includes('impersonation')?'critical':''}">${f}</div>`).join('')
    : '<div class="no-flags">✅ No suspicious indicators found</div>';

  // Checks
  const cc = document.getElementById('checksContainer');
  if (result.whitelisted) { cc.innerHTML = '<div class="no-flags">Scanning skipped — site is whitelisted.</div>'; return; }

  let html = '';

  // Local URL checks
  const local = result.heuristicResult?.checks || result.checks || {};
  html += Object.entries(local).map(([name,status]) => {
    const safe = status === 'SAFE' || status === 'TRUSTED DOMAIN';
    const crit = status.includes('CRITICAL');
    return `<div class="check-item"><span class="check-name">${fmtName(name)}</span><span class="check-status ${safe?'safe':crit?'critical':'risk'}">${safe?'✓':crit?'!!!':'!'}</span></div>`;
  }).join('');

  // Score breakdown
  if (result.breakdown) {
    html += Object.entries(result.breakdown).map(([,v]) => {
      const s=Math.round(v.score||0),cls=s>=70?'critical':s>=40?'risk':'safe';
      return `<div class="check-item"><span class="check-name">${v.label}</span><span class="check-status ${cls}">${s}/100</span></div>`;
    }).join('');
  }

  // Threat intel sources
  const sources = result.intelResult?.sources || {};
  const names   = {virusTotal:'VirusTotal',googleSafeBrowsing:'Google SB',tranco:'Tranco',openPhish:'OpenPhish',mlModel:'ML Model'};
  html += Object.entries(sources).map(([key,src]) => {
    if (!src) return `<div class="check-item"><span class="check-name">${names[key]||key}</span><span class="check-status" style="color:#555">N/A</span></div>`;
    if (!src.available) return `<div class="check-item"><span class="check-name">${names[key]||key}</span><span class="check-status" style="color:#ff8c00">⚠ Offline</span></div>`;
    if (key === 'mlModel') {
      const cls = src.flagged?'critical':src.suspicious?'risk':'safe';
      const lbl = src.flagged?`🔴 ${src.score}/100`:src.suspicious?`⚠ ${src.score}/100`:`✓ ${src.score}/100`;
      return `<div class="check-item"><span class="check-name">ML Model</span><span class="check-status ${cls}">${lbl}</span></div>`;
    }
    return `<div class="check-item"><span class="check-name">${names[key]||key}</span><span class="check-status ${src.flagged?'critical':'safe'}">${src.flagged?'🔴 FLAGGED':'✓ CLEAN'}</span></div>`;
  }).join('');

  cc.innerHTML = html;

  // Recommendation — only PHISHING and SUSPICIOUS, not LOW RISK
  const rec = result.recommendation;
  if (rec && rec.severity !== 'NONE' && rec.message && (level === 'PHISHING' || level === 'SUSPICIOUS')) {
    const border = level === 'PHISHING' ? '#ff4444' : '#ff8c00';
    const el = document.createElement('div');
    el.style.cssText = `margin:8px 16px;padding:8px 12px;border-radius:6px;font-size:11px;line-height:1.5;background:rgba(255,255,255,0.04);border-left:3px solid ${border}`;
    el.textContent = rec.message;
    cc.insertAdjacentElement('afterend', el);
  }
}

function renderHistory(history) {
  const c = document.getElementById('historyContainer');
  const bm = {'PHISHING':'badge-phishing','SUSPICIOUS':'badge-suspicious','LOW RISK':'badge-low','SAFE':'badge-safe','WHITELISTED':'badge-safe'};
  c.innerHTML = history.map(h => `<div class="history-item"><span class="history-host">${h.hostname||h.url}</span><span class="history-badge ${bm[h.level]||'badge-safe'}">${h.level}</span></div>`).join('');
}

async function renderRedirectStatus(tabId) {
  const cc = document.getElementById('checksContainer');
  let row = document.getElementById('redirect-row');
  if (!row) {
    row = document.createElement('div');
    row.id = 'redirect-row';
    row.className = 'check-item';
    cc.appendChild(row);
  }
  const data = await chrome.storage.local.get(`redirect_${tabId}`);
  const info = data[`redirect_${tabId}`];
  const cls = info ? 'critical' : 'safe';
  const val = info ? `🔴 BLOCKED` : '✓ NONE';
  row.innerHTML = `<span class="check-name">Redirect</span><span class="check-status ${cls}">${val}</span>`;
}

function fmtName(key) {
  const m={brandImpersonation:'Brand Impersonation',homograph:'Homograph Attack',ipAddress:'IP Address',tld:'Suspicious TLD',suspiciousTLD:'Suspicious TLD',subdomainDepth:'Subdomain Depth',subdomains:'Subdomain Depth',urlLength:'URL Length',suspiciousKeywords:'Suspicious Keywords',urlShortener:'URL Shortener',doubleHTTP:'Double HTTP',typosquatting:'Typosquatting',whitelist:'Trusted Site',pathDepth:'Path Depth',obfuscation:'Obfuscation',https:'HTTPS',atSymbol:'AT Symbol',excessiveDashes:'Excess Dashes'};
  return m[key]||key.replace(/([A-Z])/g,' $1').replace(/^./,s=>s.toUpperCase());
}
