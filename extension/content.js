// ============================================================
// WebSentinel - Content Script (Behavioral Analyzer)
// Automatically injected into every page
// Detects suspicious page behaviors without user doing anything
// ============================================================

(function () {
  'use strict';

  const behaviorFlags = [];
  let behaviorScore = 0;

  // ── BEHAVIOR 1: Detect disabled right-click ──────────────
  document.addEventListener('contextmenu', function (e) {
    if (e.defaultPrevented) {
      behaviorFlags.push('Page disables right-click — used to prevent users from inspecting the site');
      behaviorScore += 15;
      reportBehavior();
    }
  });

  // Override to detect if site prevents right-click
  const origPreventDefault = Event.prototype.preventDefault;
  Event.prototype.preventDefault = function () {
    if (this.type === 'contextmenu') {
      behaviorFlags.push('Right-click is being blocked by this page');
      behaviorScore += 15;
    }
    return origPreventDefault.apply(this, arguments);
  };

  // ── BEHAVIOR 2: Detect password fields on suspicious pages ─
  window.addEventListener('load', () => {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const cardFields = document.querySelectorAll(
      'input[name*="card"], input[name*="cvv"], input[name*="credit"], input[placeholder*="card"]'
    );

    if (passwordFields.length > 0) {
      behaviorFlags.push(`Page contains ${passwordFields.length} password input field(s) — credential harvesting risk`);
      behaviorScore += 10;
    }
    if (cardFields.length > 0) {
      behaviorFlags.push(`Page requests credit/debit card details — financial data harvesting risk`);
      behaviorScore += 20;
    }

    // ── BEHAVIOR 3: Detect favicon mismatch ─────────────────
    checkFaviconMismatch();

    // ── BEHAVIOR 4: External resource ratio ─────────────────
    checkExternalResources();

    // ── BEHAVIOR 5: Urgency language in page ────────────────
    checkUrgencyLanguage();

    // ── BEHAVIOR 6: Hidden iframes ───────────────────────────
    checkHiddenIframes();

    // Report all findings
    if (behaviorScore > 0) reportBehavior();
  });

  // ── BEHAVIOR 3: Favicon domain mismatch ─────────────────
  function checkFaviconMismatch() {
    const faviconLinks = document.querySelectorAll('link[rel*="icon"]');
    const currentHost = window.location.hostname;

    faviconLinks.forEach(link => {
      if (link.href) {
        try {
          const faviconHost = new URL(link.href).hostname;
          if (faviconHost && faviconHost !== currentHost) {
            behaviorFlags.push(`Favicon loaded from different domain (${faviconHost}) — impersonation indicator`);
            behaviorScore += 15;
          }
        } catch (e) {}
      }
    });
  }

  // ── BEHAVIOR 4: External Resource Ratio ─────────────────
  function checkExternalResources() {
    const allScripts = document.querySelectorAll('script[src]');
    const allImages = document.querySelectorAll('img[src]');
    const currentHost = window.location.hostname;
    let externalCount = 0;
    let totalCount = 0;

    [...allScripts, ...allImages].forEach(el => {
      const src = el.src || el.href;
      if (src) {
        totalCount++;
        try {
          const host = new URL(src).hostname;
          if (host && host !== currentHost) externalCount++;
        } catch (e) {}
      }
    });

    const ratio = totalCount > 0 ? externalCount / totalCount : 0;
    if (ratio > 0.8 && totalCount > 5) {
      behaviorFlags.push(`${Math.round(ratio * 100)}% of resources loaded from external domains — common in cloned phishing pages`);
      behaviorScore += 20;
    }
  }

  // ── BEHAVIOR 5: Urgency Language Detection ───────────────
  function checkUrgencyLanguage() {
    const urgencyPhrases = [
      'your account has been suspended',
      'verify your account immediately',
      'your account will be closed',
      'unusual activity detected',
      'confirm your identity',
      'limited time offer',
      'act now',
      'your account is at risk',
      'update your payment',
      'security alert',
      'unauthorized access',
      'click here immediately'
    ];

    const bodyText = document.body ? document.body.innerText.toLowerCase() : '';
    const foundPhrases = urgencyPhrases.filter(phrase => bodyText.includes(phrase));

    if (foundPhrases.length >= 2) {
      behaviorFlags.push(`Multiple urgency phrases detected on page: "${foundPhrases[0]}", "${foundPhrases[1]}" — social engineering indicators`);
      behaviorScore += 25;
    } else if (foundPhrases.length === 1) {
      behaviorFlags.push(`Urgency language on page: "${foundPhrases[0]}"`);
      behaviorScore += 10;
    }
  }

  // ── BEHAVIOR 6: Hidden iframes ───────────────────────────
  function checkHiddenIframes() {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      if (style.display === 'none' || style.visibility === 'hidden' ||
          parseInt(style.width) < 5 || parseInt(style.height) < 5) {
        behaviorFlags.push('Hidden iframe detected — used for clickjacking or silent credential capture');
        behaviorScore += 20;
      }
    });
  }

  // ── BEHAVIOR 7: Monitor clipboard access ─────────────────
  document.addEventListener('copy', () => {
    // If page tries to intercept copy events aggressively, flag it
  });

  navigator.clipboard && (() => {
    const origReadText = navigator.clipboard.readText?.bind(navigator.clipboard);
    if (origReadText) {
      navigator.clipboard.readText = async () => {
        behaviorFlags.push('Page is attempting to read your clipboard');
        behaviorScore += 10;
        reportBehavior();
        return origReadText();
      };
    }
  })();

  // ── BEHAVIOR 8: Popup / window.open detection ────────────
  const origOpen = window.open;
  let popupCount = 0;
  window.open = function (...args) {
    popupCount++;
    if (popupCount >= 2) {
      behaviorFlags.push(`Page is aggressively opening popups (${popupCount} times) — ad/phishing redirect behavior`);
      behaviorScore += 15;
      reportBehavior();
    }
    return origOpen.apply(this, args);
  };

  // ── Report behavior findings to background ───────────────
  function reportBehavior() {
    if (behaviorFlags.length === 0) return;

    chrome.runtime.sendMessage({
      type: 'BEHAVIOR_FLAGS',
      flags: behaviorFlags,
      score: Math.min(behaviorScore, 50), // Behavior adds max 50 points
      url: window.location.href
    }).catch(() => {}); // Ignore if background not ready
  }

  // Report on page load completion
  window.addEventListener('load', () => {
    setTimeout(reportBehavior, 1000); // Small delay to let page fully render
  });

})();


// ── Shared extension state — read by QR scanner + link tooltip ──
let _wsExtEnabled        = true;
let _wsScreenshotEnabled = false;

chrome.storage.local.get(['extensionEnabled', 'screenshotEnabled'], d => {
  _wsExtEnabled        = d.extensionEnabled        !== false;
  _wsScreenshotEnabled = d.screenshotEnabled        === true;
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if ('extensionEnabled'  in changes) _wsExtEnabled        = changes.extensionEnabled.newValue  !== false;
  if ('screenshotEnabled' in changes) _wsScreenshotEnabled = changes.screenshotEnabled.newValue === true;
});



// ============================================================
// WebSentinel — Feature 5: Link Tooltip
// ─────────────────────────────────────────────────────────────
// On mouseover any <a href> link, show a small color-coded risk
// badge near the link using quick inline heuristics.
// Debounced at 350 ms to prevent flicker while moving the mouse.
// ============================================================

(function () {
  'use strict';

  const DEBOUNCE_MS = 350;
  const COLORS = {
    'PHISHING':   '#ff4d6d',
    'SUSPICIOUS': '#ff9a3c',
    'LOW RISK':   '#ffd166',
    'SAFE':       '#00e5a0'
  };

  // ── Standalone heuristic scorer ──────────────────────────────
  function _heuristic(url) {
    let score = 0;
    const lower = url.toLowerCase();

    if (/https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(url))                       { score += 30; }
    const SUSP_TLDS = ['.xyz','.top','.click','.loan','.tk','.ml','.cf','.gq','.pw','.icu','.live'];
    if (SUSP_TLDS.some(t => lower.includes(t)))                               { score += 20; }
    if (url.startsWith('http://'))                                             { score += 15; }
    const KWS = ['login','verify','secure','account','update','confirm','banking','password','credential'];
    const hits = KWS.filter(k => lower.includes(k));
    score += hits.length >= 2 ? 20 : hits.length === 1 ? 8 : 0;
    if (['bit.ly','tinyurl','t.co','goo.gl','ow.ly','is.gd'].some(s => lower.includes(s))) { score += 15; }
    if (url.length > 100)                                                      { score += 10; }
    if ((lower.match(/-/g) || []).length > 4)                                 { score += 10; }
    if ((lower.match(/\./g) || []).length > 5)                                { score += 10; }

    score = Math.min(score, 100);
    const level = score >= 70 ? 'PHISHING' : score >= 40 ? 'SUSPICIOUS' : score >= 15 ? 'LOW RISK' : 'SAFE';
    return { score, level };
  }

  // ── Map ML score (0-100) to risk level ───────────────────────
  function _mlLevel(score) {
    return score >= 70 ? 'PHISHING' : score >= 40 ? 'SUSPICIOUS' : score >= 15 ? 'LOW RISK' : 'SAFE';
  }

  // ── Tooltip element (created once, reused) ──────────────────
  let tip = null;

  function _getTip() {
    if (tip) return tip;
    tip = document.createElement('div');
    tip.id = 'rs-link-tip';
    tip.style.cssText = [
      'position:fixed',
      'z-index:2147483645',
      'padding:5px 11px',
      'border-radius:6px',
      'font-family:Arial,sans-serif',
      'font-size:11px',
      'font-weight:bold',
      'pointer-events:none',
      'opacity:0',
      'transition:opacity 0.12s ease',
      'white-space:nowrap',
      'background:rgba(10,10,20,0.92)',
      'box-shadow:0 2px 10px rgba(0,0,0,0.6)',
      'line-height:1.6'
    ].join(';');
    document.body.appendChild(tip);
    return tip;
  }

  function _position(anchorEl) {
    const t    = _getTip();
    const rect = anchorEl.getBoundingClientRect();
    t.style.left = `${Math.max(4, Math.min(rect.left, window.innerWidth - 220))}px`;
    t.style.top  = `${rect.bottom + 5}px`;
  }

  // Show heuristic result with optional "ML scanning…" sub-line
  function _show(anchorEl, h, scanning) {
    const t   = _getTip();
    const col = COLORS[h.level] || COLORS['SAFE'];
    t.style.color  = col;
    t.style.border = `1.5px solid ${col}`;
    t.innerHTML    = `🛡 <b>${h.level}</b>  ${h.score}/100` +
                     (scanning ? `<br><span style="font-size:10px;color:#888;font-weight:normal">⏳ Scanning…</span>` : '');
    _position(anchorEl);
    t.style.opacity = '1';
  }

  // Update tooltip with ML result — show one final score
  function _showML(anchorEl, h, ml) {
    const t       = _getTip();
    const mlScore = ml.ml_score ?? 0;
    const mlLvl   = _mlLevel(mlScore);
    // Final score: worst of heuristic vs ML
    const ORDER   = ['PHISHING','SUSPICIOUS','LOW RISK','SAFE'];
    const finalLvl = ORDER[Math.min(ORDER.indexOf(h.level), ORDER.indexOf(mlLvl))];
    const finalScore = Math.max(h.score, mlScore);
    const col = COLORS[finalLvl] || COLORS['SAFE'];
    t.style.color  = col;
    t.style.border = `1.5px solid ${col}`;
    t.innerHTML    = `🛡 <b>${finalLvl}</b>  ${finalScore}/100`;
    _position(anchorEl);
    t.style.opacity = '1';
  }

  function _hide() {
    if (tip) tip.style.opacity = '0';
  }

  // ── Event listeners ─────────────────────────────────────────
  let debounceTimer  = null;
  let activeAnchor   = null;   // track current hovered anchor

  document.addEventListener('mouseover', e => {
    const anchor = e.target.closest('a[href]');
    if (!anchor) return;
    const href = anchor.href;
    if (!href || !/^https?:\/\//i.test(href)) return;

    clearTimeout(debounceTimer);
    activeAnchor = anchor;

    debounceTimer = setTimeout(() => {
      if (!_wsExtEnabled || !_wsScreenshotEnabled) return;
      try {
        if (new URL(href).hostname === window.location.hostname) return;
      } catch(_) {}
      const h = _heuristic(href);
      _show(anchor, h, true);   // show heuristic immediately + "ML scanning…"

      // Fallback: if backend doesn't respond in 3s, drop the scanning indicator
      const _mlFallback = setTimeout(() => {
        if (activeAnchor === anchor) _show(anchor, h, false);
      }, 3000);

      chrome.runtime.sendMessage({type: 'ML_SCAN_TOOLTIP', url: href}, ml => {
        clearTimeout(_mlFallback);
        if (activeAnchor !== anchor) return;
        if (ml && ml.ml_score !== undefined) {
          _showML(anchor, h, ml);
        } else {
          _show(anchor, h, false);
        }
      });
    }, DEBOUNCE_MS);
  }, true);

  document.addEventListener('mouseout', e => {
    const anchor = e.target.closest('a[href]');
    if (!anchor) return;
    clearTimeout(debounceTimer);
    activeAnchor = null;
    _hide();
  }, true);

  // ── QR image hover — screenshot-based decode (bypasses CORS) ─
  // Works for WhatsApp Web, Facebook Messenger, any CDN-hosted QR image
  let qrHoverTimer = null;
  let qrScanActive = false;
  let _qrResultAt  = 0;       // timestamp when a real result was last shown

  document.addEventListener('mouseover', e => {
    if (e.target.closest('a')) return;
    const img = e.target.closest('img');
    if (!img) return;
    if ((img.offsetWidth || img.naturalWidth || 0) < 60) return;

    clearTimeout(qrHoverTimer);
    qrHoverTimer = setTimeout(() => {
      const rect = img.getBoundingClientRect();
      if (rect.width < 60 || rect.height < 60) return;
      if (!_wsExtEnabled || !_wsScreenshotEnabled) return;

      qrScanActive = true;
      const t = _getTip();
      t.style.color   = '#888';
      t.style.border  = '1.5px solid #555';
      t.innerHTML     = '🔍 Scanning QR\u2026';
      t.style.left    = `${Math.max(4, Math.min(rect.left, window.innerWidth - 220))}px`;
      t.style.top     = `${rect.bottom + 5}px`;
      t.style.opacity = '1';

      const _qrFallback = setTimeout(() => { qrScanActive = false; _hide(); }, 4500);

      chrome.runtime.sendMessage(
        {type: 'SCAN_QR_HOVER', rect: {x: rect.left, y: rect.top, w: rect.width, h: rect.height, sw: window.innerWidth, sh: window.innerHeight}},
        result => {
          clearTimeout(_qrFallback);
          qrScanActive = false;
          if (!result || result.notQR || result.disabled) {
            setTimeout(_hide, result?.disabled ? 0 : 800);
            return;
          }
          if (!result.url) {
            // QR found but plain text / WiFi / etc.
            t.style.color  = '#aaa';
            t.style.border = '1.5px solid #555';
            t.innerHTML    = `\uD83D\uDD0D QR: ${(result.text || 'non-URL').slice(0, 50)}`;
            setTimeout(_hide, 3000);
            return;
          }
          const col  = COLORS[result.level] || COLORS['SAFE'];
          const disp = result.url.length > 48 ? result.url.slice(0, 45) + '\u2026' : result.url;
          const emoji = result.level === 'PHISHING' ? '\u26A0\uFE0F' : result.level === 'SUSPICIOUS' ? '\uD83D\uDEA8' : '\u2705';
          t.style.color  = col;
          t.style.border = `1.5px solid ${col}`;
          t.innerHTML    =
            `\uD83D\uDD0D QR: ${emoji} <b>${result.level}</b> ${result.score}/100` +
            `<br><span style="font-size:10px;color:#bbb;font-weight:normal">${disp}</span>`;
          _qrResultAt = Date.now();
        }
      );
    }, 600);
  }, true);

  document.addEventListener('mouseout', e => {
    if (e.target.closest('a') || !e.target.closest('img')) return;
    clearTimeout(qrHoverTimer);
    if (qrScanActive) return;
    // Hold tooltip for 3s after result arrives so user can read it
    if (_qrResultAt && Date.now() - _qrResultAt < 3000) return;
    _qrResultAt = 0;
    _hide();
  }, true);

})();
