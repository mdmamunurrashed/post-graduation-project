// ============================================================
// WebSentinel — banners.js
// Page-injected overlay and banner functions.
// These are passed to chrome.scripting.executeScript so they
// must be fully self-contained (no imports, no closures).
// ============================================================

export function injectPhishingWarning(data) {
  const ex=document.getElementById('websentinel-overlay');if(ex)ex.remove();
  const reasons=(data.flags||[]).length>0?data.flags.map(f=>`<li style="margin:6px 0;font-size:14px;">⚠️ ${f}</li>`).join(''):'<li style="margin:6px 0;font-size:14px;">Multiple threat indicators</li>';
  const ov=document.createElement('div');ov.id='websentinel-overlay';
  ov.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(180,0,0,0.97);z-index:2147483647;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Arial,sans-serif;color:white;';
  ov.innerHTML=`<div style="text-align:center;max-width:600px;padding:40px;"><div style="font-size:64px;margin-bottom:16px;">🛡️</div><h1 style="font-size:32px;margin:0 0 8px;letter-spacing:2px;">PHISHING SITE BLOCKED</h1><p style="font-size:16px;opacity:0.85;margin-bottom:24px;">WebSentinel detected this site as a phishing threat</p><div style="background:rgba(0,0,0,0.4);border-radius:12px;padding:20px;text-align:left;margin-bottom:24px;"><p style="font-weight:bold;font-size:16px;">🔴 Risk Score: ${data.score}/100</p><p style="font-size:14px;opacity:0.8;">Site: ${data.hostname}</p><ul style="margin:0;padding-left:18px;">${reasons}</ul></div><div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;"><button id="rs-goback-btn" style="padding:14px 28px;border:none;border-radius:8px;background:white;color:#cc0000;font-size:16px;font-weight:bold;cursor:pointer;">← Go Back to Safety</button><button id="rs-proceed-btn" style="padding:14px 28px;border:none;border-radius:8px;background:rgba(255,255,255,0.2);color:white;font-size:14px;cursor:pointer;border:1px solid rgba(255,255,255,0.4);">I understand — proceed anyway</button></div></div>`;
  document.body.appendChild(ov);document.body.style.overflow='hidden';
  document.getElementById('rs-goback-btn').addEventListener('click',()=>{window.history.length>1?window.history.back():window.location.replace('https://www.google.com');});
  document.getElementById('rs-proceed-btn').addEventListener('click',()=>{ov.remove();document.body.style.overflow='';});
}

export function injectSuspiciousBanner(data) {
  const ex=document.getElementById('rs-suspicious-banner');if(ex)ex.remove();
  const b=document.createElement('div');b.id='rs-suspicious-banner';
  b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:linear-gradient(135deg,#1a0e00,#2d1a00);border-bottom:3px solid #ff9a3c;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;font-family:Arial,sans-serif;box-shadow:0 4px 20px rgba(255,154,60,0.3);';
  b.innerHTML=`<div style="display:flex;align-items:center;gap:12px;"><span style="font-size:22px;">⚠️</span><div><div style="color:#ff9a3c;font-weight:bold;font-size:13px;">Suspicious Site — WebSentinel (${data.score}/100)</div><div style="color:#999;font-size:11px;">${data.flag||'Multiple risk indicators detected'}</div></div></div><button id="rs-susp-dismiss" style="background:rgba(255,255,255,0.1);border:1px solid #555;color:#ccc;padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;">Dismiss</button>`;
  document.body.prepend(b);
  document.getElementById('rs-susp-dismiss').addEventListener('click',()=>b.remove());
  setTimeout(()=>{if(b.parentNode)b.remove();},10000);
}

export function showRedirectWarning(fromHost, toHost, newUrl, originalUrl) {
  const ex=document.getElementById('rs-redirect-banner');
  if(ex) ex.remove();
  const b=document.createElement('div');
  b.id='rs-redirect-banner';
  b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:linear-gradient(135deg,#1a0800,#2d1400);border-bottom:3px solid #ff4d6d;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;font-family:Arial,sans-serif;box-shadow:0 4px 24px rgba(255,77,109,0.4);';
  b.innerHTML=`
    <div style="display:flex;align-items:center;gap:14px;">
      <span style="font-size:24px;">🛡️</span>
      <div>
        <div style="color:#ff4d6d;font-weight:bold;font-size:14px;">WebSentinel: Redirect Blocked!</div>
        <div style="color:#aaa;font-size:12px;"><span style="color:#ffd166">${fromHost}</span> → <span style="color:#ff9a3c">${toHost}</span></div>
      </div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <button id="rs-rd-back"  style="background:white;border:none;color:#cc0000;padding:8px 16px;border-radius:6px;font-size:12px;cursor:pointer;font-weight:bold;">← Go Back</button>
      <button id="rs-rd-allow" style="background:rgba(0,229,160,0.15);border:1px solid rgba(0,229,160,0.4);color:#00e5a0;padding:8px 14px;border-radius:6px;font-size:12px;cursor:pointer;font-weight:bold;">✓ Allow Once</button>
    </div>`;
  document.body.prepend(b);
  document.getElementById('rs-rd-back').addEventListener('click',()=>{
    window.history.length>1?window.history.back():window.location.replace(originalUrl);
  });
  document.getElementById('rs-rd-allow').addEventListener('click',()=>{
    b.remove();
    chrome.runtime.sendMessage({type:'OPEN_TAB', url:newUrl});
  });
  setTimeout(()=>{if(b.parentNode)b.remove();},3000);
}

export function showNewTabBlockedBanner(fromHost, toHost, blockedUrl) {
  const ex=document.getElementById('rs-newtab-banner');if(ex)ex.remove();
  const b=document.createElement('div');b.id='rs-newtab-banner';
  b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:linear-gradient(135deg,#0d001a,#1a0030);border-bottom:3px solid #ff4d6d;padding:14px 20px;display:flex;align-items:center;justify-content:space-between;font-family:Arial,sans-serif;';
  b.innerHTML=`<div style="display:flex;align-items:center;gap:14px;"><span style="font-size:26px;">🛡️</span><div><div style="color:#ff4d6d;font-weight:bold;font-size:14px;">New Tab Redirect BLOCKED</div><div style="color:#999;font-size:12px;"><span style="color:#ffd166">${fromHost}</span> tried to open <span style="color:#ff9a3c">${toHost}</span></div></div></div><div style="display:flex;gap:8px;"><button id="rs-nt-allow" style="background:rgba(0,229,160,0.15);border:1px solid rgba(0,229,160,0.4);color:#00e5a0;padding:7px 14px;border-radius:6px;font-size:12px;cursor:pointer;font-weight:bold;">✓ Allow Once</button><button id="rs-nt-dismiss" style="background:rgba(255,255,255,0.08);border:1px solid #444;color:#aaa;padding:7px 14px;border-radius:6px;font-size:12px;cursor:pointer;">Dismiss</button></div>`;
  document.body.prepend(b);
  document.getElementById('rs-nt-allow').addEventListener('click',()=>{
    chrome.runtime.sendMessage({type:'OPEN_TAB', url:blockedUrl});
    b.remove();
  });
  document.getElementById('rs-nt-dismiss').addEventListener('click',()=>b.remove());
  setTimeout(()=>{if(b.parentNode)b.remove();},3000);
}
