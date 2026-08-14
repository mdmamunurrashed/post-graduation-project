// ============================================================
// WebSentinel — spam-guard.js
// Spam domain/keyword list, overlay injection, OCR spam scoring
// ============================================================

const SPAM_DOMAINS = [
  'doubleclick.net','adservice.google.com','googlesyndication.com','ads.yahoo.com',
  'advertising.com','adtech.de','adblade.com','adcolony.com','admob.com','adnxs.com',
  'free-gift','you-won','claim-prize','winner-','congratulations-','free-iphone',
  'get-rich','make-money-fast','work-from-home-','microsoft-alert','apple-support-',
  'windows-warning','virus-detected-','call-now-support','tech-support-','pc-infected',
  'viralstories','clickbait','topstories-','trending-now-','viral-video-','doctors-hate'
];
const SPAM_URL_KW = [
  'free-gift','you-won','claim-now','congratulations','prize-winner','casino',
  'free-spins','make-money','work-from-home','lose-weight','miracle-cure',
  'microsoft-alert','apple-warning','virus-alert','click-here-now','limited-offer','act-now'
];

export function checkSpamDomainList(url) {
  try {
    const h = new URL(url).hostname.toLowerCase(), f = url.toLowerCase();
    for (const s of SPAM_DOMAINS) { if (h.includes(s) || f.includes(s)) return {matched:true,reason:'Spam domain: '+s}; }
    for (const k of SPAM_URL_KW)  { if (f.includes(k))                  return {matched:true,reason:'Spam keyword: '+k}; }
    return {matched: false};
  } catch(_) { return {matched: false}; }
}

export async function checkForSpam(url, tabId) {
  const dc = checkSpamDomainList(url);
  if (dc.matched) {
    chrome.scripting.executeScript({target:{tabId},func:analyzeAndShowSpam,args:[100,[dc.reason],true]}).catch(()=>{});
    return;
  }
  setTimeout(async () => {
    try { await chrome.scripting.executeScript({target:{tabId},func:analyzeAndShowSpam,args:[null,null,null]}); }
    catch(e) { console.log('[Spam]', e); }
  }, 2500);
}

// Self-contained — injected into page via executeScript (no imports allowed)
export function analyzeAndShowSpam(fs, ff, fb) {
  function analyze() {
    var sc=0,fl=[],iframes=document.querySelectorAll('iframe');
    if(iframes.length>8){sc+=25;fl.push('Excessive iframes ('+iframes.length+')');}
    var forms=document.querySelectorAll('form');
    if(forms.length>5){sc+=15;fl.push('Many forms ('+forms.length+')');}
    var popupKw=['winner','congratulations','you won','free gift','claim now','limited offer','act now','click here'];
    var bodyText=(document.body&&document.body.innerText||'').toLowerCase();
    var hits=popupKw.filter(function(k){return bodyText.includes(k);});
    if(hits.length>=2){sc+=30;fl.push('Spam keywords: '+hits.slice(0,3).join(', '));}
    var scripts=document.querySelectorAll('script[src]');
    var adDomains=['doubleclick','googlesyndication','adnxs','advertising','adtech'];
    var adScripts=Array.from(scripts).filter(function(s){return adDomains.some(function(d){return(s.src||'').includes(d);});});
    if(adScripts.length>3){sc+=20;fl.push('Heavy ad network injection');}
    var meta=document.querySelector('meta[http-equiv="refresh"]');
    if(meta){sc+=25;fl.push('Auto-redirect meta tag');}
    return{score:Math.min(sc,100),flags:fl};
  }

  function show(sc, fl, isBlock) {
    if(document.getElementById('rs-spam-overlay')) return;
    var ov=document.createElement('div');ov.id='rs-spam-overlay';
    if(isBlock){
      ov.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(20,10,0,0.97);z-index:2147483647;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:Arial,sans-serif;color:white;';
      var rs=fl.slice(0,3).map(function(f){return'<li style="margin:6px 0;font-size:14px;">⚠️ '+f+'</li>';}).join('')||'<li style="margin:6px 0;font-size:14px;">Multiple spam indicators</li>';
      ov.innerHTML='<div style="text-align:center;max-width:600px;padding:40px;"><div style="font-size:64px;margin-bottom:16px;">🚫</div><h1 style="font-size:28px;margin:0 0 8px;color:#ff9a3c;">SPAM SITE BLOCKED</h1><p style="opacity:0.8;margin-bottom:24px;">WebSentinel detected spam</p><div style="background:rgba(0,0,0,0.4);border-radius:12px;padding:20px;text-align:left;margin-bottom:24px;border:1px solid rgba(255,154,60,0.3);"><p style="color:#ff9a3c;font-weight:bold;">🟠 Score: '+sc+'/100</p><ul style="margin:0;padding-left:18px;">'+rs+'</ul></div><div style="display:flex;gap:12px;justify-content:center;"><button id="rs-spam-back" style="padding:12px 28px;border:none;border-radius:8px;background:white;color:#cc6600;font-size:15px;font-weight:bold;cursor:pointer;">← Go Back</button><button id="rs-spam-proceed" style="padding:12px 28px;border:none;border-radius:8px;background:rgba(255,255,255,0.1);color:white;font-size:13px;cursor:pointer;border:1px solid rgba(255,255,255,0.3);">Proceed anyway</button></div></div>';
      document.body.style.overflow='hidden';
    } else {
      ov.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;background:linear-gradient(135deg,#1a0e00,#2d1f00);border-bottom:3px solid #ff9a3c;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;font-family:Arial,sans-serif;';
      ov.innerHTML='<div style="display:flex;align-items:center;gap:12px;"><span style="font-size:22px;">⚠️</span><div><div style="color:#ff9a3c;font-weight:bold;font-size:13px;">Spam Warning</div><div style="color:#999;font-size:11px;">'+(fl[0]||'Spam detected')+'</div></div></div><div style="display:flex;gap:8px;"><button id="rs-spam-back" style="background:white;border:none;color:#cc6600;padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;font-weight:bold;">← Leave</button><button id="rs-spam-proceed" style="background:rgba(255,255,255,0.1);border:1px solid #555;color:#ccc;padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;">Ignore</button></div>';
      setTimeout(function(){if(ov.parentNode)ov.remove();},12000);
    }
    document.body.prepend(ov);
    document.getElementById('rs-spam-back').addEventListener('click',function(){window.history.length>1?window.history.back():window.location.replace('https://www.google.com');});
    document.getElementById('rs-spam-proceed').addEventListener('click',function(){ov.remove();document.body.style.overflow='';});
  }

  var sc, fl, isB;
  if (fs !== null) { sc=fs; fl=ff; isB=fb; }
  else { var r=analyze(); sc=r.score; fl=r.flags; isB=sc>=70; if(sc<40) return; }
  show(sc, fl, isB);
}
