// ============================================================
// WebSentinel — threat-intel.js
// VirusTotal, Google Safe Browsing, Tranco, OpenPhish, ML model
// ============================================================

import { WEBSENTINEL_CONFIG } from './config.js';
import { _cacheKey, _shouldSkipCache } from './cache.js';
import { authFetch } from './auth.js';

export class ThreatIntelEngine {
  constructor(url) {
    this.url     = url;
    this.results = {virusTotal:null,googleSafeBrowsing:null,tranco:null,openPhish:null,mlModel:null};
    this.errors  = [];
  }

  async analyze() {
    const cached = await this._getFromCache(this.url);
    if (cached) return cached;
    const [vt,gsb,tr,op,ml] = await Promise.allSettled([
      this._checkVirusTotal(), this._checkGoogleSafeBrowsing(),
      this._checkTranco(),     this._checkOpenPhish(), this._checkMLModel()
    ]);
    this.results.virusTotal         = vt.status  ==='fulfilled'?vt.value :null;
    this.results.googleSafeBrowsing = gsb.status ==='fulfilled'?gsb.value:null;
    this.results.tranco             = tr.status  ==='fulfilled'?tr.value :null;
    this.results.openPhish          = op.status  ==='fulfilled'?op.value :null;
    this.results.mlModel            = ml.status  ==='fulfilled'?ml.value :null;
    const combined = this._combineResults();
    await this._saveToCache(this.url, combined);
    return combined;
  }

  async _checkVirusTotal() {
    const apiKey = WEBSENTINEL_CONFIG.VIRUSTOTAL_API_KEY;
    if (!apiKey) return {available:false,reason:'No key'};
    try {
      const enc   = new TextEncoder();
      const urlId = btoa(String.fromCharCode(...enc.encode(this.url))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
      const resp  = await fetch(`${WEBSENTINEL_CONFIG.VIRUSTOTAL_URL_ENDPOINT}/${urlId}`,{headers:{'x-apikey':apiKey,'Accept':'application/json'},signal:AbortSignal.timeout(8000)});
      if (!resp.ok) {
        try{const fd=new FormData();fd.append('url',this.url);await fetch(WEBSENTINEL_CONFIG.VIRUSTOTAL_URL_ENDPOINT,{method:'POST',headers:{'x-apikey':apiKey},body:fd,signal:AbortSignal.timeout(5000)});}catch(_){}
        return {available:true,flagged:false,details:'Submitted for scanning'};
      }
      const d=await resp.json(),s=d?.data?.attributes?.last_analysis_stats||{};
      const mal=s.malicious||0,sus=s.suspicious||0,har=s.harmless||0,tot=mal+sus+har;
      return {available:true,flagged:mal>0||sus>2,score:tot>0?((mal+sus*0.5)/tot)*100:0,malicious:mal,suspicious:sus,harmless:har,total:tot,details:`${mal} malicious, ${sus} suspicious of ${tot}`};
    } catch(e){return {available:false,reason:e.message};}
  }

  async _checkGoogleSafeBrowsing() {
    const apiKey = WEBSENTINEL_CONFIG.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey) return {available:false,reason:'No key'};
    try {
      const resp=await fetch(`${WEBSENTINEL_CONFIG.GOOGLE_SAFE_BROWSING_ENDPOINT}?key=${apiKey}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client:{clientId:'websentinel',clientVersion:'1.0'},threatInfo:{threatTypes:['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],platformTypes:['ANY_PLATFORM'],threatEntryTypes:['URL'],threatEntries:[{url:this.url}]}}),signal:AbortSignal.timeout(8000)});
      const d=await resp.json(),m=d?.matches||[];
      return {available:true,flagged:m.length>0,score:m.length>0?100:0,threats:m.map(x=>x.threatType),details:m.length>0?`Flagged: ${m.map(x=>x.threatType).join(', ')}`:'Clean'};
    } catch(e){return {available:false,reason:e.message};}
  }

  async _checkTranco() {
    if (!WEBSENTINEL_CONFIG.ML_API_ENABLED) return {available:false,reason:'ML API disabled'};
    try {
      const resp=await authFetch(WEBSENTINEL_CONFIG.TRANCO_ENDPOINT,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:this.url}),signal:AbortSignal.timeout(5000)});
      if(!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const d=await resp.json();
      return {available:true,flagged:false,inTranco:d.in_tranco,score:d.risk_score||0,details:d.in_tranco?'Tranco top site — trusted':'Not in Tranco top sites (+15 risk)'};
    } catch(e){return {available:false,reason:e.message};}
  }

  async _checkOpenPhish() {
    try {
      const feed=await this._getOpenPhishFeed(),n=this.url.toLowerCase().trim();
      const f=feed.some(u=>n.includes(u.toLowerCase().trim())||u.toLowerCase().trim().includes(n));
      return {available:true,flagged:f,score:f?100:0,details:f?'OpenPhish match':'Not in OpenPhish'};
    } catch(e){return {available:false,reason:e.message};}
  }

  async _getOpenPhishFeed() {
    const K='openphish_feed',T='openphish_ts',TTL=60*60*1000;
    const s=await chrome.storage.local.get([K,T]);
    if(s[K]&&s[T]&&Date.now()-s[T]<TTL) return s[K];
    const r=await fetch(WEBSENTINEL_CONFIG.OPENPHISH_FEED);
    const urls=(await r.text()).split('\n').filter(l=>l.trim());
    await chrome.storage.local.set({[K]:urls,[T]:Date.now()});
    return urls;
  }

  async _checkMLModel() {
    if (!WEBSENTINEL_CONFIG.ML_API_ENABLED) return {available:false,reason:'Disabled'};
    try {
      const resp=await authFetch(WEBSENTINEL_CONFIG.ML_API_ENDPOINT,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:this.url}),signal:AbortSignal.timeout(WEBSENTINEL_CONFIG.ML_API_TIMEOUT)});
      if(!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const d=await resp.json();
      return {available:true,flagged:d.prediction==='phishing',suspicious:d.prediction==='suspicious',score:d.ml_score||0,prediction:d.prediction,rf_score:d.rf_score,lstm_score:d.lstm_score,hf_score:d.hf_score,confidence:d.confidence,top_features:d.top_features||[],details:`ML: ${d.prediction} (${d.ml_score}/100)`,models_used:d.models_used};
    } catch(e){return {available:false,reason:e.message,score:0};}
  }

  _combineResults() {
    const w=WEBSENTINEL_CONFIG.WEIGHTS,r=this.results;
    let intelScore=0,intelFlags=[],sourcesChecked=0,sourcesFlagged=0;

    if(r.virusTotal?.available){sourcesChecked++;if(r.virusTotal.flagged){sourcesFlagged++;intelScore+=(r.virusTotal.score||80)*w.virusTotal*4;intelFlags.push(`🔴 VirusTotal: ${r.virusTotal.details}`);}}
    if(r.googleSafeBrowsing?.available){sourcesChecked++;if(r.googleSafeBrowsing.flagged){sourcesFlagged++;intelScore+=100*w.googleSafeBrowsing*5;intelFlags.push(`🔴 Google Safe Browsing: ${r.googleSafeBrowsing.details}`);}}
    if(r.tranco?.available){sourcesChecked++;intelScore+=(r.tranco.score||0);if(r.tranco.inTranco){intelFlags.push(`✅ Tranco: Top reputed site`);}else{intelFlags.push(`⚠️ Tranco: Not in top sites list (+15 risk)`);}}
    if(r.openPhish?.available){sourcesChecked++;if(r.openPhish.flagged){sourcesFlagged++;intelScore+=100*0.3;intelFlags.push(`🔴 OpenPhish: ${r.openPhish.details}`);}}

    if(r.mlModel?.available){
      sourcesChecked++;
      if(r.mlModel.flagged){sourcesFlagged++;intelScore+=(r.mlModel.score||0)*w.mlModel*5;intelFlags.push(`🤖 ML Model: PHISHING (RF:${r.mlModel.rf_score} LSTM:${r.mlModel.lstm_score} HF:${r.mlModel.hf_score})`);}
      else if(r.mlModel.suspicious){intelScore+=(r.mlModel.score||0)*w.mlModel*2;intelFlags.push(`🤖 ML Model: Suspicious (${r.mlModel.score}/100)`);}
      else{intelFlags.push(`✅ ML Model: Legitimate (${r.mlModel.score}/100)`);}
    } else if(r.mlModel&&!r.mlModel.available){
      intelFlags.push(`⚠️ ML Model: Offline (${r.mlModel.reason||''})`);
    }

    intelScore=Math.round(Math.min(100,intelScore));
    if(sourcesChecked>0&&sourcesFlagged===0) intelFlags.push(`✅ ${sourcesChecked} sources checked — no threats`);
    if(sourcesFlagged>1) intelFlags.push(`⚠️ Flagged by ${sourcesFlagged}/${sourcesChecked} sources`);
    return {intelScore,intelFlags,sourcesChecked,sourcesFlagged,sources:{...this.results},errors:this.errors};
  }

  async _getFromCache(url) {
    if(_shouldSkipCache(url)) return null;
    const key=_cacheKey(url),s=await chrome.storage.local.get(key);
    if(!s[key]) return null;
    return (Date.now()-s[key].timestamp)>WEBSENTINEL_CONFIG.CACHE_DURATION_MS?null:s[key].data;
  }

  async _saveToCache(url,data) {
    if(_shouldSkipCache(url)) return;
    const key=_cacheKey(url);
    await chrome.storage.local.set({[key]:{data,timestamp:Date.now()}});
  }
}
