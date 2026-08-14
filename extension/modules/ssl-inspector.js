// ============================================================
// WebSentinel — ssl-inspector.js
// HTTPS, domain age (WHOIS/RDAP), certificate validation
// ============================================================

export class SSLInspector {
  constructor(url){try{this.url=url;this.parsed=new URL(url);this.hostname=this.parsed.hostname;}catch(e){this.parseError=true;}}

  async analyze(){
    if(this.parseError) return {available:false};
    const res={hasHTTPS:false,flags:[],score:0};
    res.hasHTTPS=this.parsed.protocol==='https:';
    if(!res.hasHTTPS){res.score+=20;res.flags.push('No HTTPS');}
    try{
      const w=await this._checkDomainAge();
      if(w){
        res.domainAge=w.ageInDays;res.registrar=w.registrar;
        if(w.ageInDays<30){res.score+=35;res.flags.push(`Domain only ${w.ageInDays} days old`);}
        else if(w.ageInDays<90){res.score+=15;res.flags.push(`New domain (${w.ageInDays} days)`);}
        else if(w.ageInDays<180){res.score+=5;res.flags.push(`Domain < 6 months (${w.ageInDays} days)`);}
        else res.flags.push(`✅ Domain age: ${Math.floor(w.ageInDays/365)} years`);
      }
    }catch(_){res.flags.push('WHOIS lookup failed');}
    if(['.tk','.ml','.ga','.cf','.gq'].some(t=>this.hostname.endsWith(t))){res.score+=15;res.flags.push('Free domain with free SSL');}
    try{const c=await this._verifyCertificateMatch();if(c.mismatch){res.score+=30;res.flags.push('SSL certificate mismatch');}}catch(_){}
    res.score=Math.min(100,res.score);res.available=true;return res;
  }

  async _checkDomainAge(){
    const r=await fetch(`https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName=${this.hostname}&apiKey=free`,{signal:AbortSignal.timeout(5000)});
    if(!r.ok){
      const fb=await fetch(`https://rdap.org/domain/${this._base()}`,{signal:AbortSignal.timeout(5000)});
      if(!fb.ok) return null;
      const d=await fb.json(),ev=(d.events||[]).find(e=>e.eventAction==='registration');
      if(!ev?.eventDate) return null;
      return{ageInDays:Math.floor((Date.now()-new Date(ev.eventDate))/86400000),creationDate:ev.eventDate,registrar:'Unknown'};
    }
    const d=await r.json(),ds=d?.create_date||d?.creation_date;
    if(!ds) return null;
    return{ageInDays:Math.floor((Date.now()-new Date(ds))/86400000),creationDate:ds,registrar:d?.registrar_name||'Unknown'};
  }

  async _verifyCertificateMatch(){
    try{await fetch(`https://${this.hostname}`,{method:'HEAD',signal:AbortSignal.timeout(3000)});return{mismatch:false};}
    catch(e){return{mismatch:e.message.includes('certificate')||e.message.includes('SSL')||e.message.includes('cert')};}
  }

  _base(){return this.hostname.split('.').slice(-2).join('.');}
}
