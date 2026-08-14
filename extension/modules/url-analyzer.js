// ============================================================
// WebSentinel — url-analyzer.js
// Heuristic URL risk scoring (runs locally, no API calls)
// ============================================================

const SUSPICIOUS_KEYWORDS = [
  'login','signin','verify','secure','account','update','confirm','banking',
  'paypal','amazon','microsoft','apple','google','netflix','password',
  'credential','authenticate','suspend','unusual','limited','urgent','alert','warning'
];
const TOP_BRANDS = [
  'paypal','google','facebook','amazon','microsoft','apple','netflix','instagram',
  'twitter','linkedin','dropbox','gmail','outlook','yahoo','bank','wellsfargo',
  'chase','citibank','hsbc','barclays','ebay','steam','discord','whatsapp'
];
const SUSPICIOUS_TLDS = [
  '.xyz','.top','.club','.online','.site','.icu','.live','.stream',
  '.gq','.ml','.cf','.tk','.pw','.cc','.work','.click','.loan','.win','.download','.review'
];
export const TRUSTED_DOMAINS = [
  'google.com','facebook.com','amazon.com','microsoft.com','apple.com',
  'github.com','gitlab.com','youtube.com','twitter.com','x.com',
  'linkedin.com','instagram.com','wikipedia.org','reddit.com',
  'netflix.com','spotify.com','discord.com','slack.com','zoom.us',
  'paypal.com','stripe.com','ebay.com','shopify.com',
  'outlook.com','office.com','microsoftonline.com','live.com',
  'icloud.com','appleid.apple.com','accounts.google.com',
  'whatsapp.com','telegram.org','messenger.com',
  'dropbox.com','notion.so','atlassian.com','trello.com',
  'stackoverflow.com','bitbucket.org','digitalocean.com',
];

export class URLAnalyzer {
  constructor(url) {
    this.rawURL   = url;
    this.score    = 0;
    this.flags    = [];
    this.checks   = {};
    this.hostname = '';
    try {
      const p      = new URL(url);
      this.parsed  = p;
      this.hostname= p.hostname.toLowerCase();
      this.pathname= p.pathname;
      this.params  = p.searchParams;
    } catch(_) { this.parseError = true; }
  }

  checkURLLength()       { if(this.rawURL.length>100){this.score+=10;this.flags.push(`Unusually long URL (${this.rawURL.length} chars)`);this.checks.urlLength='MEDIUM RISK';}else this.checks.urlLength='SAFE'; }
  checkIPAddress()       { if(/^\d{1,3}(\.\d{1,3}){3}$/.test(this.hostname)){this.score+=30;this.flags.push('IP address used instead of domain');this.checks.ipAddress='HIGH RISK';}else this.checks.ipAddress='SAFE'; }
  checkSuspiciousTLD()   { const t=SUSPICIOUS_TLDS.find(t=>this.hostname.endsWith(t));if(t){this.score+=20;this.flags.push(`Suspicious TLD: ${t}`);this.checks.tld='HIGH RISK';}else this.checks.tld='SAFE'; }
  checkSubdomainDepth()  { const p=this.hostname.split('.');if(p.length>4){this.score+=15;this.flags.push(`Excessive subdomains (${p.length-2})`);this.checks.subdomains='MEDIUM RISK';}else this.checks.subdomains='SAFE'; }
  checkBrandImpersonation() {
    const root=this.hostname.split('.').slice(-2).join('.');
    const trusted=TRUSTED_DOMAINS.find(d=>root===d||this.hostname.endsWith('.'+d));
    if(trusted){this.checks.brandImpersonation='SAFE';return;}
    const brand=TOP_BRANDS.find(b=>this.hostname.includes(b)&&!this.hostname.endsWith(b+'.com')&&!this.hostname.endsWith(b+'.net'));
    if(brand){this.score+=35;this.flags.push(`Brand impersonation: "${brand}"`);this.checks.brandImpersonation='HIGH RISK';}
    else this.checks.brandImpersonation='SAFE';
  }
  checkHomographAttack() { if(/[^\x00-\x7F]/.test(this.hostname)){this.score+=25;this.flags.push('Homograph attack (non-ASCII chars in domain)');this.checks.homograph='CRITICAL';}else this.checks.homograph='SAFE'; }
  checkSpecialCharacters(){ const c=(this.rawURL.match(/@|%40/g)||[]).length;if(c>0){this.score+=20;this.flags.push(`Suspicious @ in URL`);this.checks.specialChars='HIGH RISK';}else this.checks.specialChars='SAFE'; }
  checkSuspiciousKeywords(){ const kw=SUSPICIOUS_KEYWORDS.filter(k=>this.rawURL.toLowerCase().includes(k));if(kw.length>1){this.score+=15;this.flags.push(`Suspicious keywords: ${kw.slice(0,3).join(', ')}`);this.checks.keywords='MEDIUM RISK';}else this.checks.keywords='SAFE'; }
  checkPathDepth()       { const d=(this.pathname.match(/\//g)||[]).length;if(d>8){this.score+=10;this.flags.push(`Deep URL path (${d} levels)`);this.checks.pathDepth='MEDIUM RISK';}else this.checks.pathDepth='SAFE'; }
  checkObfuscation()     { const h=(this.rawURL.match(/%[0-9a-fA-F]{2}/g)||[]).length;if(h>5){this.score+=15;this.flags.push(`Heavy URL encoding (${h} chars)`);this.checks.obfuscation='HIGH RISK';}else this.checks.obfuscation='SAFE'; }
  _lev(a,b){const dp=Array.from({length:a.length+1},(_,i)=>Array.from({length:b.length+1},(_,j)=>i===0?j:j===0?i:0));for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++)dp[i][j]=a[i-1]===b[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);return dp[a.length][b.length];}

  analyze() {
    if(this.parseError) return {score:0,level:'UNKNOWN',flags:['Could not parse URL'],checks:{}};
    this.checkURLLength();this.checkIPAddress();this.checkSuspiciousTLD();this.checkSubdomainDepth();
    this.checkBrandImpersonation();this.checkHomographAttack();this.checkSpecialCharacters();
    this.checkSuspiciousKeywords();this.checkPathDepth();this.checkObfuscation();
    const score=Math.min(100,this.score);
    const level=score>=70?'PHISHING':score>=40?'SUSPICIOUS':score>=15?'LOW RISK':'SAFE';
    return {score,level,flags:this.flags,checks:this.checks,hostname:this.hostname,url:this.rawURL};
  }
}
