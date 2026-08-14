// ============================================================
// WebSentinel — fusion-engine.js
// Combines heuristic + intel + SSL + behavior into final score
// ============================================================

import { WEBSENTINEL_CONFIG } from './config.js';

export class DecisionFusionEngine {
  static fuse(heuristic, intel, ssl, behavior=null) {
    const w=WEBSENTINEL_CONFIG.WEIGHTS;
    const hS=Math.round(Math.min(100,heuristic?.score||0));
    const iS=Math.round(Math.min(100,intel?.intelScore||0));
    const sS=Math.round(Math.min(100,ssl?.score||0));
    const bS=Math.round(Math.min(100,behavior?.score||0));

    const fused=Math.round(
      (hS*0.10)+  // URL heuristics
      (iS*0.60)+  // Threat intel (ML + VT + GSB + Tranco)
      (sS*0.15)+  // SSL & domain age
      (bS*0.15)   // Behavioral analysis
    );
    console.log(`[WebSentinel] Score components — heuristic:${hS} intel:${iS} ssl:${sS} behavior:${bS} fused:${fused}`);

    const hard   = intel?.sources?.googleSafeBrowsing?.flagged||intel?.sources?.openPhish?.flagged;
    const vtM    = intel?.sources?.virusTotal?.malicious||0;
    const finalScore = (hard||vtM>=5)?Math.max(85,fused):Math.min(100,fused);

    const t     = WEBSENTINEL_CONFIG.SCORE_THRESHOLDS;
    const level = finalScore>=t.PHISHING?'PHISHING':finalScore>=t.SUSPICIOUS?'SUSPICIOUS':finalScore>=t.LOW_RISK?'LOW RISK':'SAFE';
    const color = finalScore>=t.PHISHING?'red':finalScore>=t.SUSPICIOUS?'orange':finalScore>=t.LOW_RISK?'yellow':'green';
    const emoji = finalScore>=t.PHISHING?'🔴':finalScore>=t.SUSPICIOUS?'🟠':finalScore>=t.LOW_RISK?'🟡':'🟢';

    const allFlags=[...(heuristic?.flags||[]),...(intel?.intelFlags||[]),...(ssl?.flags||[]),...(behavior?.flags||[])];
    const breakdown={
      heuristic:{score:hS,label:'URL Analysis',         weight:`${Math.round(w.heuristic*100)}%`},
      intel:    {score:iS,label:'Threat Intelligence',  weight:`${Math.round(w.virusTotal*100)}%`},
      ssl:      {score:sS,label:'SSL & Domain Age',     weight:'15%'},
      behavior: {score:bS,label:'Behavioral Analysis',  weight:`${Math.round(w.behavior*100)}%`}
    };
    const srcAvail=[heuristic?1:0,(intel?.sourcesChecked>0)?1:0,ssl?.available?1:0,behavior?1:0].reduce((a,b)=>a+b,0);
    const confidence=srcAvail>=3?'HIGH':srcAvail>=2?'MEDIUM':'LOW';
    return{finalScore,level,color,emoji,allFlags,breakdown,confidence,hardPhishing:hard,vtMalicious:vtM,sourcesAvailable:srcAvail,timestamp:new Date().toISOString()};
  }

  static getRecommendation(r) {
    const m={
      'PHISHING':  {action:'BLOCK', message:'Phishing detected. Do NOT enter any personal information.',severity:'CRITICAL'},
      'SUSPICIOUS':{action:'WARN',  message:'Multiple red flags. Proceed with extreme caution.',        severity:'HIGH'},
    };
    return m[r.level]||{action:'ALLOW',message:'',severity:'NONE'};
  }
}
