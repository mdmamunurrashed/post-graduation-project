'use strict';

let history = [];
let activeFilter = 'ALL';

// ── Colours ───────────────────────────────────────────────────
const COLORS = { PHISHING:'#ff4d6d', SUSPICIOUS:'#ff9a3c', 'LOW RISK':'#ffd166', SAFE:'#00e5a0', WHITELISTED:'#6c63ff' };

// ── Load from storage ─────────────────────────────────────────
function load() {
  chrome.storage.local.get(['history'], function(data) {
    const raw = data.history || [];
    history = raw.filter(function(h) {
      return h && h.level;
    }).map(function(h) {
      return {
        hostname:   h.hostname || h.url || '',
        level:      h.level,
        score:      h.finalScore != null ? h.finalScore : (h.score != null ? h.score : 0),
        timestamp:  h.timestamp || '',
        intelSources: h.intelResult ? h.intelResult.sourcesChecked : '—'
      };
    });
    render();
  });
}

// ── Render all ────────────────────────────────────────────────
function render() {
  renderStats();
  renderTimeline();
  renderDonut();
  renderTable();
  checkML();
}

// ── Stats ─────────────────────────────────────────────────────
function renderStats() {
  var total = history.length;
  var safe  = history.filter(function(h){ return h.level==='SAFE'||h.level==='WHITELISTED'; }).length;
  var susp  = history.filter(function(h){ return h.level==='SUSPICIOUS'||h.level==='LOW RISK'; }).length;
  var phish = history.filter(function(h){ return h.level==='PHISHING'; }).length;
  var pct   = function(n){ return total ? Math.round(n/total*100)+'% of total' : '0% of total'; };

  document.getElementById('sTotal').textContent = total;
  document.getElementById('sSafe').textContent  = safe;
  document.getElementById('sSusp').textContent  = susp;
  document.getElementById('sPhish').textContent = phish;
  document.getElementById('sSafePct').textContent  = pct(safe);
  document.getElementById('sSuspPct').textContent  = pct(susp);
  document.getElementById('sPhishPct').textContent = pct(phish);
}

// ── Donut Chart (pure canvas) ─────────────────────────────────
function renderDonut() {
  var canvas = document.getElementById('donutCanvas');
  var ctx    = canvas.getContext('2d');
  var w = canvas.width, h = canvas.height;
  ctx.clearRect(0,0,w,h);

  var safe  = history.filter(function(h){ return h.level==='SAFE'||h.level==='WHITELISTED'; }).length;
  var low   = history.filter(function(h){ return h.level==='LOW RISK'; }).length;
  var susp  = history.filter(function(h){ return h.level==='SUSPICIOUS'; }).length;
  var phish = history.filter(function(h){ return h.level==='PHISHING'; }).length;
  var total = safe+low+susp+phish || 1;

  var segments = [
    {val:safe,  color:'#00e5a0', label:'Safe'},
    {val:low,   color:'#ffd166', label:'Low Risk'},
    {val:susp,  color:'#ff9a3c', label:'Suspicious'},
    {val:phish, color:'#ff4d6d', label:'Phishing'}
  ].filter(function(s){ return s.val > 0; });

  if (segments.length === 0) {
    segments = [{val:1, color:'#1e1e3a', label:'No data'}];
  }

  var cx = w*0.32, cy = h/2, r = Math.min(cx,cy)-12, inner = r*0.6;
  var start = -Math.PI/2;

  segments.forEach(function(seg) {
    var angle = (seg.val/total)*Math.PI*2;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,start,start+angle);
    ctx.closePath();
    ctx.fillStyle = seg.color;
    ctx.fill();
    start += angle;
  });

  // Inner hole
  ctx.beginPath();
  ctx.arc(cx,cy,inner,0,Math.PI*2);
  ctx.fillStyle = '#0f0f1c';
  ctx.fill();

  // Centre text
  ctx.fillStyle = '#e2e2f0';
  ctx.font = 'bold 22px system-ui';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total === 1 && segments[0].label === 'No data' ? '0' : history.length, cx, cy-8);
  ctx.font = '10px system-ui';
  ctx.fillStyle = '#5a5a7a';
  ctx.fillText('SCANNED', cx, cy+12);

  // Legend — positioned right side with clear gap from donut
  var lx = w*0.72, ly = cy - (segments.length * 16);
  segments.forEach(function(seg,i){
    var y = ly + i*32;
    // Dot
    ctx.fillStyle = seg.color;
    ctx.beginPath();
    ctx.arc(lx, y, 7, 0, Math.PI*2);
    ctx.fill();
    // Label
    ctx.fillStyle = '#e2e2f0';
    ctx.font = '12px monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText(seg.label, lx+16, y-6);
    // Count
    ctx.fillStyle = seg.color;
    ctx.font = 'bold 11px monospace';
    ctx.fillText('('+seg.val+')', lx+16, y+8);
  });
}


// ── Risk Timeline ─────────────────────────────────────────────
function renderTimeline() {
  var canvas = document.getElementById('timelineCanvas');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  var items = history.slice(0, 30).reverse(); // oldest → newest left → right

  if (items.length === 0) {
    ctx.fillStyle = '#5a5a7a';
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No scan data yet — browse some websites!', w/2, h/2);
    document.getElementById('anomalyBadge').style.display = 'none';
    return;
  }

  var pad = {top:20, bottom:52, left:32, right:16};
  var chartW = w - pad.left - pad.right;
  var chartH = h - pad.top - pad.bottom;

  // Background risk zone bands
  [{from:0,to:15,c:'rgba(0,229,160,0.04)'},{from:15,to:40,c:'rgba(255,209,102,0.04)'},{from:40,to:70,c:'rgba(255,154,60,0.04)'},{from:70,to:100,c:'rgba(255,77,109,0.05)'}]
    .forEach(function(z) {
      var y1 = pad.top + chartH - (z.to/100)*chartH;
      var y2 = pad.top + chartH - (z.from/100)*chartH;
      ctx.fillStyle = z.c;
      ctx.fillRect(pad.left, y1, chartW, y2-y1);
    });

  // Grid lines + Y-axis labels
  ctx.font = '9px monospace';
  ctx.textAlign = 'right';
  [0,25,50,75,100].forEach(function(v) {
    var y = pad.top + chartH - (v/100)*chartH;
    ctx.fillStyle = '#5a5a7a';
    ctx.fillText(v, pad.left-4, y+3);
    ctx.strokeStyle = 'rgba(255,255,255,0.04)';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w-pad.right, y); ctx.stroke();
  });

  // Anomaly detection
  var anomalies = new Set();
  for (var i = 1; i < items.length; i++) {
    if ((items[i].score||0) - (items[i-1].score||0) > 30) anomalies.add(i);
  }
  var seenSusp = {};
  items.forEach(function(item, i) {
    if (item.level === 'SUSPICIOUS' || item.level === 'PHISHING') {
      if (seenSusp[item.hostname] !== undefined) {
        anomalies.add(i);
        anomalies.add(seenSusp[item.hostname]);
      } else {
        seenSusp[item.hostname] = i;
      }
    }
  });

  // Point coordinates
  var n = items.length;
  var step = n > 1 ? chartW / (n-1) : 0;
  var pts = items.map(function(item, i) {
    return {
      x: pad.left + (n===1 ? chartW/2 : i*step),
      y: pad.top + chartH - (Math.min(100,Math.max(0,item.score||0))/100)*chartH,
      item: item
    };
  });

  // Area fill under line
  if (pts.length > 1) {
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pad.top+chartH);
    pts.forEach(function(p) { ctx.lineTo(p.x, p.y); });
    ctx.lineTo(pts[pts.length-1].x, pad.top+chartH);
    ctx.closePath();
    ctx.fillStyle = 'rgba(108,99,255,0.07)';
    ctx.fill();
  }

  // Line
  if (pts.length > 1) {
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (var j = 1; j < pts.length; j++) ctx.lineTo(pts[j].x, pts[j].y);
    ctx.strokeStyle = 'rgba(108,99,255,0.45)';
    ctx.lineWidth = 2;
    ctx.stroke();
  }

  // Points, anomaly rings, x-labels
  pts.forEach(function(p, i) {
    var color = COLORS[p.item.level] || '#00e5a0';
    var isAnom = anomalies.has(i);

    if (isAnom) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 10, 0, Math.PI*2);
      ctx.strokeStyle = 'rgba(255,77,109,0.7)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.arc(p.x, p.y, 5, 0, Math.PI*2);
    ctx.fillStyle = color;
    ctx.fill();

    // Score label for high-risk points
    if ((p.item.score||0) >= 50) {
      ctx.fillStyle = color;
      ctx.font = 'bold 9px monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'bottom';
      ctx.fillText(p.item.score, p.x, p.y-7);
    }

    // Rotated x-axis label
    var label = (p.item.hostname||'').replace(/^www\./,'').slice(0,11);
    ctx.save();
    ctx.translate(p.x, pad.top+chartH+6);
    ctx.rotate(-Math.PI/4);
    ctx.fillStyle = isAnom ? '#ff4d6d' : '#5a5a7a';
    ctx.font = (isAnom ? 'bold ' : '')+'8px monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'top';
    ctx.fillText(label, 0, 0);
    ctx.restore();
  });

  // Anomaly badge in panel title
  var badge = document.getElementById('anomalyBadge');
  if (anomalies.size > 0) {
    badge.textContent = '⚠ '+anomalies.size+' anomal'+(anomalies.size===1?'y':'ies');
    badge.style.display = 'inline';
  } else {
    badge.style.display = 'none';
  }
}

// ── Table ─────────────────────────────────────────────────────
function renderTable() {
  var tbody = document.getElementById('historyTbody');
  var data  = activeFilter === 'ALL' ? history : history.filter(function(h){
    if (activeFilter === 'SAFE') return h.level==='SAFE'||h.level==='WHITELISTED'||h.level==='LOW RISK';
    return h.level === activeFilter;
  });

  if (data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state"><div class="icon">📭</div>No entries for this filter</div></td></tr>';
    return;
  }

  tbody.innerHTML = data.slice(0,100).map(function(item){
    var level = item.level || 'SAFE';
    var color = COLORS[level] || '#00e5a0';
    var time  = item.timestamp ? new Date(item.timestamp).toLocaleString() : '—';
    return '<tr>'+
      '<td class="td-url" title="'+item.hostname+'">'+item.hostname+'</td>'+
      '<td><span class="history-badge" style="background:'+color+'22;color:'+color+'">'+level+'</span></td>'+
      '<td style="font-family:monospace;color:'+color+'">'+item.score+'/100</td>'+
      '<td style="color:#5a5a7a;font-size:10px;font-family:monospace">'+time+'</td>'+
      '</tr>';
  }).join('');
}

// ── ML API check ──────────────────────────────────────────────
function checkML() {
  var el = document.getElementById('mlStatus');
  fetch('http://localhost:5000/health').then(function(r){ return r.json(); }).then(function(d){
    el.textContent  = 'ONLINE';
    el.style.color  = '#00e5a0';
  }).catch(function(){
    el.textContent = 'OFFLINE';
    el.style.color = '#ff4d6d';
  });
}

// ── Filter buttons ────────────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(function(btn){
  btn.addEventListener('click', function(){
    document.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
    btn.classList.add('active');
    activeFilter = btn.dataset.f;
    renderTable();
  });
});

// ── Clear ─────────────────────────────────────────────────────
document.getElementById('clearBtn').addEventListener('click', function(){
  if (confirm('Clear all scan history?')) {
    chrome.storage.local.set({history:[]}, function(){ history=[]; render(); });
  }
});

// ── Auto refresh ──────────────────────────────────────────────
setInterval(load, 8000);

// ── Start ─────────────────────────────────────────────────────
load();