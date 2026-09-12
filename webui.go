package main

import (
	"os/exec"
	"runtime"
)

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = hidden("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = hidden("open", url)
	default:
		cmd = hidden("xdg-open", url)
	}
	_ = cmd.Start()
}

const webHTML = `<!doctype html><html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nwtoolkit</title>
<style>
:root{--bg:#0f1419;--panel:#1a2029;--line:#2a333f;--fg:#e6edf3;--mut:#8b98a5;--acc:#3ebbc1;--ok:#3fb950;--warn:#d29922;--err:#f85149}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
header b{font-size:18px;letter-spacing:.5px}
header span{color:var(--mut);font-size:12px}
nav{display:flex;gap:4px;padding:10px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
nav button{background:transparent;border:1px solid var(--line);color:var(--mut);padding:7px 14px;border-radius:7px;cursor:pointer;font-size:13px}
nav button.active{background:var(--acc);border-color:var(--acc);color:#04252a;font-weight:600}
main{padding:20px;max-width:1000px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:18px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end;margin-bottom:14px}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin-bottom:4px}
input,select{background:var(--bg);border:1px solid var(--line);color:var(--fg);padding:8px 10px;border-radius:7px;font-size:14px}
input{width:190px}
button.go{background:var(--acc);border:none;color:#04252a;font-weight:600;padding:9px 16px;border-radius:7px;cursor:pointer}
button.stop{background:var(--err);border:none;color:#fff;padding:9px 16px;border-radius:7px;cursor:pointer}
.stat{display:inline-block;margin-right:22px}
.stat b{font-size:20px;display:block}
.stat small{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
canvas{width:100%;height:200px;background:var(--bg);border:1px solid var(--line);border-radius:8px;margin-top:10px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font:13px/1.5 ui-monospace,Consolas,monospace;margin:0;white-space:pre-wrap}
table{width:100%;border-collapse:collapse;font:13px ui-monospace,Consolas,monospace}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:500}
.hint{color:var(--mut);font-size:12px;margin-top:8px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
</style></head><body>
<header><b>nwtoolkit</b><span>network diagnostics &middot; v1.28</span><span style="margin-left:auto"><label style="display:inline;text-transform:none;letter-spacing:0;color:var(--fg);font-size:13px">IP version <select id="ipver" style="margin-left:6px"><option>IPv4</option><option>IPv6</option></select></label></span></header>
<nav id="tabs">
 <button data-t="ping" class="active">Ping</button>
 <button data-t="trace">Traceroute</button>
 <button data-t="dns">DNS query</button>
 <button data-t="dnsspeed">DNS speed test</button>
 <button data-t="dhcp">DHCP speed test</button>
 <button data-t="lldp">LLDP neighbour</button>
 <button data-t="about">About</button>
</nav>
<main>

<section id="ping" class="tab">
 <div class="card">
  <div class="row">
   <div><label>Host / IP</label><input id="p_host" value="1.1.1.1"></div>
   <div><label>Interval (s)</label><input id="p_int" value="1" style="width:80px"></div>
   <button class="go" onclick="startLoop('ping')">Start</button>
   <button class="stop" onclick="stopLoop()">Stop</button>
  </div>
  <div id="p_stats"></div>
  <canvas id="p_cv"></canvas>
  <pre id="p_log" style="margin-top:10px;max-height:160px"></pre>
 </div>
</section>

<section id="trace" class="tab" hidden>
 <div class="card">
  <div class="row">
   <div><label>Host / IP</label><input id="t_host" value="example.com"></div>
   <div><label>Max hops</label><input id="t_max" value="30" style="width:80px"></div>
   <div><label>Names</label><select id="t_res"><option value="0">no</option><option value="1">yes (reverse DNS)</option></select></div>
   <div><label>Repeat (s)</label><input id="t_int" value="0" style="width:80px"></div>
   <button class="go" onclick="startTrace()">Start</button>
   <button class="stop" onclick="stopLoop()">Stop</button>
  </div>
  <div class="hint">Repeat = 0 &rarr; one-shot. &gt;0 &rarr; continuous monitor that refreshes the table.</div>
  <table id="t_tbl"><thead><tr><th>hop</th><th>adres</th><th>rtt (ms)</th></tr></thead><tbody></tbody></table>
 </div>
</section>

<section id="dns" class="tab" hidden>
 <div class="card">
  <div class="row">
   <div><label>Name</label><input id="d_name" value="example.com"></div>
   <div><label>Server (empty = system)</label><input id="d_srv" placeholder="e.g. 1.1.1.1"></div>
   <div><label>Type</label><select id="d_type"><option>A</option><option>AAAA</option><option>MX</option><option>TXT</option><option>NS</option><option>CNAME</option><option>SOA</option><option>PTR</option></select></div>
   <button class="go" onclick="dnsOnce()">Query</button>
  </div>
  <div id="d_stat"></div>
  <pre id="d_out"></pre>
 </div>
</section>

<section id="dnsspeed" class="tab" hidden>
 <div class="card">
  <div class="row">
   <div><label>Name</label><input id="ds_name" value="example.com"></div>
   <div><label>Server (empty = system)</label><input id="ds_srv" placeholder="e.g. 1.1.1.1"></div>
   <div><label>Interval (s)</label><input id="ds_int" value="5" style="width:80px"></div>
   <button class="go" onclick="startLoop('dnsspeed')">Start</button>
   <button class="stop" onclick="stopLoop()">Stop</button>
  </div>
  <div id="ds_stats"></div>
  <canvas id="ds_cv"></canvas>
 </div>
</section>

<section id="dhcp" class="tab" hidden>
 <div class="card">
  <div class="row">
   <div><label>DHCP server (empty = broadcast)</label><input id="dh_srv" placeholder="empty = DISCOVER on :68"></div>
   <div><label>Interval (s)</label><input id="dh_int" value="5" style="width:80px"></div>
   <button class="go" onclick="startLoop('dhcp')">Start</button>
   <button class="stop" onclick="stopLoop()">Stop</button>
  </div>
  <div class="hint">Empty field = broadcast to the network itself, with no prior knowledge of any server; every server that answers is listed. Filling in a server IP measures that one server with a unicast INFORM.</div>
  <div id="dh_stats"></div>
  <canvas id="dh_cv"></canvas>
 </div>
</section>

<section id="lldp" class="tab" hidden>
 <div class="card">
  <div class="row">
   <div><label>Interface</label><select id="ll_if"><option value="">automatic</option></select></div>
   <div><label>Wait (s)</label><input id="ll_wait" value="35" style="width:90px"></div>
   <button class="go" onclick="lldpGo()">Find neighbour</button>
  </div>
  <div class="hint">Asks the connected switch and port over LLDP. Can take up to ~30 s, because LLDP is sent periodically. On Windows this goes through the built-in pktmon, so run as Administrator.</div>
  <div id="ll_out"></div>
 </div>
</section>

<section id="about" class="tab" hidden>
 <div class="card">
  <div style="font-size:20px;font-weight:600;margin-bottom:10px">nwtoolkit v1.28</div>
  <p>Network diagnostic tool for IPv4, IPv6 and LLDP.</p>
  <p>Made by vibe coding using Anthropic's Claude*.</p>
  <p>Software is licensed under the MIT license. If you have any suggestions, bug fixes or want to get in touch visit <a href="https://github.com/bruijnes/" target="_blank" style="color:var(--acc)">github.com/bruijnes</a>.</p>
  <p class="hint">* Claude is a trademark of Anthropic, PBC.</p>
  <pre style="max-height:280px;overflow:auto;background:var(--panel,#f0f0f0);border:1px solid #ccc;border-radius:6px;padding:12px;margin-top:14px;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap">MIT License

Copyright (c) 2026 Vincent Bruijnes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.</pre>
 </div>
</section>

</main>
<script>
var timer=null, series=[], logs=[];
function $(id){return document.getElementById(id)}
document.querySelectorAll('#tabs button').forEach(function(b){b.onclick=function(){
 stopLoop();
 document.querySelectorAll('#tabs button').forEach(function(x){x.classList.remove('active')});
 b.classList.add('active');
 document.querySelectorAll('.tab').forEach(function(s){s.hidden=true});
 $(b.dataset.t).hidden=false;
}});
function stopLoop(){if(timer){clearInterval(timer);timer=null}}
function v6p(){return ($("ipver")&&$("ipver").value==="IPv6")?"&v6=1":""}
function fmt(n){return n==null?'-':n.toFixed(2)}

function drawChart(cv,data,unit){
 var dpr=window.devicePixelRatio||1, w=cv.clientWidth, h=cv.clientHeight;
 cv.width=w*dpr; cv.height=h*dpr; var x=cv.getContext('2d'); x.scale(dpr,dpr);
 x.clearRect(0,0,w,h);
 var pad=34, vals=data.filter(function(v){return v!=null});
 if(!vals.length){return}
 var mn=Math.min.apply(null,vals), mx=Math.max.apply(null,vals);
 if(mx-mn<1){mx=mn+1} mn=Math.max(0,mn-(mx-mn)*0.1); mx=mx+(mx-mn)*0.1;
 var gx=function(i){return pad+(w-pad-8)*(data.length<2?0:i/(data.length-1))};
 var gy=function(v){return h-24-(h-34)*((v-mn)/(mx-mn))};
 x.strokeStyle='#2a333f'; x.fillStyle='#8b98a5'; x.font='11px system-ui'; x.lineWidth=1;
 for(var k=0;k<=4;k++){var vy=mn+(mx-mn)*k/4, yy=gy(vy);
  x.beginPath();x.moveTo(pad,yy);x.lineTo(w-8,yy);x.stroke();
  x.fillText(vy.toFixed(0),4,yy+3);}
 x.strokeStyle='#3ebbc1'; x.lineWidth=2; x.beginPath(); var started=false;
 data.forEach(function(v,i){if(v==null){return} var px=gx(i),py=gy(v);
  if(!started){x.moveTo(px,py);started=true}else{x.lineTo(px,py)}});
 x.stroke();
 var last=vals[vals.length-1];
 x.fillStyle='#8b98a5';x.font='11px system-ui';
 x.fillText(unit,6,12);
 x.fillStyle='#e6edf3';x.font='12px system-ui';
 x.fillText('laatst '+last.toFixed(2)+' '+unit,w-150,16);
}
function statBlock(el,vals,unit){
 var v=vals.filter(function(z){return z!=null});
 if(!v.length){el.innerHTML='<span class=hint>waiting for a measurement…</span>';return}
 var mn=Math.min.apply(null,v),mx=Math.max.apply(null,v),av=v.reduce(function(a,b){return a+b},0)/v.length;
 var loss=Math.round((vals.length-v.length)/vals.length*100);
 var u='<small style="text-transform:none;letter-spacing:0"> '+unit+'</small>';
 el.innerHTML='<div class=stat><small>laatst</small><b>'+fmt(v[v.length-1])+u+'</b></div>'+
  '<div class=stat><small>min</small><b>'+fmt(mn)+u+'</b></div>'+
  '<div class=stat><small>gem</small><b>'+fmt(av)+u+'</b></div>'+
  '<div class=stat><small>max</small><b>'+fmt(mx)+u+'</b></div>'+
  '<div class=stat><small>verlies</small><b>'+loss+'%</b></div>'+
  '<div class=stat><small>metingen</small><b>'+vals.length+'</b></div>';
}

function startLoop(kind){
 stopLoop(); series=[]; logs=[];
 var int;
 var tick=function(){
  if(kind==='ping'){
   fetch('/api/ping?host='+encodeURIComponent($('p_host').value)+v6p()).then(function(r){return r.json()}).then(function(d){
    series.push(d.ok?d.rtt_ms:null);
    logs.unshift((new Date()).toLocaleTimeString()+'  '+(d.ok?('reply from '+d.from+'  '+d.rtt_ms.toFixed(2)+' ms'):('ERROR: '+(d.err||''))));
    logs=logs.slice(0,50);
    if(series.length>120)series=series.slice(-120);
    statBlock($('p_stats'),series,'ms'); drawChart($('p_cv'),series,'ms'); $('p_log').textContent=logs.join('\n');
   });
   int=parseFloat($('p_int').value)||1;
  } else if(kind==='dnsspeed'){
   fetch('/api/dns?type=HINFO&name='+encodeURIComponent($('ds_name').value)+'&server='+encodeURIComponent($('ds_srv').value)+v6p()).then(function(r){return r.json()}).then(function(d){
    series.push(d.ok?d.rtt_ms:null); if(series.length>120)series=series.slice(-120);
    statBlock($('ds_stats'),series,'ms'); drawChart($('ds_cv'),series,'ms');
   });
   int=parseFloat($('ds_int').value)||5;
  } else if(kind==='dhcp'){
   fetch('/api/dhcp?server='+encodeURIComponent($('dh_srv').value)+v6p()).then(function(r){return r.json()}).then(function(d){
    series.push(d.ok?d.rtt_ms:null); if(series.length>120)series=series.slice(-120);
    statBlock($('dh_stats'),series,'ms'); drawChart($('dh_cv'),series,'ms');
    if(!d.ok){var e=$('dh_stats');e.innerHTML+='<div class=hint style="color:var(--err)">'+(d.err||'')+'</div>'}
   });
   int=parseFloat($('dh_int').value)||5;
  }
 };
 tick(); timer=setInterval(tick,(int||1)*1000);
}

function dnsOnce(){
 fetch('/api/dns?name='+encodeURIComponent($('d_name').value)+'&server='+encodeURIComponent($('d_srv').value)+'&type='+$('d_type').value+v6p())
 .then(function(r){return r.json()}).then(function(d){
  if(d.ok){$('d_stat').innerHTML='<div class=stat><small>responstijd</small><b>'+d.rtt_ms.toFixed(2)+' ms</b></div><div class=stat><small>server</small><b style=font-size:15px>'+d.server+'</b></div>';
   $('d_out').textContent=(d.answers&&d.answers.length)?d.answers.join('\n'):'(no records)';}
  else{$('d_stat').innerHTML='<span style="color:var(--err)">ERROR: '+(d.err||'')+'  ('+d.rtt_ms.toFixed(2)+' ms)</span>';$('d_out').textContent='';}
 });
}

function startTrace(){
 stopLoop();
 var run=function(){
  var tb=$('t_tbl').querySelector('tbody');
  fetch('/api/traceroute?host='+encodeURIComponent($('t_host').value)+'&maxhops='+$('t_max').value+'&resolve='+$('t_res').value+v6p())
  .then(function(r){return r.json()}).then(function(d){
   if(!d.ok){tb.innerHTML='<tr><td colspan=3 style="color:var(--err)">'+(d.err||'')+'</td></tr>';return}
   tb.innerHTML=d.hops.map(function(h){
    var addr=h.ip?(h.name?h.name+' ('+h.ip+')':h.ip):'* * *';
    var rtts=(h.rtts||[]).map(function(x){return x<0?'*':x.toFixed(2)}).join('  ');
    var col=h.reached?'style="color:var(--ok)"':'';
    return '<tr '+col+'><td>'+h.n+'</td><td>'+addr+(h.reached?' ⇐ doel':'')+'</td><td>'+rtts+'</td></tr>';
   }).join('');
  });
 };
 run();
 var iv=parseFloat($('t_int').value)||0;
 if(iv>0)timer=setInterval(run,iv*1000);
}

// LLDP
fetch('/api/lldp/interfaces').then(function(r){return r.json()}).then(function(d){
 if(d.interfaces){var sel=$('ll_if');d.interfaces.forEach(function(name){var o=document.createElement('option');o.value=name;o.textContent=name;sel.appendChild(o)})}
}).catch(function(){});
function lldpGo(){
 var out=$('ll_out');
 out.innerHTML='<div class=hint>Searching for LLDP frames… this can take up to ~30 s.</div>';
 var wait=parseInt($('ll_wait').value)||35;
 var ifv=$('ll_if').value;
 fetch('/api/lldp?wait='+wait+'&iface='+encodeURIComponent(ifv)).then(function(r){return r.json()}).then(function(d){
  if(!d.ok){out.innerHTML='<div style="color:var(--err)">'+(d.err||'error')+'</div>';return}
  if(!d.neighbors||!d.neighbors.length){out.innerHTML='<div class=hint>No LLDP neighbour seen on '+(d.device||'')+'. LLDP may be disabled, or it is an unmanaged switch.</div>';return}
  out.innerHTML=d.neighbors.map(function(n){
   var rows=[['Systeemnaam',n.sysname],['Poort',n.port],['Poortomschrijving',n.portdesc],['VLAN',n.vlan>0?n.vlan:''],['Chassis-ID',n.chassis],['Mgmt-adres',n.mgmt],['Capabilities',n.caps],['TTL',n.ttl>0?n.ttl+' s':''],['Systeeminfo',n.sysdesc]];
   return '<div class=card style="background:var(--bg)"><table>'+rows.filter(function(r){return r[1]!==''&&r[1]!=null}).map(function(r){
    return '<tr><th style="width:160px">'+r[0]+'</th><td>'+String(r[1])+'</td></tr>'}).join('')+'</table></div>';
  }).join('');
 }).catch(function(e){out.innerHTML='<div style="color:var(--err)">'+e+'</div>'});
}
</script></body></html>`
