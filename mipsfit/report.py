"""Portable report: candidate ranking, actionable findings and a cache map."""
import json
from pathlib import Path


def write_report(out, model, candidates, findings=(), simulation=None):
    """Writes report.html plus the JSON `simulate` needs to replay this analysis."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "model.json").write_text(json.dumps(model, indent=2),
                                    encoding="utf-8")
    (out / "candidates.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    traces = model.get("traces", [])

    data = json.dumps(dict(
        functions=[dict(name=f["name"], size=f["size"], source=f["source"], unit=f.get("unit"), offset=f.get("offset", 0),
                        address=f["address"]) for f in model["functions"]],
        units=[dict(id=u["id"], size=u["size"], movable=u["movable"], region=u["region"], address=u["address"],
                    executed=u.get("executed_bytes", 0), instructions=u.get("executed_instructions", 0),
                    misses=u.get("misses", 0)) for u in model["units"]],
        candidates=[dict(id=c["id"], rank=c["rank"], method=c["method"], cost=c["cost"], addresses=c["addresses"],
                         conflicts=c["conflicts"]) for c in candidates],
        findings=list(findings), traces=traces, simulation=simulation or {},
        warnings=model["warnings"])).replace("<", "\\u003c")
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>MipsFit report</title>
<style>body{font:15px system-ui;margin:24px;background:#111820;color:#e0e8f0}h1{font-size:24px}h2{font-size:19px;margin-top:26px}p{max-width:1000px}
select,input,button{padding:7px;background:#202e3c;color:inherit;border:1px solid #54718a;margin:4px;border-radius:4px}
button.on{background:#38536b}canvas{width:100%;image-rendering:pixelated;background:#25313d}
table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #334355;padding:6px}
th{position:sticky;top:0;background:#1d2935}.muted{color:#a8bacb}.scroll{max-height:460px;overflow:auto}
.num{text-align:right}.tab{display:none}.tab.on{display:block}.card{background:#1a2430;border:1px solid #2d3d4d;border-radius:6px;padding:12px;margin:8px 0}
#tip{position:fixed;display:none;z-index:9;pointer-events:none;max-width:420px;background:#0d141b;border:1px solid #54718a;
border-radius:5px;padding:7px 9px;font-size:13px;line-height:1.45;box-shadow:0 4px 14px #0008;overflow-wrap:anywhere}
#tip b{color:#8fd694}#tip .k{color:#a8bacb}
.big{font-size:22px}.win{color:#8fd694}.bad{color:#e88}</style>
<h1>MipsFit code layout report</h1>
<label>Candidate <select id="candidate"></select></label><span id="score" class="muted"></span>
<div><button data-tab="summary" class="on">Summary</button><button data-tab="actions">Actions</button>
<button data-tab="conflicts">Conflicts</button><button data-tab="functions">Functions</button><button data-tab="map">Cache map</button></div>
<div id="summary" class="tab on"></div>
<div id="actions" class="tab"><p class="muted">Potential source/build improvements and remaining conflicts. Savings are estimates from re-planning the layout with the change applied, not measurements.</p><div id="actionlist"></div></div>
<div id="conflicts" class="tab"><p class="muted">Strongest remaining interleaved pairs sharing a cache slot in the selected candidate.</p><div class="scroll"><table><thead><tr><th>Weight</th><th>Slot</th><th>Code A</th><th>Code B</th></tr></thead><tbody id="conflictrows"></tbody></table></div></div>
<div id="functions" class="tab"><p class="muted">Activity figures cover the entire placement unit and repeat for functions sharing that unit. Instructions and baseline misses are weighted per-frame averages across traces; executed bytes is the union of code reached across captures. Addresses follow the selected candidate.</p><input id="filter" placeholder="Filter function or source"><span id="count" class="muted"></span>
<div class="scroll"><table><thead><tr><th>Function</th><th class="num">Function bytes</th><th class="num">Unit executed bytes</th><th class="num">Unit instructions/frame</th><th class="num">Unit baseline misses/frame</th><th class="num">Address</th><th>Source</th></tr></thead><tbody id="rows"></tbody></table></div></div>
<div id="map" class="tab"><p class="muted">Each row is a 16 KiB window, each column one of 512 cache slots. Colour identifies the placement unit; brightness shows its instruction count on a log scale, not which individual lines ran. Dark units were not executed in the traces. Vertically aligned cells share a slot but conflict only when accessed. Hover for unit totals; misses refer to the baseline.</p><canvas id="cache"></canvas></div>
<div id="tip"></div>
<h2>Limitations</h2><ul id="warnings"></ul>
<script>const data=DATA;
const $=id=>document.getElementById(id), hex=n=>'0x'+(n>>>0).toString(16).padStart(8,'0'), fmt=n=>n===undefined||n===null?'—':(Math.round(n*100)/100).toLocaleString();
const units=new Map(data.units.map(u=>[u.id,u]));let cells=[],base=0,rowCount=0;
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e}
for(const c of data.candidates){const o=el('option',c.rank+'. '+c.id+' — '+c.method);o.value=c.id;$('candidate').appendChild(o)}
for(const w of data.warnings)$('warnings').appendChild(el('li',w));
for(const t of data.traces||[])for(const w of (t.warnings||[]))$('warnings').appendChild(el('li',w));
for(const b of document.querySelectorAll('button[data-tab]'))b.onclick=()=>{
  for(const x of document.querySelectorAll('button[data-tab]'))x.classList.toggle('on',x===b);
  for(const x of document.querySelectorAll('.tab'))x.classList.toggle('on',x.id===b.dataset.tab);
  if(b.dataset.tab==='map')drawMap();};
function selected(){return data.candidates.find(c=>c.id===$('candidate').value)}
function summary(){const c=selected(),cost=c.cost,bl=data.candidates.find(x=>x.id==='baseline'),d=$('summary');d.replaceChildren();
 const card=el('div',undefined,'card');
 const mpf=cost.misses_per_frame, base=bl&&bl.cost.misses_per_frame;
 card.appendChild(el('div','Estimated conflict cost: '+fmt(cost.alias),'big'));
 card.appendChild(el('div','How much code that takes turns running has to share the same cache spot, and so keeps evicting itself. A score for comparing layouts, not a count of anything — lower is better.','muted'));
 if(mpf!==undefined){const delta=base!==undefined?mpf-base:0;
  card.appendChild(el('div','Simulated misses per frame: '+fmt(mpf)+' = '+fmt(mpf*48)+' cycles/frame',delta<0?'win':(delta>0?'bad':'')));
  if(base!==undefined&&delta)card.appendChild(el('div',(delta<0?'Saves ':'Costs ')+fmt(Math.abs(delta))+' misses/frame vs baseline ('+fmt(Math.abs(delta)*48)+' cycles/frame)',delta<0?'win':'bad'));}
 card.appendChild(el('div','Padding: '+cost.padding_bytes+' bytes · order disruption: '+cost.disruption,'muted'));
 d.appendChild(card);
 const sim=data.simulation||{};
 if(sim.baseline){const s=el('div',undefined,'card');
  s.appendChild(el('div','Baseline replay — weighted averages across traces'));
  s.appendChild(el('div','misses/frame '+fmt(sim.baseline.misses_per_frame)+' · conflict '+fmt(sim.baseline.conflict_misses)+' · capacity '+fmt(sim.baseline.capacity_misses)+' · first touch '+fmt(sim.baseline.first_misses),'muted'));
  if(sim.associative!==undefined)s.appendChild(el('div','Fully associative LRU comparison: '+fmt(sim.associative)+' misses/frame. This is not a lower bound or a prediction of achievable savings. Miss classification uses the same LRU reference; initial recency is unknown, and first touches are counted since capture/reset.','muted'));
  if(sim.working_set!==undefined){const over=sim.working_set/512;
   s.appendChild(el('div','Code touched per frame: '+fmt(sim.working_set)+' distinct lines ('+fmt(sim.working_set*32/1024)+' KiB) against a 512-line, 16 KiB cache'+
    (over>1?' — '+fmt(over)+'× cache capacity.':'.')+' Peak: '+fmt(sim.working_set_max)+' lines. Footprint alone does not determine capacity misses.','muted'));}
  d.appendChild(s);}
 for(const t of (data.traces||[])){const row=cost.traces&&cost.traces[t.name];if(!row)continue;
  const s=el('div',undefined,'card');s.appendChild(el('div',t.name+': '+fmt(row.misses_per_frame)+' misses/frame over '+row.frames+' frames'+(row.sampled?' (sampled)':'')));
  const cal=t.calibration||{};s.appendChild(el('div','Replay vs emulator: '+(cal.exact?'exact':(cal.frames_differing+' frames differ'))+' · captured with the '+(cal.executor||'?'),'muted'));
  d.appendChild(s);}}
function actions(){const d=$('actionlist');d.replaceChildren();
 if(!data.findings.length){d.appendChild(el('p','No findings listed; findings may have been disabled.','muted'));return}
 for(const f of data.findings){const card=el('div',undefined,'card');
  card.appendChild(el('div',f.title,'big'));
  if(f.where)card.appendChild(el('div',f.where,'muted'));
  card.appendChild(el('div',f.detail));
  if(f.savings!==null&&f.savings!==undefined)card.appendChild(el('div','Estimated saving: '+fmt(f.savings)+' misses/frame ('+fmt(f.savings*48)+' cycles)','win'));
  card.appendChild(el('div','Suggested change: '+f.suggestion));
  for(const s of (f.sources||[]))card.appendChild(el('div',s,'muted'));
  d.appendChild(card)}}
function conflicts(){const c=selected(),t=$('conflictrows');t.replaceChildren();
 for(const p of c.conflicts){const tr=el('tr');
  for(const v of [fmt(p.weight),p.slot,p.a.unit+' +'+hex(p.a.offset),p.b.unit+' +'+hex(p.b.offset)])tr.appendChild(el('td',v));
  t.appendChild(tr)}}
function table(){const c=selected(),q=$('filter').value.toLowerCase();$('rows').replaceChildren();let n=0;
 const list=[...data.functions].sort((a,b)=>b.size-a.size);
 for(const f of list){if(!(f.name+' '+f.source).toLowerCase().includes(q))continue;if(++n>400)break;
  const u=f.unit?units.get(f.unit):null,addr=f.unit&&c.addresses[f.unit]!==undefined?c.addresses[f.unit]+f.offset:f.address;
  const tr=el('tr');
  for(const v of [f.name,f.size,u?fmt(u.executed):'—',u?fmt(u.instructions):'—',u?fmt(u.misses):'—',hex(addr),f.source])tr.appendChild(el('td',v));
  $('rows').appendChild(tr)}
 $('count').textContent=n+' functions'}
function drawMap(){const c=selected(),list=data.units.filter(u=>u.size);
 base=Math.floor(Math.min(...list.map(u=>c.addresses[u.id]))/16384)*16384;
 rowCount=Math.ceil((Math.max(...list.map(u=>c.addresses[u.id]+u.size))-base)/16384);
 const canvas=$('cache');canvas.width=512;canvas.height=Math.max(rowCount*12,12);
 const ctx=canvas.getContext('2d');ctx.clearRect(0,0,512,canvas.height);cells=[];
 // a handful of units run orders of magnitude more than the rest, so brightness
 // follows a log scale and every unit that ran at all starts well above the
 // near-black used for code the trace never reached
 const hottest=Math.max(1,...list.map(u=>u.instructions||0)),span=Math.log1p(hottest);
 list.forEach((u,i)=>{const n=u.instructions||0,hue=(i*137.508)%360;
  const t=n?0.05+0.95*(span?Math.log1p(n)/span:1):0;
  ctx.fillStyle=n?'hsl('+hue+' '+(34+56*t)+'% '+(28+44*t)+'%)':'hsl('+hue+' 14% 25%)';
  for(let a=Math.floor(c.addresses[u.id]/32)*32;a<c.addresses[u.id]+u.size;a+=32){const n=(a-base)/32;cells[n]=u;ctx.fillRect(n%512,Math.floor(n/512)*12,1,10)}});}
function slotAt(e){const r=$('cache').getBoundingClientRect();
 const x=Math.min(511,Math.max(0,Math.floor((e.clientX-r.left)/r.width*512)));
 const y=Math.min(rowCount-1,Math.max(0,Math.floor((e.clientY-r.top)/r.height*rowCount)));
 return {x,y,cell:(r.width/512),unit:cells[y*512+x],address:base+(y*512+x)*32}}
$('cache').onmousemove=e=>{const t=$('tip');if(!rowCount){t.style.display='none';return}
 const s=slotAt(e),u=s.unit;
 t.replaceChildren();
 t.appendChild(el('div',u?u.id:'unassigned','' ));
 const meta=el('div',undefined,'k');
 meta.textContent=hex(s.address)+' · slot '+s.x+' · window '+s.y;
 t.appendChild(meta);
 if(u){const b=el('div');b.appendChild(el('b',fmt(u.instructions)+' instructions/frame'));
  b.appendChild(document.createTextNode(' · '+fmt(u.misses)+' misses/frame'));t.appendChild(b);
  t.appendChild(el('div',u.size+' bytes · '+(u.movable?'movable':'pinned'),'k'));}
 t.style.display='block';
 // anchor to the hovered slot, flipping when close to an edge
 const r=$('cache').getBoundingClientRect(),w=t.offsetWidth||260,h=t.offsetHeight||64;
 let left=r.left+(s.x+0.5)*s.cell+12, top=e.clientY+16;
 if(left+w>innerWidth-8)left=Math.max(8,r.left+(s.x+0.5)*s.cell-w-12);
 if(top+h>innerHeight-8)top=Math.max(8,e.clientY-h-12);
 t.style.left=left+'px';t.style.top=top+'px'};
$('cache').onmouseleave=()=>{$('tip').style.display='none'};
function render(){const c=selected();
 $('score').textContent=c.cost.misses_per_frame!==undefined?fmt(c.cost.misses_per_frame)+' simulated misses/frame':fmt(c.cost.alias)+' estimated conflict cost';
 summary();actions();conflicts();table();if($('map').classList.contains('on'))drawMap()}
$('candidate').onchange=render;$('filter').oninput=table;render();
</script></html>'''.replace("DATA", data)
    (out / "report.html").write_text(page, encoding="utf-8")
