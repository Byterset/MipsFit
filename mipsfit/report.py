"""Portable report: candidate ranking, actionable findings and a cache map."""
import json
from collections import defaultdict
from pathlib import Path

from .trg import alias_pairs, lines


def relationship_data(graph, units, candidates):
    """Aggregate undirected chunk edges by unit, keeping exact conflict lines.

    Only the report needs these data. The extra unit index denotes code outside
    mapped units; its relationships remain visible in the ranked list.
    """
    weights = defaultdict(float)
    for a, neighbors in enumerate(graph.neighbors):
        for b, weight in neighbors.items():
            if a < b:
                ua, ub = sorted((graph.unit[a], graph.unit[b]))
                weights[ua, ub] += weight
    conflicts = {}
    for candidate in candidates:
        base = [candidate["addresses"][u["id"]] for u in units] + [0]
        line = lines(graph, base)
        pairs = {}
        for weight, a, b in alias_pairs(graph, base):
            ua, ub = graph.unit[a], graph.unit[b]
            if ua > ub:
                ua, ub, a, b = ub, ua, b, a
            entry = pairs.setdefault((ua, ub), [0.0, set(), set()])
            entry[0] += weight
            entry[1].add(line[a])
            entry[2].add(line[b])
        conflicts[candidate["id"]] = [
            [a, b, weight, sorted(first), sorted(second)]
            for (a, b), (weight, first, second) in sorted(pairs.items())]
    return dict(source=graph.source, edges=[[a, b, w] for (a, b), w in sorted(weights.items())],
                conflicts=conflicts)


def write_report(out, model, candidates, graph, findings=(), simulation=None):
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
        relationships=relationship_data(graph, model["units"], candidates),
        findings=list(findings), traces=traces, simulation=simulation or {},
        warnings=model["warnings"])).replace("<", "\\u003c")
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>MipsFit report</title>
<style>body{font:15px system-ui;margin:24px;background:#111820;color:#e0e8f0}h1{font-size:24px}h2{font-size:19px;margin-top:26px}p{max-width:1000px}
select,input,button{padding:7px;background:#202e3c;color:inherit;border:1px solid #54718a;margin:4px;border-radius:4px}
button.on{background:#38536b}canvas{width:100%;image-rendering:pixelated;background:#25313d}
table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #334355;padding:6px}
th{position:sticky;top:0;background:#1d2935}.muted{color:#a8bacb}.scroll{max-height:460px;overflow:auto}
.num{text-align:right}.tab{display:none}.tab.on{display:block}.card{background:#1a2430;border:1px solid #2d3d4d;border-radius:6px;padding:12px;margin:8px 0;overflow-wrap:anywhere}
#tip{position:fixed;display:none;z-index:9;pointer-events:none;max-width:420px;background:#0d141b;border:1px solid #54718a;
border-radius:5px;padding:7px 9px;font-size:13px;line-height:1.45;box-shadow:0 4px 14px #0008;overflow-wrap:anywhere}
#tip b{color:#8fd694}#tip .k{color:#a8bacb}
#cache{cursor:pointer}#relationships{overflow-wrap:anywhere}#relationships[hidden]{display:none}
#mapLegend{max-width:none}.selection-key{color:#fff}.conflict-key{color:#ffb454}
.big{font-size:22px}.win{color:#8fd694}.bad{color:#e88}</style>
<h1>MipsFit code layout report</h1>
<label id="candidateControl">Candidate <select id="candidate"></select></label><span id="score" class="muted"></span>
<div><button data-tab="summary" class="on">Summary</button><button data-tab="actions">Actions</button>
<button data-tab="conflicts">Conflicts</button><button data-tab="functions">Functions</button><button data-tab="map">Cache map</button></div>
<div id="summary" class="tab on"></div>
<div id="actions" class="tab"><p class="muted">Potential source/build improvements and remaining conflicts. Savings are estimates from re-planning the layout with the change applied, not measurements.</p><div id="actionlist"></div></div>
<div id="conflicts" class="tab"><p class="muted">Strongest remaining interleaved pairs sharing a cache slot in the selected candidate.</p><div class="scroll"><table><thead><tr><th>Weight</th><th>Slot</th><th>Code A</th><th>Code B</th></tr></thead><tbody id="conflictrows"></tbody></table></div></div>
<div id="functions" class="tab"><p class="muted">Activity figures cover the entire placement unit and repeat for functions sharing that unit. Instructions and baseline misses are weighted per-frame averages across traces; executed bytes is the union of code reached across captures. Addresses follow the selected candidate.</p><input id="filter" placeholder="Filter function or source"><span id="count" class="muted"></span>
<div class="scroll"><table><thead><tr><th>Function</th><th class="num">Function bytes</th><th class="num">Unit executed bytes</th><th class="num">Unit instructions/frame</th><th class="num">Unit baseline misses/frame</th><th class="num">Address</th><th>Source</th></tr></thead><tbody id="rows"></tbody></table></div></div>
<div id="map" class="tab"><p class="muted">Each row is a 16 KiB window, each column one of 512 cache slots. Colours identify placement units, which may contain multiple functions. Hover for unit totals; misses refer to the baseline. Click a block to show its relationships, or another block to switch. The Candidate dropdown preserves the selection and updates conflicts for that layout. Click the selected block again or elsewhere outside the map to restore normal heat.</p>
<canvas id="cache" role="img" aria-label="Code placement by cache slot; click a block to select its relationships"></canvas>
<p id="mapLegend" class="muted" aria-live="polite"></p>
<div id="relationships" hidden><h2 id="relationshipTitle"></h2><p id="relationshipNote" class="muted"></p>
<table><thead><tr><th>Related placement unit</th><th class="num">Relationship weight</th><th class="num">Conflicting weight</th></tr></thead><tbody id="relationshipRows"></tbody></table></div></div>
<div id="tip"></div>
<h2>Limitations</h2><ul id="warnings"></ul>
<script>const data=DATA;
const $=id=>document.getElementById(id), hex=n=>'0x'+(n>>>0).toString(16).padStart(8,'0'), fmt=n=>n===undefined||n===null?'—':(Math.round(n*100)/100).toLocaleString();
const units=new Map(data.units.map(u=>[u.id,u])),unitIndex=new Map(data.units.map((u,i)=>[u.id,i]));
const relationships=data.relationships,neighbors=new Map(),functionNames=new Map();
let cells=[],base=0,rowCount=0,pinnedUnit=null;
for(const f of data.functions){if(!f.unit||!f.name||f.name==='??')continue;const names=functionNames.get(f.unit)||[];if(!names.includes(f.name))names.push(f.name);functionNames.set(f.unit,names)}
for(const [a,b,weight] of relationships.edges){
 if(!neighbors.has(a))neighbors.set(a,new Map());neighbors.get(a).set(b,weight);
 if(a!==b){if(!neighbors.has(b))neighbors.set(b,new Map());neighbors.get(b).set(a,weight)}}
function unitName(index){const u=data.units[index];if(!u)return 'Code outside mapped units';
 const names=functionNames.get(u.id)||[];return names.length?names.slice(0,3).join(', ')+(names.length>3?' +'+(names.length-3)+' more':''):u.id}
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
function relationState(c){const related=new Map(),marked=new Set();
 if(pinnedUnit!==null){
  for(const [unit,weight] of neighbors.get(pinnedUnit)||[])related.set(unit,{weight,conflict:0});
  for(const [a,b,weight,first,second] of relationships.conflicts[c.id]){
   if(a!==pinnedUnit&&b!==pinnedUnit)continue;
   related.get(a===pinnedUnit?b:a).conflict+=weight;
   for(const line of first)marked.add(line);for(const line of second)marked.add(line)}}
 return {related,marked}}
function relationshipPanel(related){const legend=$('mapLegend'),panel=$('relationships');legend.replaceChildren();
 panel.hidden=pinnedUnit===null;
 if(pinnedUnit===null){legend.textContent='Heat: instructions/frame (log scale). Brightness covers each whole unit, not individual executed lines.';return}
 const mode=relationships.source==='trace'?'Temporal relationships':'Static relationship estimate';
 legend.appendChild(el('span','White outline: selected unit. ','selection-key'));
 legend.appendChild(document.createTextNode('Brightness: relationship strength relative to its strongest neighbor (log scale). '));
 legend.appendChild(el('span','Orange outlines: related chunks sharing a cache slot.','conflict-key'));
 $('relationshipTitle').textContent=mode+' — '+unitName(pinnedUnit);
 const rows=[...related].sort((a,b)=>b[1].weight-a[1].weight||a[0]-b[0]);
 $('relationshipNote').textContent=(rows.length?'Strongest '+Math.min(10,rows.length)+' of '+rows.length+' retained relationships. ':'No retained relationships for this unit. ')+
  (relationships.source==='trace'?'Weights sum chunk-level interleaving from the optimizer’s graph. ':'Weights come from static call/return estimates, not a captured execution order. ')+
  'Conflicting weight is the portion contributing to this layout’s graph score, not measured misses. Missing edges do not prove that code never interacts.';
 const body=$('relationshipRows');body.replaceChildren();
 for(const [index,row] of rows.slice(0,10)){const tr=el('tr'),name=el('td',(index===pinnedUnit?'Within selected unit: ':'')+unitName(index));
  if(data.units[index]&&data.units[index].id!==unitName(index))name.appendChild(el('div',data.units[index].id,'muted'));
  tr.appendChild(name);tr.appendChild(el('td',fmt(row.weight),'num'));
  tr.appendChild(el('td',fmt(row.conflict)+' ('+fmt(100*row.conflict/row.weight)+'%)','num'));body.appendChild(tr)}}
function drawMap(){const c=selected(),list=data.units.filter(u=>u.size),{related,marked}=relationState(c);
 relationshipPanel(related);
 if(!list.length){cells=[];rowCount=0;return}
 base=Math.floor(Math.min(...list.map(u=>c.addresses[u.id]))/16384)*16384;
 rowCount=Math.ceil((Math.max(...list.map(u=>c.addresses[u.id]+u.size))-base)/16384);
 // Extra backing resolution keeps thin outlines readable without changing the map geometry.
 const canvas=$('cache');canvas.width=512*4;canvas.height=Math.max(rowCount*12,12)*4;
 const ctx=canvas.getContext('2d');ctx.scale(4,4);cells=[];
 const hottest=Math.max(1,...list.map(u=>u.instructions||0)),span=Math.log1p(hottest);
 let strongest=0;for(const [index,row] of related)if(index!==pinnedUnit)strongest=Math.max(strongest,row.weight);
 const strengthSpan=Math.log1p(strongest);
 list.forEach(u=>{const i=unitIndex.get(u.id),n=u.instructions||0,hue=(i*137.508)%360;
  if(pinnedUnit===null){const t=n?0.05+0.95*(span?Math.log1p(n)/span:1):0;
   ctx.fillStyle=n?'hsl('+hue+' '+(34+56*t)+'% '+(28+44*t)+'%)':'hsl('+hue+' 14% 25%)';
  }else{const weight=related.get(i)?.weight||0,t=strengthSpan?Math.log1p(weight)/strengthSpan:0;
   ctx.fillStyle=i===pinnedUnit?'hsl('+hue+' 55% 50%)':weight?'hsl('+hue+' '+(40+50*t)+'% '+(30+42*t)+'%)':'hsl('+hue+' 10% 13%)'}
  for(let a=Math.floor(c.addresses[u.id]/32)*32;a<c.addresses[u.id]+u.size;a+=32){const n=(a-base)/32;cells[n]=u;ctx.fillRect(n%512,Math.floor(n/512)*12,1,10)}});
 if(pinnedUnit!==null){const u=data.units[pinnedUnit],first=Math.floor(c.addresses[u.id]/32)-base/32,last=Math.ceil((c.addresses[u.id]+u.size)/32)-base/32;
  ctx.strokeStyle='#fff';ctx.lineWidth=0.5;
  for(let start=first;start<last;){const end=Math.min(last,(Math.floor(start/512)+1)*512);
   ctx.strokeRect(start%512+0.25,Math.floor(start/512)*12+0.25,end-start-0.5,9.5);start=end}
  ctx.strokeStyle='#ffb454';
  const markedCells=[...marked].map(line=>line-base/32).filter(n=>n>=0&&n<rowCount*512).sort((a,b)=>a-b);
  for(let i=0;i<markedCells.length;){const start=markedCells[i++];let end=start+1;
   while(i<markedCells.length&&markedCells[i]===end&&Math.floor(end/512)===Math.floor(start/512)){end++;i++}
   ctx.strokeRect(start%512+0.25,Math.floor(start/512)*12+2,end-start-0.5,6)}}}
function slotAt(e){const r=$('cache').getBoundingClientRect();
 const x=Math.min(511,Math.max(0,Math.floor((e.clientX-r.left)/r.width*512)));
 const y=Math.min(rowCount-1,Math.max(0,Math.floor((e.clientY-r.top)/r.height*rowCount)));
 return {x,y,cell:(r.width/512),unit:cells[y*512+x],address:base+(y*512+x)*32}}
$('cache').onmousemove=e=>{const t=$('tip');if(!rowCount){t.style.display='none';return}
 const s=slotAt(e),u=s.unit;
 t.replaceChildren();
 const name=u?unitName(unitIndex.get(u.id)):'unassigned';
 t.appendChild(el('div',name));
 if(u&&name!==u.id)t.appendChild(el('div',u.id,'k'));
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
// Hover only updates the tooltip. A click is the only way to pin or switch a unit.
$('cache').onclick=e=>{if(!rowCount)return;const u=slotAt(e).unit;if(!u)return;
 const index=unitIndex.get(u.id);pinnedUnit=pinnedUnit===index?null:index;drawMap()};
document.addEventListener('click',e=>{if(e.target!==$('cache')&&!$('candidateControl').contains(e.target)&&pinnedUnit!==null){pinnedUnit=null;drawMap()}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&pinnedUnit!==null){pinnedUnit=null;drawMap()}});
function render(){const c=selected();
 $('score').textContent=c.cost.misses_per_frame!==undefined?fmt(c.cost.misses_per_frame)+' simulated misses/frame':fmt(c.cost.alias)+' estimated conflict cost';
 summary();actions();conflicts();table();if($('map').classList.contains('on'))drawMap()}
$('candidate').onchange=render;$('filter').oninput=table;render();
</script></html>'''.replace("DATA", data)
    (out / "report.html").write_text(page, encoding="utf-8")
