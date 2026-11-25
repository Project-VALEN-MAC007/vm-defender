/* Rabbit Hole overview tab, centred on Jev: is Jev running, how deep attackers go, Jev vs its fallback.
   Uses globals from dashboard.js: rh, renderRabbit, $, escapeHtml, when, pct, secs. */
(function(){
  const GROUPS=[
    {id:'jev',name:'Jev',short:'Jev',cls:'jev'},
    {id:'fallback',name:'ตัวสำรอง',short:'สำรอง',cls:'fallback'}];
  const GOAL={recon:'สำรวจระบบ',credential_hunting:'หารหัสผ่าน/คีย์',data_theft:'ขโมยข้อมูล',exploitation:'โจมตีช่องโหว่',persistence:'พยายามฝังตัว',other:'ยังไม่ชัด'};
  const CATEGORY={recon:'สำรวจ',config:'ไฟล์ตั้งค่า',credential:'รหัส/คีย์',backup:'แบ็กอัป',data:'ข้อมูลลับ',admin:'หน้าแอดมิน',notes:'บันทึก',api:'API'};
  const num=v=>(v||0).toLocaleString('th-TH');

  function reach(dist,depth){return Object.entries(dist||{}).filter(([k])=>Number(k)>=depth).reduce((a,[,v])=>a+v,0)}

  function names(d){
    const map={};
    ((d.pool&&d.pool.items)||[]).concat((d.pool&&d.pool.shell_items)||[]).forEach(i=>{map[i.id]=i.path});
    (d.scenarios||[]).forEach(s=>(s.nodes||[]).forEach(n=>{if(!map[n.id])map[n.id]=n.path}));
    return map;
  }

  /* ---------- Jev panel: summary, goals, timeline, attackers (list + detail), decision log ---------- */
  const jv={ip:null,page:0,q:'',goal:'',sort:'updated',logPage:0,logQ:'',detail:null,detailIp:null};
  const PAGE=12,LOGPAGE=10;
  const pc=v=>v==null?'-':Math.round(v*100)+'%';

  function skeleton(){
    $('rh-jev-status').innerHTML=`
      <div class="jv-head" id="jv-head"></div>
      <div class="jv-row2">
        <section class="jv-panel"><h5>เป้าหมายผู้โจมตี</h5><div id="jv-goals"></div></section>
        <section class="jv-panel"><h5>เบาะแสที่ถูกเดินตาม <small id="jv-tl-unit"></small></h5><div id="jv-timeline"></div></section>
      </div>
      <section class="jv-panel jv-md">
        <div class="jv-list">
          <div class="jv-bar-tools"><h5>ผู้โจมตี <small id="jv-count"></small></h5>
            <input id="jv-q" type="search" placeholder="ค้นหา IP" aria-label="ค้นหา IP">
            <select id="jv-goal" aria-label="กรองเป้าหมาย"><option value="">ทุกเป้าหมาย</option>${Object.entries(GOAL).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></div>
          <div class="table-wrap"><table class="jv-table"><thead><tr><th>IP</th><th>เป้าหมาย</th><th data-sort="confidence" class="jv-sortable">มั่นใจ</th><th data-sort="max_depth" class="jv-sortable">ลึก</th><th data-sort="updated" class="jv-sortable">อัปเดต</th></tr></thead><tbody id="jv-rows"></tbody></table></div>
          <div class="jv-pager" id="jv-pager"></div>
        </div>
        <div class="jv-detail" id="jv-detail"></div>
      </section>
      <section class="jv-panel">
        <div class="jv-bar-tools"><h5>Log การตัดสินใจ <small id="jv-log-count"></small></h5><input id="jv-log-q" type="search" placeholder="ค้นหา IP หรือ path" aria-label="ค้นหา log"></div>
        <div class="table-wrap"><table class="jv-feed"><thead><tr><th>เวลา</th><th>IP</th><th>เบาะแส</th><th>ชั้น</th><th>โดย</th></tr></thead><tbody id="jv-log"></tbody></table></div>
        <div class="jv-pager" id="jv-log-pager"></div>
      </section>`;
    $('jv-q').addEventListener('input',e=>{jv.q=e.target.value.trim();jv.page=0;rows(rh.data)});
    $('jv-goal').addEventListener('change',e=>{jv.goal=e.target.value;jv.page=0;rows(rh.data)});
    $('jv-log-q').addEventListener('input',e=>{jv.logQ=e.target.value.trim().toLowerCase();jv.logPage=0;log(rh.data)});
    $('rh-jev-status').addEventListener('click',e=>{
      const th=e.target.closest('[data-sort]');if(th){jv.sort=th.dataset.sort;jv.page=0;rows(rh.data);return}
      const tr=e.target.closest('[data-ip]');if(tr){select(tr.dataset.ip);return}
      const pg=e.target.closest('[data-page]');if(pg){jv[pg.dataset.target]=Number(pg.dataset.page);pg.dataset.target==='page'?rows(rh.data):log(rh.data)}
    });
  }

  function status(d){
    if(!$('jv-head'))skeleton();
    head(d);goals(d.plan||{});timeline(d.summary.clue_timeline||{});rows(d);log(d);
    if(jv.ip)loadDetail(jv.ip,true);
  }

  function head(d){
    const s=d.summary,ai=d.ai||{},plan=d.plan||{},by=s.followed_clue_by||{};
    const followed=(by.jev||0)+(by.fallback||0),share=followed?(by.jev||0)/followed:null;
    let state,cls;
    if(d.strategy!=='jev'){state='ปิด';cls='warn'}
    else if(!ai.enabled||!ai.key_set){state='ใช้ตัวสำรอง';cls='warn'}
    else if(!plan.exists||plan.error){state='รอแผน';cls='warn'}
    else{state='ทำงาน';cls='ok'}
    const conf=s.by_strategy&&s.by_strategy.jev&&s.by_strategy.jev.average_confidence;
    const tiles=[[num((d.jev_attackers||[]).length),'กำลังคุม'],[pc(share),'Jev ตัดสินเอง'],[pc(conf),'มั่นใจเฉลี่ย'],[num(by.jev),'ครั้งที่ตามเบาะแส Jev']];
    $('jv-head').innerHTML=`<span class="jv-mark" aria-hidden="true"><img src="/static/jev-logo.png" alt="" onerror="this.remove()"><em>J</em></span>
      <div class="jv-title"><h4>Jev</h4><span class="pill ${cls}">${state}</span>${plan.generated?`<small>แผนล่าสุด ${escapeHtml(when(plan.generated))}</small>`:''}</div>
      <div class="jv-tiles">${tiles.map(([v,l])=>`<div><b>${v}</b><span>${l}</span></div>`).join('')}</div>`;
  }

  function goals(plan){
    const g=Object.entries(plan.goals||{}).sort((a,b)=>b[1]-a[1]),total=g.reduce((a,[,v])=>a+v,0);
    if(!total){$('jv-goals').innerHTML='<div class="empty">ยังไม่มีแผน</div>';return}
    $('jv-goals').innerHTML=`<div class="jv-seg">${g.map(([k,v],i)=>`<i class="g${i%5}" style="flex:${v}" title="${escapeHtml(GOAL[k]||k)} ${v}"></i>`).join('')}</div>
      <div class="jv-goal-list">${g.map(([k,v],i)=>`<button type="button" class="jv-goal-row" data-goal="${escapeHtml(k)}"><i class="g${i%5}"></i><span>${escapeHtml(GOAL[k]||k)}</span><b>${num(v)}</b><small>${Math.round(v/total*100)}%</small></button>`).join('')}</div>`;
    $('jv-goals').querySelectorAll('[data-goal]').forEach(b=>b.onclick=()=>{jv.goal=b.dataset.goal===jv.goal?'':b.dataset.goal;$('jv-goal').value=jv.goal;jv.page=0;rows(rh.data)});
  }

  function timeline(t){
    const b=(t.buckets||[]).filter(x=>x.jev+x.fallback);
    $('jv-tl-unit').textContent=t.unit==='day'?'รายวัน':'รายชั่วโมง';
    if(!b.length){$('jv-timeline').innerHTML='<div class="empty">ยังไม่มีข้อมูล</div>';return}
    const max=Math.max(1,...b.map(x=>x.jev+x.fallback)),every=Math.max(1,Math.ceil(b.length/10));
    const label=x=>{const d=new Date(x.start);return t.unit==='day'?d.toLocaleDateString('th-TH',{day:'numeric',month:'short'}):d.toLocaleTimeString('th-TH',{hour:'2-digit',minute:'2-digit'})};
    $('jv-timeline').innerHTML=`<div class="jv-timeline">${b.map((x,i)=>`<div class="jv-col" title="${escapeHtml(label(x))} · Jev ${x.jev} · สำรอง ${x.fallback}"><div class="jv-stack" style="height:${((x.jev+x.fallback)/max*100).toFixed(1)}%">${x.fallback?`<i class="fallback" style="flex:${x.fallback}"></i>`:''}${x.jev?`<i class="jev" style="flex:${x.jev}"></i>`:''}</div><small>${i%every===0?escapeHtml(label(x)):''}</small></div>`).join('')}</div>
      <div class="jv-legend jv-legend-left"><span class="jv-key jev">Jev</span><span class="jv-key fallback">สำรอง</span></div>`;
  }

  function pager(target,page,pages){
    if(pages<=1)return '';
    const btn=(p,l,dis)=>`<button type="button" class="text small" data-target="${target}" data-page="${p}" ${dis?'disabled':''}>${l}</button>`;
    return `${btn(page-1,'‹ ก่อนหน้า',page===0)}<span>${page+1} / ${pages}</span>${btn(page+1,'ถัดไป ›',page>=pages-1)}`;
  }

  function rows(d){
    let list=(d.jev_attackers||[]).slice();
    if(jv.q)list=list.filter(r=>r.source_ip.includes(jv.q));
    if(jv.goal)list=list.filter(r=>r.goal===jv.goal);
    if(jv.sort!=='updated')list.sort((a,b)=>(b[jv.sort]||0)-(a[jv.sort]||0));
    const pages=Math.max(1,Math.ceil(list.length/PAGE));jv.page=Math.min(jv.page,pages-1);
    $('jv-count').textContent=`${num(list.length)} IP`;
    $('rh-jev-status').querySelectorAll('[data-sort]').forEach(th=>th.classList.toggle('on',th.dataset.sort===jv.sort));
    if(!jv.ip&&list.length)select(list[0].source_ip);
    $('jv-rows').innerHTML=list.slice(jv.page*PAGE,(jv.page+1)*PAGE).map(r=>`<tr data-ip="${escapeHtml(r.source_ip)}" class="${r.source_ip===jv.ip?'selected':''}" tabindex="0"><td><code>${escapeHtml(r.source_ip)}</code></td><td>${escapeHtml(GOAL[r.goal]||'ยังไม่ชัด')}</td><td><div class="jv-mini"><div class="jv-track"><i style="width:${Math.round((r.confidence||0)*100)}%"></i></div><b>${pc(r.confidence)}</b></div></td><td>${r.max_depth||'-'}</td><td class="mono">${escapeHtml(shortTime(r.updated))}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">ไม่พบ</td></tr>';
    $('jv-pager').innerHTML=pager('page',jv.page,pages);
    if(!list.length&&!(d.jev_attackers||[]).length)$('jv-detail').innerHTML='<div class="empty">ยังไม่มีผู้โจมตี</div>';
  }

  function select(ip){
    jv.ip=ip;
    $('rh-jev-status').querySelectorAll('#jv-rows tr').forEach(tr=>tr.classList.toggle('selected',tr.dataset.ip===ip));
    loadDetail(ip,false);
  }

  async function loadDetail(ip,quiet){
    if(!quiet||jv.detailIp!==ip)$('jv-detail').innerHTML='<div class="empty">กำลังโหลด…</div>';
    try{const a=await api('/api/rabbit-hole/jev-attacker.json?ip='+encodeURIComponent(ip));if(jv.ip!==ip)return;jv.detailIp=ip;$('jv-detail').innerHTML=detail(a)}
    catch(error){if(jv.ip===ip)$('jv-detail').innerHTML=`<p class="error">${escapeHtml(error.message)}</p>`}
  }

  function gauge(v){const p=v==null?0:Math.round(v*100);return `<span class="jv-gauge" style="--p:${p}"><b>${v==null?'-':p+'%'}</b></span>`}

  function detail(a){
    const g=a.goal||{};
    const steps=(a.steps||[]).map(x=>`<li class="${x.by||''}"><span class="d">${x.depth??'·'}</span><code title="${escapeHtml(x.path||'')}">${escapeHtml(x.path||'-')}</code>${x.by==='jev'?`<em>Jev ${pc(x.confidence)}</em>`:x.by==='fallback'?'<em class="fb">สำรอง</em>':''}</li>`).join('');
    const next=(a.decisions||[]).map(dec=>`<div class="jv-pick"><div class="jv-from"><code>${escapeHtml(dec.from.path)}</code>${dec.seen?'<span class="pill deep">เปิดแล้ว</span>':''}</div>${dec.options.map(o=>`<div class="jv-opt ${o.chosen?'on':''}" title="${escapeHtml(o.path)}"><span>${o.chosen?'✓ ':''}${escapeHtml(short(o.path))}</span><div class="jv-track"><i style="width:${o.p==null?0:Math.round(o.p*100)}%"></i></div><b>${o.p==null?'-':Math.round(o.p*100)+'%'}</b></div>`).join('')}</div>`).join('');
    return `<div class="jv-dh">${gauge(g.confidence)}<div><code class="jv-ip">${escapeHtml(a.source_ip)}</code><strong>${escapeHtml(GOAL[g.label]||'ยังไม่ชัด')}</strong><small>${a.family==='shell'?'SSH/Telnet':a.family==='web'?'Web':'-'} · ลึก ${a.max_depth||0} ชั้น · ${num(a.sessions)} ช่วง</small></div></div>
      <h6>เส้นทาง</h6>${steps?`<ol class="jv-path-list">${steps}</ol>`:'<div class="empty">ยังไม่ได้เปิดเหยื่อ</div>'}
      <h6>Jev เลือกเบาะแสถัดไป</h6>${next||'<div class="empty">ยังไม่มีทางแยกให้ตัดสิน</div>'}`;
  }

  function log(d){
    let list=(d.summary.jev_decisions||[]);
    if(jv.logQ)list=list.filter(r=>(r.source_ip||'').includes(jv.logQ)||(r.path||'').toLowerCase().includes(jv.logQ));
    const pages=Math.max(1,Math.ceil(list.length/LOGPAGE));jv.logPage=Math.min(jv.logPage,pages-1);
    $('jv-log-count').textContent=`${num(list.length)} รายการ`;
    $('jv-log').innerHTML=list.slice(jv.logPage*LOGPAGE,(jv.logPage+1)*LOGPAGE).map(r=>`<tr><td class="mono">${escapeHtml(when(r.time))}</td><td><code>${escapeHtml(r.source_ip||'-')}</code></td><td><code class="jv-path">${escapeHtml(r.path||'-')}</code>${r.clue_from?`<small>จาก ${escapeHtml(r.clue_from)}</small>`:''}</td><td>${r.depth??'-'}</td><td>${r.by==='jev'?`<span class="jv-key jev">Jev ${pc(r.confidence)}</span>`:'<span class="jv-key fallback">สำรอง</span>'}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">ไม่มีรายการ</td></tr>';
    $('jv-log-pager').innerHTML=pager('logPage',jv.logPage,pages);
  }

  function shortTime(v){if(!v)return '-';const d=new Date(v);return d.toLocaleString('th-TH',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'})}
  function short(path){path=String(path||'-');const parts=path.split('/').filter(Boolean);return parts.length>2?'…/'+parts.slice(-2).join('/'):path}

  function ladder(d){
    const s=d.summary,groups=GROUPS.filter(g=>s.by_strategy&&s.by_strategy[g.id]&&s.by_strategy[g.id].windows);
    const maxDepth=Math.max(5,(d.settings&&d.settings.limits&&d.settings.limits.max_depth)||0,s.overall.max_depth||0);
    const deepest=Math.max(1,s.overall.max_depth||1);
    const map=names(d),ex=s.depth_examples||{};
    $('rh-ladder-legend').innerHTML=groups.map(g=>`<span class="jv-key ${g.cls}">${g.name} <small>${num(s.by_strategy[g.id].windows)} ช่วง</small></span>`).join('');
    if(!groups.length){$('rh-ladder').innerHTML='<div class="empty">ยังไม่มีผู้โจมตีเข้าเส้นทางลวงในช่วงเวลานี้</div>';return}
    const rows=[];
    for(let depth=1;depth<=Math.min(maxDepth,Math.max(deepest,3));depth++){
      const bars=groups.map(g=>{const b=s.by_strategy[g.id],base=reach(b.depth_distribution,1),c=reach(b.depth_distribution,depth),p=base?c/base:0;
        return `<div class="jv-bar ${g.cls}" title="${g.name}: ${num(c)} จาก ${num(base)}"><i style="width:${(p*100).toFixed(1)}%"></i><span>${Math.round(p*100)}%<small>${num(c)}</small></span></div>`}).join('');
      const items=(ex[String(depth)]||[]).map(e=>`<span class="jv-bait" title="เปิด ${num(e.count)} ครั้ง">${e.category?`<em>${escapeHtml(CATEGORY[e.category]||e.category)}</em>`:''}<code>${escapeHtml(map[e.resource]||e.resource)}</code></span>`).join('');
      const label=depth===1?'จุดเริ่ม':depth===deepest?'ลึกสุดที่มีคนไปถึง':'ตามเบาะแสต่อ';
      rows.push(`<div class="jv-row" style="--d:var(--d${Math.min(5,depth)})"><div class="jv-depth"><b>ชั้น ${depth}</b><small>${label}</small></div><div class="jv-bars">${bars}</div><div class="jv-baits">${items||'<span class="data-note">ยังไม่มีใครถึง</span>'}</div></div>`);
    }
    $('rh-ladder').innerHTML=`<div class="jv-row jv-head"><span>ชั้น</span><span>ไปถึงชั้นนี้ (% ของคนที่เข้ามา)</span><span>เหยื่อที่ถูกเปิดบ่อยในชั้นนี้</span></div>`+rows.join('');
  }

  function compare(d){
    const s=d.summary,groups=GROUPS.filter(g=>s.by_strategy&&s.by_strategy[g.id]&&s.by_strategy[g.id].windows);
    if(!groups.length){$('rh-strategy-head').innerHTML='';$('rh-strategy-body').innerHTML='<tr><td class="empty">ยังไม่มีข้อมูล</td></tr>';$('rh-strategy-note').textContent='';return}
    const metrics=[
      ['Session ที่เข้ามา',b=>b.sessions,num,null],
      ['เดินตามเบาะแสอย่างน้อย 1 ขั้น',b=>b.follow_rate,pct,1],
      ['ความลึกเฉลี่ย (ชั้น)',b=>b.average_depth,v=>v??'-',1],
      ['ลึกสุด (ชั้น)',b=>b.max_depth,v=>v??'-',1],
      ['เหยื่อที่เปิดเฉลี่ยต่อช่วง',b=>b.average_resources,v=>v??'-',1],
      ['เวลาโต้ตอบเฉลี่ย',b=>b.average_duration_seconds,secs,1],
      ['เวลาโต้ตอบมัธยฐาน',b=>b.median_duration_seconds,secs,1]];
    $('rh-strategy-head').innerHTML=`<tr><th>ตัวชี้วัด</th>${groups.map(g=>`<th><span class="jv-key ${g.cls}">${g.short}</span></th>`).join('')}</tr>`;
    $('rh-strategy-body').innerHTML=metrics.map(([label,get,fmt,better])=>{
      const vals=groups.map(g=>get(s.by_strategy[g.id]));
      const nums=vals.filter(v=>typeof v==='number');
      const best=better&&groups.length>1&&nums.length>1?Math.max(...nums):null;
      return `<tr><td>${label}</td>${vals.map(v=>`<td class="${best!=null&&v===best?'jv-best':''}">${fmt(v)}</td>`).join('')}</tr>`}).join('');
    const small=groups.some(g=>(s.by_strategy[g.id].sessions||0)<10);
    $('rh-strategy-note').textContent=small?'ข้อมูลยังน้อย (< 10 Session)':'';
  }

  const base=renderRabbit;
  renderRabbit=function(){
    base();
    const d=rh.data;
    if(!rh.available||!d||!d.summary)return;
    try{status(d);ladder(d);compare(d)}catch(error){$('rh-jev-status').innerHTML=`<p class="error">แสดงภาพรวม Jev ไม่สำเร็จ: ${escapeHtml(error.message)}</p>`}
  };
})();
