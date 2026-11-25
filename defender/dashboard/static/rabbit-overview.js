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

  function status(d){
    const s=d.summary,ai=d.ai||{},plan=d.plan||{},by=s.followed_clue_by||{};
    const followed=(by.jev||0)+(by.fallback||0),share=followed?(by.jev||0)/followed:null;
    let state,cls;
    if(d.strategy!=='jev'){state='ปิด';cls='warn'}
    else if(!ai.enabled||!ai.key_set){state='ใช้ตัวสำรอง';cls='warn'}
    else if(!plan.exists||plan.error){state='รอแผน';cls='warn'}
    else{state='ทำงาน';cls='ok'}
    const conf=s.by_strategy&&s.by_strategy.jev&&s.by_strategy.jev.average_confidence;
    const pc=v=>v==null?'-':Math.round(v*100)+'%';
    const list=d.jev_attackers||[];
    $('rh-jev-status').innerHTML=`
      <div class="jv-head">
        <span class="jv-mark" aria-hidden="true"><img src="/static/jev-logo.png" alt="" onerror="this.remove()"><em>J</em></span>
        <h4>Jev</h4><span class="pill ${cls}">${state}</span>
        <div class="jv-stats"><span><b>${list.length}</b>กำลังคุม</span><span><b>${pc(share)}</b>Jev ตัดสินเอง</span><span><b>${pc(conf)}</b>มั่นใจเฉลี่ย</span></div>
      </div>
      ${list.length?`<div class="jv-cards">${list.map(card).join('')}</div>`:'<div class="empty">ยังไม่มีผู้โจมตี</div>'}`;
  }

  function gauge(v){const p=v==null?0:Math.round(v*100);return `<span class="jv-gauge" style="--p:${p}"><b>${v==null?'-':p+'%'}</b></span>`}

  function card(a){
    const g=a.goal||{};
    const steps=(a.steps||[]).map(x=>`<code title="${escapeHtml(x.path||'')}">${escapeHtml(short(x.path))}</code>`).join('<i>›</i>');
    const next=(a.decisions||[]).map(dec=>`<div class="jv-pick"><div class="jv-from">${escapeHtml(short(dec.from.path))} ›</div>${dec.options.map(o=>`<div class="jv-opt ${o.chosen?'on':''}" title="${escapeHtml(o.path)}"><span>${o.chosen?'✓ ':''}${escapeHtml(short(o.path))}</span><div class="jv-track"><i style="width:${o.p==null?0:Math.round(o.p*100)}%"></i></div><b>${o.p==null?'-':Math.round(o.p*100)+'%'}</b></div>`).join('')}</div>`).join('');
    return `<article class="jv-card">
      <header>${gauge(g.confidence)}<div><code class="jv-ip">${escapeHtml(a.source_ip)}</code><strong>${escapeHtml(GOAL[g.label]||'ยังไม่ชัด')}</strong></div>${a.max_depth?`<span class="pill deep">ชั้น ${a.max_depth}</span>`:''}</header>
      ${steps?`<div class="jv-steps">${steps}</div>`:''}
      ${next?`<div class="jv-next">${next}</div>`:''}
    </article>`;
  }

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
