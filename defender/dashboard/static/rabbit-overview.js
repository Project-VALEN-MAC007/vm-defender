/* Rabbit Hole overview tab, centred on Jev: is Jev running, how deep attackers go, Jev vs its fallback.
   Uses globals from dashboard.js: rh, renderRabbit, $, escapeHtml, when, pct, secs. */
(function(){
  const GROUPS=[
    {id:'jev',name:'Jev คุมเส้นทาง',short:'Jev',cls:'jev'},
    {id:'fallback',name:'ตัวเลือกสำรอง (Jev ไม่ตอบ)',short:'สำรอง',cls:'fallback'}];
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
    const followed=(by.jev||0)+(by.fallback||0);
    const share=followed?(by.jev||0)/followed:null;
    const jevMode=d.strategy==='jev';
    let state,cls;
    if(!jevMode){state='ยังไม่ได้ตั้งให้ Jev คุมเส้นทาง';cls='warn'}
    else if(!ai.enabled||!ai.key_set){state='ใช้ตัวเลือกสำรอง (ยังไม่เปิด Jev หรือยังไม่มีคีย์)';cls='warn'}
    else if(!plan.exists){state='รอแผนแรกจาก Jev planner';cls='warn'}
    else if(plan.error){state='อ่านแผนของ Jev ไม่ได้';cls='bad'}
    else{state='กำลังคุมเส้นทาง';cls='ok'}
    const conf=s.by_strategy&&s.by_strategy.jev&&s.by_strategy.jev.average_confidence;
    const kpis=[
      [share==null?'-':Math.round(share*100)+'%','เบาะแสที่ Jev ตัดสินเอง',`${num(by.jev)} จาก ${num(followed)} ที่ผู้โจมตีเดินตาม`],
      [num(by.jev),'ครั้งที่ผู้โจมตีตามเบาะแสของ Jev',`ตัวเลือกสำรอง ${num(by.fallback)} ครั้ง`],
      [plan.exists&&!plan.error?num(plan.attackers):'-','ผู้โจมตีที่ Jev มีแผนให้',plan.generated?'อัปเดต '+when(plan.generated):'ยังไม่มีแผน'],
      [conf==null?'-':Math.round(conf*100)+'%','ความมั่นใจเฉลี่ยของ Jev','ตอนเลือกเบาะแสที่มีคนเดินตาม']];
    $('rh-jev-status').innerHTML=`
      <div class="jv-top">
        <div class="jv-id"><span class="jv-mark" aria-hidden="true"><img src="/static/jev-logo.png" alt="" onerror="this.remove()"><em>J</em></span><div><h4>Jev</h4><span class="pill ${cls}">${escapeHtml(state)}</span></div></div>
        <div class="jv-kpis">${kpis.map(([v,l,h])=>`<div><b>${v}</b><span>${l}</span><small>${escapeHtml(h)}</small></div>`).join('')}</div>
      </div>
      <div class="jv-grid">
        <section class="jv-panel"><h5>เป้าหมายผู้โจมตีที่ Jev ประเมิน</h5>${goals(plan)}</section>
        <section class="jv-panel"><h5>การตัดสินใจล่าสุดของ Jev</h5>${decisions(s.jev_decisions||[])}</section>
      </div>
      <section class="jv-panel"><h5>เบาะแสที่ผู้โจมตีเดินตาม ตามเวลา <small>${(s.clue_timeline||{}).unit==='day'?'รายวัน':'รายชั่วโมง'}</small></h5>${timeline(s.clue_timeline||{})}</section>
      ${(plan.recent||[]).length?`<section class="jv-panel"><h5>แผนของ Jev ราย IP <small>${num(plan.attackers)} IP</small></h5><div class="jv-chips">${plan.recent.map(r=>`<div class="jv-chip"><code>${escapeHtml(r.source_ip)}</code><span>${escapeHtml(GOAL[r.goal&&r.goal.label]||'ยังไม่ชัด')}${r.goal&&r.goal.confidence!=null?` · ${Math.round(r.goal.confidence*100)}%`:''}</span><small>ตัดสินแล้ว ${r.choices} ช่อง · ${escapeHtml(when(r.updated))}</small></div>`).join('')}</div></section>`:''}`;
  }

  function goals(plan){
    const g=Object.entries(plan.goals||{}).sort((a,b)=>b[1]-a[1]),total=g.reduce((a,[,v])=>a+v,0);
    if(!total)return '<div class="empty">ยังไม่มีแผนจาก Jev</div>';
    return `<div class="jv-goals">${g.map(([k,v])=>`<div class="jv-goal"><span>${escapeHtml(GOAL[k]||k)}</span><div class="jv-track"><i style="width:${(v/total*100).toFixed(1)}%"></i></div><b>${num(v)}</b></div>`).join('')}</div>`;
  }

  function decisions(rows){
    if(!rows.length)return '<div class="empty">ยังไม่มีผู้โจมตีเดินตามเบาะแสที่ Jev วาง</div>';
    return `<div class="table-wrap"><table class="jv-feed"><thead><tr><th>เวลา</th><th>Source IP</th><th>เบาะแสที่วาง</th><th>ชั้น</th><th>โดย</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mono">${escapeHtml(when(r.time))}</td><td><code>${escapeHtml(r.source_ip||'-')}</code></td><td><code class="jv-path">${escapeHtml(r.path||'-')}</code>${r.clue_from?`<small>ต่อจาก ${escapeHtml(r.clue_from)}</small>`:''}</td><td>${r.depth??'-'}</td><td>${r.by==='jev'?`<span class="jv-key jev">Jev${r.confidence!=null?' '+Math.round(r.confidence*100)+'%':''}</span>`:'<span class="jv-key fallback">สำรอง</span>'}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function timeline(t){
    const b=t.buckets||[];
    if(!b.length)return '<div class="empty">ยังไม่มีการเดินตามเบาะแสในช่วงเวลานี้</div>';
    const rows=b.filter(x=>x.jev+x.fallback);if(!rows.length)return '<div class="empty">ยังไม่มีการเดินตามเบาะแสของ Jev ในช่วงเวลานี้</div>';
    const max=Math.max(1,...rows.map(x=>x.jev+x.fallback));
    const label=x=>{const d=new Date(x.start);return t.unit==='day'?d.toLocaleDateString('th-TH',{day:'numeric',month:'short'}):d.toLocaleTimeString('th-TH',{hour:'2-digit',minute:'2-digit'})};
    const every=Math.max(1,Math.ceil(rows.length/12));
    return `<div class="jv-timeline">${rows.map((x,i)=>{const tot=x.jev+x.fallback;return `<div class="jv-col" title="${escapeHtml(label(x))}: Jev ${x.jev} · สำรอง ${x.fallback}"><div class="jv-stack" style="height:${(tot/max*100).toFixed(1)}%">${[['fallback',x.fallback],['jev',x.jev]].map(([k,v])=>v?`<i class="${k}" style="flex:${v}"></i>`:'').join('')}</div><small>${i%every===0?escapeHtml(label(x)):''}</small></div>`}).join('')}</div><div class="jv-legend jv-legend-left">${GROUPS.map(g=>`<span class="jv-key ${g.cls}">${g.short}</span>`).join('')}</div>`;
  }

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
    $('rh-strategy-note').textContent=(small?'กลุ่มใดกลุ่มหนึ่งมีน้อยกว่า 10 Session ตัวเลขยังแกว่งได้มาก · ':'')+'เทียบได้ตรงเมื่อใช้จุดเริ่ม ช่วงเวลา และกลุ่มผู้ทดสอบเดียวกัน';
  }

  const base=renderRabbit;
  renderRabbit=function(){
    base();
    const d=rh.data;
    if(!rh.available||!d||!d.summary)return;
    try{status(d);ladder(d);compare(d)}catch(error){$('rh-jev-status').innerHTML=`<p class="error">แสดงภาพรวม Jev ไม่สำเร็จ: ${escapeHtml(error.message)}</p>`}
  };
})();
