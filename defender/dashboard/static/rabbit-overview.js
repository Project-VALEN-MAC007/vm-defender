/* Rabbit Hole overview tab, centred on Jev: is Jev running, how deep attackers go, Jev vs fixed paths.
   Uses globals from dashboard.js: rh, renderRabbit, $, escapeHtml, when, pct, secs. */
(function(){
  const GROUPS=[
    {id:'jev',name:'Jev คุมเส้นทาง',short:'Jev',cls:'jev'},
    {id:'fallback',name:'ตัวเลือกสำรอง (Jev ไม่ตอบ)',short:'สำรอง',cls:'fallback'},
    {id:'fixed',name:'เส้นทางคงที่',short:'คงที่',cls:'fixed'}];
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
    const followed=(by.jev||0)+(by.fallback||0)+(by.fixed||0);
    const share=followed?(by.jev||0)/followed:null;
    const jevMode=d.strategy==='jev';
    let state,cls;
    if(!jevMode){state='ปิดอยู่ — ใช้เส้นทางคงที่';cls='warn'}
    else if(!ai.enabled||!ai.key_set){state='ใช้ตัวเลือกสำรอง (ยังไม่เปิด Jev หรือยังไม่มีคีย์)';cls='warn'}
    else if(!plan.exists){state='รอแผนแรกจาก Jev planner';cls='warn'}
    else if(plan.error){state='อ่านแผนของ Jev ไม่ได้';cls='bad'}
    else{state='กำลังคุมเส้นทาง';cls='ok'}
    const conf=(s.by_strategy&&s.by_strategy.jev&&s.by_strategy.jev.average_confidence);
    const recent=(plan.recent||[]).slice(0,5);
    const flow=[
      ['1','ผู้โจมตีเข้ามา','โดน redirect จาก IDS เข้าเว็บ/SSH ลวง'],
      ['2','Jev อ่านพฤติกรรม','ดูว่าเปิดอะไร เร็วแค่ไหน แล้วเดาเป้าหมาย'],
      ['3','เลือกเบาะแสจากคลัง','หยิบเหยื่อที่ตรงเป้าหมายมาเติมในช่องเบาะแส'],
      ['4','ผู้โจมตีเดินลึกขึ้น','ยิ่งลึก ยิ่งอยู่นาน ยิ่งเห็นพฤติกรรมมาก']];
    $('rh-jev-status').innerHTML=`
      <div class="jv-top">
        <div class="jv-id"><span class="jv-mark" aria-hidden="true">J</span><div><h4>Jev — ผู้วางเบาะแส</h4><span class="pill ${cls}">${escapeHtml(state)}</span></div></div>
        <div class="jv-kpis">
          <div><b>${share==null?'-':Math.round(share*100)+'%'}</b><small>ของเบาะแสที่ผู้โจมตีเดินตาม<br>Jev เป็นคนวาง (${num(by.jev)} จาก ${num(followed)})</small></div>
          <div><b>${plan.exists&&!plan.error?num(plan.attackers):'-'}</b><small>ผู้โจมตีที่ Jev มีแผนให้<br>${plan.generated?'อัปเดต '+escapeHtml(when(plan.generated)):'ยังไม่มีแผน'}</small></div>
          <div><b>${conf==null?'-':Math.round(conf*100)+'%'}</b><small>ความมั่นใจเฉลี่ยของ Jev<br>ตอนเลือกเบาะแส</small></div>
        </div>
      </div>
      <ol class="jv-flow">${flow.map(([n,t,x])=>`<li><span>${n}</span><div><b>${t}</b><small>${x}</small></div></li>`).join('')}</ol>
      ${recent.length?`<div class="jv-recent"><h5>Jev กำลังวางแผนให้ใคร</h5><div class="jv-chips">${recent.map(r=>`<div class="jv-chip"><code>${escapeHtml(r.source_ip)}</code><span>${escapeHtml(GOAL[r.goal&&r.goal.label]||'ยังไม่ชัด')}${r.goal&&r.goal.confidence!=null?` · ${Math.round(r.goal.confidence*100)}%`:''}</span><small>ตัดสินแล้ว ${r.choices} ช่อง</small></div>`).join('')}</div></div>`:''}`;
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
