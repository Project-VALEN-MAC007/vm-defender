/* Rabbit Hole: Jev strategy and decoy pool. Uses globals from dashboard.js: rh, renderSetup, setupFilled, api, postScope, $, escapeHtml, when. */
(function(){
  const pool={editing:null};
  const KIND={file:'ไฟล์',listing:'โฟลเดอร์',api:'API (JSON)',people_api:'API รายชื่อคน',form:'หน้า Login'};
  const GOAL={recon:'สำรวจระบบ',credential_hunting:'หารหัสผ่าน/คีย์',data_theft:'ขโมยข้อมูล',exploitation:'โจมตีช่องโหว่',persistence:'พยายามฝังตัว',other:'ไม่ชัดเจน'};
  const TEMPLATE={id:'my-item',kind:'file',category:'config',lure:2,path:'/backup/settings.ini.bak',
    description:'Old settings backup with an SMTP password and a link to the admin panel',
    body_lines:['[mail]','host = mail.{{org.domain}}','user = noreply@{{org.domain}}','password = {{secret:password:smtp}}','','; panel: {{clue:panel}}'],
    slots:{panel:{categories:['admin'],kinds:['form']}}};

  function renderPool(){
    const d=rh.data;if(!d||!d.pool)return;
    const jevMode=d.strategy==='jev';
    $('rh-pool-card').classList.toggle('dimmed',!jevMode);
    const plan=d.plan||{},st=$('rh-plan-state');
    if(!jevMode){st.className='pill';st.textContent='โหมดคงที่: ยังไม่ได้ใช้คลังนี้'}
    else if(!d.ai.enabled||!d.ai.key_set){st.className='pill warn';st.textContent='ใช้ตัวเลือกสำรอง (ยังไม่เปิด Jev หรือยังไม่มีคีย์)'}
    else if(!plan.exists){st.className='pill warn';st.textContent='ยังไม่พบแผนจาก Jev planner'}
    else{st.className='pill ok';st.textContent='Jev คุมอยู่ '+plan.attackers+' ผู้โจมตี'}
    const by=(d.summary&&d.summary.followed_clue_by)||{};
    const followed=Object.keys(by).length?`<p class="data-note">เบาะแสที่ผู้โจมตีเดินตามในช่วงนี้: Jev <b>${by.jev||0}</b> · ตัวเลือกสำรอง <b>${by.fallback||0}</b> · ฉากคงที่ <b>${by.fixed||0}</b></p>`:'';
    $('rh-plan-detail').innerHTML=followed+(plan.recent&&plan.recent.length?`<div class="table-wrap"><table><thead><tr><th>Source IP</th><th>Jev ประเมินว่าต้องการ</th><th>ช่องที่ Jev ตัดสินแล้ว</th><th>อัปเดต</th></tr></thead><tbody>${plan.recent.map(r=>`<tr><td><code>${escapeHtml(r.source_ip)}</code></td><td>${escapeHtml(GOAL[r.goal&&r.goal.label]||'-')}${r.goal&&r.goal.confidence!=null?` <small class="data-note">${Math.round(r.goal.confidence*100)}%</small>`:''}</td><td>${r.choices}</td><td>${when(r.updated)}</td></tr>`).join('')}</tbody></table></div>`:'');
    $('rh-pool-errors').textContent=(d.pool.errors||[]).join(' · ');
    const groups={};d.pool.items.forEach(i=>(groups[i.category]=groups[i.category]||[]).push(i));
    const shell=(d.pool.shell_items||[]);
    const shellHtml=shell.length?`<div class="pool-group"><h5>SSH/Telnet (Cowrie) <span class="data-note">${shell.length} · ใช้ผ่าน plugin trap-rabbit</span></h5>${shell.map(i=>`<div class="pool-item${i.entry?' entry':''}"><div class="pool-top"><code>${escapeHtml(i.path)}</code><span class="lure" title="ความน่าสนใจ ${i.lure}/3">${'●'.repeat(i.lure)}${'○'.repeat(3-i.lure)}</span></div><p>${escapeHtml(i.description)}</p><div class="pool-tags">${i.entry?'<span class="pill ok">จุดเริ่ม</span>':''}<span class="pill">${escapeHtml(d.pool.categories[i.category]||i.category)}</span>${i.slots.map(s=>`<span class="pill info">เบาะแส: ${escapeHtml(s.name)}</span>`).join('')}</div></div>`).join('')}</div>`:'';
    $('rh-pool').innerHTML=Object.entries(groups).map(([cat,items])=>`<div class="pool-group"><h5>${escapeHtml(d.pool.categories[cat]||cat)} <span class="data-note">${items.length}</span></h5>${items.map(i=>`<div class="pool-item${i.entry?' entry':''}"><div class="pool-top"><code>${escapeHtml(i.path)}</code><span class="lure" title="ความน่าสนใจ ${i.lure}/3">${'●'.repeat(i.lure)}${'○'.repeat(3-i.lure)}</span></div><p>${escapeHtml(i.description)}</p><div class="pool-tags">${i.entry?'<span class="pill ok">จุดเริ่ม</span>':''}<span class="pill">${escapeHtml(KIND[i.kind]||i.kind)}</span>${i.slots.map(s=>`<span class="pill info" title="เลือกได้จากหมวด ${escapeHtml(s.categories.join(', '))}">เบาะแส: ${escapeHtml(s.name)}${s.count>1?' ×'+s.count:''}</span>`).join('')}${i.builtin?'':'<span class="pill violet">ของฉัน</span>'}</div><div class="split-actions"><button type="button" class="text small pool-view" data-id="${escapeHtml(i.id)}">ดูสิ่งที่ผู้โจมตีเห็น</button>${i.builtin?'':`<button type="button" class="text small pool-edit" data-id="${escapeHtml(i.id)}">แก้ไข</button><button type="button" class="danger small pool-del" data-id="${escapeHtml(i.id)}">ลบ</button>`}</div></div>`).join('')}</div>`).join('')+shellHtml;
  }
  async function preview(id){
    const box=$('rh-pool-preview');box.classList.remove('hidden');box.innerHTML='<div class="empty">กำลังสร้างตัวอย่าง…</div>';
    try{const p=await api('/api/rabbit-hole/pool-preview.json?id='+encodeURIComponent(id));
      box.innerHTML=`<div class="preview-item"><header><code>${escapeHtml(p.item.path)}</code><button type="button" class="text small" id="rh-pool-preview-close">ปิด</button></header><pre>${escapeHtml(p.content)}</pre>${Object.entries(p.candidates).map(([slot,list])=>`<p class="data-note">ช่อง <b>${escapeHtml(slot)}</b> Jev เลือกได้จาก ${list.length} ชิ้น: ${list.map(c=>`<code>${escapeHtml(c.path)}</code>`).join(' ')}</p>`).join('')}<p class="data-note">${escapeHtml(p.note)}</p></div>`;
      box.scrollIntoView({behavior:'smooth',block:'nearest'})}catch(e){box.innerHTML=`<p class="error">${escapeHtml(e.message)}</p>`}
  }
  function openForm(item){
    pool.editing=item?item.id:null;$('rh-pool-form').classList.remove('hidden');$('rh-pool-form-error').textContent='';
    $('rh-pool-form-title').textContent=item?'แก้ไขชิ้นข้อมูลลวง '+item.id:'เพิ่มชิ้นข้อมูลลวง';
    $('rh-pool-json').value=JSON.stringify(item?item.raw:TEMPLATE,null,2);$('rh-pool-json').focus();
  }
  async function editItem(id){
    const i=rh.data.pool.items.find(x=>x.id===id);if(!i||!i.raw)return;
    openForm({id,raw:i.raw});
  }
  async function saveItem(e){
    e.preventDefault();$('rh-pool-form-error').textContent='';
    let item;try{item=JSON.parse($('rh-pool-json').value)}catch(err){$('rh-pool-form-error').textContent='JSON ไม่ถูกต้อง: '+err.message;return}
    try{const r=await postScope('/api/rabbit-hole/pool/save',{item});rh.data.pool=r.pool;$('rh-pool-form').classList.add('hidden');renderPool();preview(item.id)}
    catch(err){$('rh-pool-form-error').textContent=err.message}
  }
  async function deleteItem(id){
    if(!confirm('ลบชิ้นข้อมูลลวง '+id+'? (ระบบเก็บสำเนาไว้ใน .backups)'))return;
    try{const r=await postScope('/api/rabbit-hole/pool/delete',{id});rh.data.pool=r.pool;renderPool()}catch(err){$('rh-pool-errors').textContent=err.message}
  }

  // Wrap the dashboard's setup renderer: set the strategy radio once, then draw the pool.
  const original=renderSetup;
  renderSetup=function(){
    const first=!setupFilled;
    original.apply(this,arguments);
    if(first&&rh.data){const v=rh.data.strategy||'fixed';const r=document.querySelector(`input[name="rh-strategy"][value="${v}"]`);if(r)r.checked=true;markMode(v)}
    renderPool();
  };
  function markMode(v){
    $('rh-setup').classList.toggle('jev-mode',v==='jev');
    let note=$('rh-scenario-mode-note');
    if(!note&&$('rh-scenarios')){note=document.createElement('p');note.id='rh-scenario-mode-note';note.className='status-banner';$('rh-scenarios').before(note)}
    if(note){note.textContent='โหมด Jev คุมเส้นทาง: ฉาก Web ด้านล่างใช้เฉพาะเมื่อเลือก "เส้นทางคงที่" ส่วนฉาก SSH/Telnet ยังใช้ตามที่เลือก';note.classList.toggle('hidden',v!=='jev')}
  }
  document.querySelectorAll('input[name="rh-strategy"]').forEach(r=>r.addEventListener('change',()=>markMode(r.value)));
  $('rh-pool-new').addEventListener('click',()=>openForm(null));
  $('rh-pool-cancel').addEventListener('click',()=>$('rh-pool-form').classList.add('hidden'));
  $('rh-pool-form').addEventListener('submit',saveItem);
  $('rh-pool-card').addEventListener('click',e=>{
    const v=e.target.closest('.pool-view');if(v){preview(v.dataset.id);return}
    const ed=e.target.closest('.pool-edit');if(ed){editItem(ed.dataset.id);return}
    const d=e.target.closest('.pool-del');if(d){deleteItem(d.dataset.id);return}
    if(e.target.id==='rh-pool-preview-close')$('rh-pool-preview').classList.add('hidden');
  });
})();
