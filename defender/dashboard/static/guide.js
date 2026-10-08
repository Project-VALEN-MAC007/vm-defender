/* TRAP setup tutorial inside the dashboard. Content is static and written by the project. */
(function () {
  const $g = id => document.getElementById(id);
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[c]));
  const STORE = 'trap-guide-done';
  const load = () => { try { return JSON.parse(localStorage.getItem(STORE) || '{}'); } catch (e) { return {}; } };
  const save = v => { try { localStorage.setItem(STORE, JSON.stringify(v)); } catch (e) { /* progress is a convenience only */ } };

  const DIAGRAM = `<svg viewBox="0 0 900 430" role="img" aria-label="ทราฟฟิกทุกตัวผ่าน Defender ก่อนถึง Real Web หรือ Honeypot" class="guide-diagram">
  <defs><marker id="g-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="currentColor"/></marker></defs>
  <g class="gd-box"><rect x="20" y="170" width="150" height="74" rx="10"/><text x="95" y="200" class="gd-name">ผู้ใช้ / ผู้โจมตี</text><text x="95" y="222" class="gd-sub">เข้า https://defender.lab</text></g>
  <g class="gd-box gd-accent"><rect x="240" y="40" width="250" height="350" rx="12"/><text x="365" y="70" class="gd-name">Defender</text><text x="365" y="90" class="gd-sub">outer 192.168.56.10 · inner 10.10.10.1</text>
    <rect x="262" y="110" width="206" height="40" rx="8" class="gd-inner"/><text x="365" y="135" class="gd-item">Suricata · ตรวจจับ</text>
    <rect x="262" y="160" width="206" height="40" rx="8" class="gd-inner"/><text x="365" y="185" class="gd-item">Decision Engine · ให้คะแนน</text>
    <rect x="262" y="210" width="206" height="40" rx="8" class="gd-inner"/><text x="365" y="235" class="gd-item">Nginx · เว็บ  |  nftables · SSH</text>
    <rect x="262" y="260" width="206" height="40" rx="8" class="gd-inner"/><text x="365" y="285" class="gd-item">Dashboard 127.0.0.1:9090</text>
    <rect x="262" y="310" width="206" height="40" rx="8" class="gd-inner"/><text x="365" y="335" class="gd-item">trap-sync · ดึง log ทุกนาที</text></g>
  <g class="gd-box"><rect x="590" y="40" width="290" height="96" rx="12"/><text x="735" y="72" class="gd-name">Real Web</text><text x="735" y="94" class="gd-sub">10.10.10.3:8080</text><text x="735" y="116" class="gd-sub">เว็บจริง รับเฉพาะจาก Defender</text></g>
  <g class="gd-box"><rect x="590" y="170" width="290" height="220" rx="12"/><text x="735" y="200" class="gd-name">Honeypot</text><text x="735" y="220" class="gd-sub">10.10.10.2 · Docker</text>
    <text x="610" y="252" class="gd-left">SNARE + TANNER  :8083</text><text x="610" y="276" class="gd-left">Rabbit Hole web decoy  :8084</text><text x="610" y="300" class="gd-left">Cowrie SSH :2222  Telnet :2223</text><text x="610" y="324" class="gd-left">WordPress :8081  phpMyAdmin :8082</text><text x="610" y="348" class="gd-left">Deploy agent  :8091</text><text x="610" y="372" class="gd-left gd-dim">log: /var/log/trap, /var/log/cowrie</text></g>
  <g class="gd-lines" fill="none"><path d="M170 207H240" marker-end="url(#g-arrow)"/><path d="M490 88H590" marker-end="url(#g-arrow)"/><path d="M490 232H540V250H590" marker-end="url(#g-arrow)"/><path d="M490 280H590" marker-end="url(#g-arrow)" stroke-dasharray="5 4"/><path d="M590 330H490" marker-end="url(#g-arrow)" stroke-dasharray="5 4"/></g>
  <text x="540" y="80" class="gd-edge">ปกติ</text><text x="540" y="222" class="gd-edge">เสี่ยง → Honeypot</text><text x="540" y="273" class="gd-edge">สั่ง Deploy</text><text x="540" y="323" class="gd-edge">log</text>
</svg>`;

  const GUIDE = [
    {id: 'overview', title: 'ภาพรวม', lead: 'TRAP ใช้ 3 เครื่อง ติดตั้งตามลำดับ Real Web → Honeypot → Defender แล้วค่อยเชื่อมและตรวจ ทุกเครื่องเป็น Ubuntu และคุยกันผ่านวง inner 10.10.10.0/24',
      diagram: true,
      table: {head: ['เครื่อง', 'IP', 'พอร์ตที่เปิด', 'ติดตั้ง'], rows: [
        ['Defender', 'outer 192.168.56.10 (enp0s3)\ninner 10.10.10.1\nmanagement enp0s9', '80, 443 จากภายนอก · 22 จาก management', 'Suricata, Nginx, nftables, Python 3, repo ที่ /opt/trap'],
        ['Honeypot', '10.10.10.2', '8081–8084, 2222, 2223, 8091 เฉพาะจาก 10.10.10.1', 'Docker, Python 3, repo ที่ /opt/trap, Cowrie'],
        ['Real Web', '10.10.10.3', '8080 เฉพาะจาก 10.10.10.1', 'เว็บจริงของระบบ'],
      ]},
      note: 'IP และชื่อ interface ในคู่มือเป็นค่าของ lab ที่ยืนยันแล้ว ถ้าเครื่องจริงต่างไป ให้แทนค่าเหมือนกันทุกจุด'},
    {id: 'realweb', title: 'Real Web', machine: 'Real Web · 10.10.10.3', lead: 'เครื่องนี้มีแค่เว็บจริง และต้องรับคำขอจาก Defender เท่านั้น เพื่อไม่ให้ใครเลี่ยงด่านตรวจได้', steps: [
      {title: 'รันเว็บจริงที่พอร์ต 8080', text: 'ใช้เว็บของทีมหรือเว็บทดสอบใดก็ได้ ให้ฟังที่ 10.10.10.3:8080', code: 'curl -I http://10.10.10.3:8080/   # ต้องได้ 200'},
      {title: 'เปิด firewall ให้เฉพาะ Defender', text: 'ปิดทุกอย่าง เปิดเฉพาะ 8080 และ SSH จาก 10.10.10.1', code: 'sudo ufw default deny incoming\nsudo ufw allow from 10.10.10.1 to any port 8080 proto tcp\nsudo ufw allow from 10.10.10.1 to any port 22 proto tcp\nsudo ufw enable && sudo ufw status numbered'},
    ]},
    {id: 'honeypot', title: 'Honeypot', machine: 'Honeypot · 10.10.10.2', lead: 'เครื่องนี้รันบริการลวงทั้งหมด: SNARE/TANNER, Rabbit Hole web decoy, Cowrie และ Deploy agent ทุกพอร์ตรับเฉพาะจาก Defender', steps: [
      {title: 'ลงแพ็กเกจและวาง repo', code: 'sudo apt update\nsudo apt install -y docker.io docker-compose-v2 python3 git rsync\nsudo git clone <repo-url> /opt/trap\nsudo mkdir -p /var/lib/trap /var/log/trap'},
      {title: 'SNARE + TANNER (Web Honeypot)', text: 'ตั้ง IP ฝั่ง inner และให้ SNARE เชื่อ X-Real-IP เฉพาะจาก Defender', code: 'cd /opt/trap/honeypot/snare-tanner\npython3 bootstrap.py\ncp settings.env.example settings.env\n# แก้ settings.env: SNARE_BIND_IP=10.10.10.2  TRAP_TRUSTED_PROXY_CIDRS=10.10.10.1/32\nsudo docker compose --env-file settings.env up -d --build\ncurl -fsS http://10.10.10.2:8083/ >/dev/null && echo SNARE OK'},
      {title: 'Cowrie (SSH 2222 / Telnet 2223)', text: 'Cowrie ไม่ได้อยู่ใน repo ใช้ Docker image ทางการ คัดลอกระบบไฟล์จำลอง (fs.pickle + honeyfs) ออกมาไว้นอก container ครั้งแรก เพื่อให้ Rabbit Hole ใส่ไฟล์ลวงได้เอง', code: 'sudo mkdir -p /var/log/cowrie /var/lib/trap/cowrie-fs\nsudo docker create --name cowrie-seed cowrie/cowrie:latest\nsudo docker cp cowrie-seed:/cowrie/cowrie-git/src/cowrie/data/fs.pickle /var/lib/trap/cowrie-fs/fs.pickle\nsudo docker cp cowrie-seed:/cowrie/cowrie-git/honeyfs /var/lib/trap/cowrie-fs/honeyfs\nsudo docker rm cowrie-seed\nsudo docker run -d --name cowrie --restart unless-stopped \\\n  -p 10.10.10.2:2222:2222 -p 10.10.10.2:2223:2223 \\\n  -e COWRIE_TELNET_ENABLED=yes \\\n  -v /var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie \\\n  -v /var/lib/trap/cowrie-fs/fs.pickle:/cowrie/cowrie-git/src/cowrie/data/fs.pickle \\\n  -v /var/lib/trap/cowrie-fs/honeyfs:/cowrie/cowrie-git/honeyfs:ro \\\n  cowrie/cowrie:latest', note: 'path ภายใน image อาจต่างตามรุ่น ตรวจด้วย docker run --rm cowrie/cowrie:latest ls /cowrie/cowrie-git ก่อน'},
      {title: 'ใส่ไฟล์ลวงของ Rabbit Hole ลง Cowrie อัตโนมัติ', text: 'timer นี้อ่าน /var/lib/trap/rabbit-hole.json ทุกนาที ถ้าฉาก SSH/Telnet เปลี่ยน (หรือปิด Rabbit Hole) จะแก้ fs.pickle กับ honeyfs สำรอง fs.pickle ไว้ก่อน แล้ว restart Cowrie ถ้าไม่เปลี่ยนจะไม่ทำอะไร', code: 'sudo cp honeypot/rabbit-hole/trap-cowrie-sync.* /etc/systemd/system/\nsudo nano /etc/systemd/system/trap-cowrie-sync.service   # ตรวจ path fs.pickle/honeyfs และคำสั่ง restart\nsudo systemctl daemon-reload && sudo systemctl enable --now trap-cowrie-sync.timer\nsudo systemctl start trap-cowrie-sync && journalctl -u trap-cowrie-sync -n 5', note: 'ถ้าใช้ Docker ตามขั้นก่อนหน้า ให้ตั้ง --fs-pickle /var/lib/trap/cowrie-fs/fs.pickle --honeyfs /var/lib/trap/cowrie-fs/honeyfs --restart-cmd "docker restart cowrie"'},
      {title: 'Rabbit Hole web decoy', text: 'config ไฟล์นี้ใช้ร่วมกับ Dashboard: Dashboard แก้ แล้ว trap-sync ส่งมาให้ทุกนาที', code: 'sudo cp /opt/trap/config/rabbit-hole.example.json /var/lib/trap/rabbit-hole.json\n# แก้: "web": {"host": "10.10.10.2", "port": 8084, "log_path": "/var/log/trap/rabbit-hole-web.jsonl",\n#        "trusted_proxies": ["10.10.10.1/32"]},\n#      "secret_path": "/var/lib/trap/rabbit-hole.secret",\n#      "custom_scenario_dir": "/var/lib/trap/rabbit-hole-scenarios"\ncd /opt/trap && python3 -m defender.rabbit_hole check --config /var/lib/trap/rabbit-hole.json\nsudo useradd --system --shell /usr/sbin/nologin traprabbit\nsudo chown traprabbit /var/log/trap\nsudo cp honeypot/rabbit-hole/trap-rabbit-hole.service /etc/systemd/system/\nsudo systemctl daemon-reload && sudo systemctl enable --now trap-rabbit-hole'},
      {title: 'Deploy agent (ปุ่ม Clone/Deploy)', text: 'ทำตาม honeypot/deploy-agent/README.md: สร้างผู้ใช้ trapdeploy, token, /etc/trap/deploy-agent.json แล้ว enable service', code: 'sudo cp /opt/trap/honeypot/deploy-agent/deploy-agent.example.json /etc/trap/deploy-agent.json\nsudo nano /etc/trap/deploy-agent.json   # IP, allowed_targets, run_as\nsudo systemctl enable --now trap-deploy-agent'},
      {title: 'ผู้ใช้สำหรับ sync จาก Defender', text: 'Defender ใช้ผู้ใช้นี้ส่ง config มาและดึง log กลับ', code: 'sudo useradd --create-home --shell /bin/sh trapsync\nsudo chown -R trapsync /var/lib/trap\nsudo setfacl -m u:trapsync:r /var/log/cowrie/cowrie.json /var/log/trap/rabbit-hole-web.jsonl\n# ใส่ public key ของ Defender ลง /home/trapsync/.ssh/authorized_keys'},
      {title: 'Firewall', code: 'sudo ufw default deny incoming\nfor p in 22 2222 2223 8081 8082 8083 8084 8091; do\n  sudo ufw allow from 10.10.10.1 to any port $p proto tcp\ndone\nsudo ufw enable && sudo ufw status numbered'},
    ]},
    {id: 'defender', title: 'Defender', machine: 'Defender · 192.168.56.10 / 10.10.10.1', lead: 'Defender ตรวจทุกคำขอ ให้คะแนน แล้วส่งไป Real Web หรือ Honeypot และเป็นที่อยู่ของ Dashboard นี้', steps: [
      {title: 'ลงแพ็กเกจและวาง repo', code: 'sudo apt update\nsudo apt install -y suricata nginx nftables python3 git rsync\nsudo git clone <repo-url> /opt/trap\ncd /opt/trap && python3 -m unittest discover -s tests'},
      {title: 'Suricata', text: 'ใช้กฎ ET Open 13 กฎของโครงงาน ฟัง interface ฝั่ง outer และเปิด eve-log', code: 'sudo cp defender/suricata/rules/et-open-selected.rules /etc/suricata/rules/\nsudo nano /etc/suricata/suricata.yaml   # rule-files: [et-open-selected.rules]  af-packet: interface: enp0s3\nsudo suricata -T -c /etc/suricata/suricata.yaml && sudo systemctl restart suricata'},
      {title: 'Decision Engine', text: 'เริ่มด้วย dry_run: true ดูผลใน log ก่อน แล้วค่อยเปลี่ยนเป็น false · web_profile เลือก snare หรือ rabbithole', code: 'sudo mkdir -p /etc/adaptive-defender\nsudo cp defender/decision_engine/config/live.json /etc/adaptive-defender/live.json\nsudo cp defender/decision_engine/systemd/adaptive-defender.service /etc/systemd/system/\nsudo systemctl daemon-reload && sudo systemctl enable --now adaptive-defender'},
      {title: 'Nginx', text: 'แทนค่า __TOKEN__ ทุกตัวใน template: OUTER_IP 192.168.56.10 · REAL_WEB 10.10.10.3:8080 · SNARE 10.10.10.2:8083 · RABBIT_HOLE 10.10.10.2:8084 · WORDPRESS :8081 · PHPMYADMIN :8082 · certificate ของ defender.lab', code: 'sudo cp defender/nginx/adaptive-honeypot.conf.template /etc/nginx/sites-available/trap\nsudo nano /etc/nginx/sites-available/trap\ngrep -n \'__[A-Z0-9_]*__\' /etc/nginx/sites-available/trap   # ต้องไม่เหลือ\nsudo ln -sf /etc/nginx/sites-available/trap /etc/nginx/sites-enabled/trap\nsudo nginx -t && sudo systemctl reload nginx'},
      {title: 'nftables (SSH/Telnet ไป Cowrie)', text: 'แทนชื่อ interface และ endpoint 10.10.10.2:2222 / 2223 ใน template ตั้ง timed rollback ตาม docs/root-operations.md ก่อน apply ทุกครั้ง', code: 'sudo cp defender/nftables/ssh-redirect.nft.template /etc/nftables.d/trap.nft\nsudo nano /etc/nftables.d/trap.nft\nsudo nft --check -f /etc/nftables.d/trap.nft && sudo nft -f /etc/nftables.d/trap.nft'},
      {title: 'Dashboard', text: 'แทน CHANGE_ME ทุกตัวใน trap.json แล้วสร้าง Master Admin · Dashboard ห้ามรันด้วย root', code: 'sudo mkdir -p /etc/trap /var/lib/trap/rabbit-hole-scenarios\nsudo cp config/trap.example.json /etc/trap/trap.json\nsudo useradd --system --shell /usr/sbin/nologin trap-dashboard\nsudo chown -R trap-dashboard /var/lib/trap\npython3 -m defender.dashboard.manage_users --file /etc/trap/users.json \\\n  --username admin --name "Master Admin" --role master_admin\nsudo cp defender/dashboard/systemd/trap-dashboard.service /etc/systemd/system/\nsudo systemctl daemon-reload && sudo systemctl enable --now trap-dashboard'},
      {title: 'ให้แก้กฎผ่าน Dashboard ได้บนเครื่องจริง', text: 'Dashboard ไม่มีสิทธิ์เขียนไฟล์กฎของ Suricata เอง มันเขียนชุดกฎที่แก้ลง /var/lib/trap/rules แล้ว trap-apply-rules (root) ทดสอบด้วย suricata -T ติดตั้ง reload และถอยกลับเองถ้าไม่ผ่าน ผลขึ้นในหน้า จัดการกฎ', code: 'sudo install -d -o trap-dashboard -g trap-dashboard /var/lib/trap/rules\nsudo cp defender/suricata/systemd/trap-apply-rules.* /etc/systemd/system/\nsudo systemctl daemon-reload && sudo systemctl enable --now trap-apply-rules.path\n# ใน /etc/trap/trap.json ส่วน rules: "apply_dir": "/var/lib/trap/rules"'},
      {title: 'เชื่อม Rabbit Hole และ Deploy ใน trap.json', text: 'rabbit-hole.json ใช้ไฟล์เดียวกับ Honeypot (path ตรงกันทั้งสองเครื่อง) คัดลอก secret จาก Honeypot มาครั้งเดียวด้วย scp -p เพื่อให้ path ลวงตรงกัน', code: '"paths": {\n  "rabbit_hole_config": "/var/lib/trap/rabbit-hole.json",\n  "rabbit_hole_logs": ["/var/log/trap/honeypot/rabbit-hole-web.jsonl"],\n  "honeypot_paths": ["/var/log/trap/honeypot/cowrie.json", "/var/log/trap/honeypot/tanner-events.jsonl"]\n},\n"web_deploy": {\n  "agent_url": "http://10.10.10.2:8091",\n  "token_file": "/etc/trap/deploy-agent.token"\n}'},
      {title: 'trap-sync ทุกนาที', text: 'ส่ง config ที่แก้ใน Dashboard ไป Honeypot และดึง log กลับมาให้ Dashboard อ่าน', code: 'sudo ssh-keygen -t ed25519 -N "" -f /etc/trap/trapsync_ed25519\nsudo ssh-copy-id -i /etc/trap/trapsync_ed25519 trapsync@10.10.10.2\nsudo scp -p -i /etc/trap/trapsync_ed25519 trapsync@10.10.10.2:/var/lib/trap/rabbit-hole.secret /var/lib/trap/\necho "* * * * * root /opt/trap/deploy/trap-sync.sh" | sudo tee /etc/cron.d/trap-sync'},
      {title: 'เปิด Dashboard จากเครื่องผู้ดูแล', text: 'Dashboard ฟังเฉพาะ 127.0.0.1 จึงเข้าผ่าน SSH tunnel แล้วเปิด http://127.0.0.1:9090/', code: 'ssh -L 9090:127.0.0.1:9090 <user>@<management IP ของ Defender>'},
    ]},
    {id: 'verify', title: 'เชื่อมและตรวจ', machine: 'ทำบน Defender', lead: 'ตรวจทีละชั้นจากล่างขึ้นบน ถ้าขั้นไหนไม่ผ่าน อย่าข้ามไปขั้นถัดไป', steps: [
      {title: 'Defender เข้าถึงทุก backend', code: 'curl -fsS -o /dev/null -w "%{http_code}\\n" http://10.10.10.3:8080/\ncurl -fsS -o /dev/null -w "%{http_code}\\n" http://10.10.10.2:8083/\ncurl -fsS -o /dev/null -w "%{http_code}\\n" http://10.10.10.2:8084/\nnc -zv 10.10.10.2 2222 && nc -zv 10.10.10.2 2223'},
      {title: 'ตรวจความพร้อมด้วยเครื่องมือของโครงงาน', text: 'ห้ามไปต่อถ้ารายงานมีสถานะ blocked', code: 'cd /opt/trap\npython3 -m defender.validation.readiness --pretty\npython3 -m defender.validation.production --config /etc/trap/trap.json --pretty'},
      {title: 'ทดสอบการส่งต่อจากเครื่องผู้โจมตีทดสอบ', text: 'ยิงคำขอที่ตรงกฎหลายครั้งจนคะแนนถึงเกณฑ์ แล้วดูในหน้า การแจ้งเตือน ว่ามี "ส่งต่อ Web Honeypot"', code: 'for i in 1 2 3; do curl -sk -A "sqlmap/1.8" "https://defender.lab/?id=1%20UNION%20SELECT" >/dev/null; done\ncurl -sk https://defender.lab/robots.txt   # หลังถึงเกณฑ์ ต้องได้หน้าจาก Honeypot'},
      {title: 'ทดสอบ SSH ไป Cowrie', code: 'ssh -o StrictHostKeyChecking=no root@192.168.56.10   # หลังถึงเกณฑ์ ต้องเข้า Cowrie'},
      {title: 'ตรวจใน Dashboard', text: 'ภาพรวม: บริการ 3 ตัวต้องขึ้น "ทำงาน" · Rabbit Hole: ต้องเห็น Session หลังทดสอบ · Deploy หน้าเว็บ: สถานะ SNARE ต้อง "ตอบปกติ"'},
    ]},
    {id: 'windows', title: 'ลองบน Windows', machine: 'เครื่องของตัวเอง', lead: 'ลองใช้ Dashboard กับข้อมูลเดโม่ได้โดยไม่ต้องมี 3 เครื่อง ไม่ต้องมี Docker', steps: [
      {title: 'ติดตั้ง Python 3.8 ขึ้นไป', text: 'จาก python.org ติ๊ก "Add python.exe to PATH" ตอนติดตั้ง'},
      {title: 'ดับเบิลคลิก start-trap-demo.bat', text: 'ไฟล์อยู่ในโฟลเดอร์ vm-defender จะสร้างข้อมูลเดโม่ แล้วเปิดหน้าต่าง Deploy agent (โหมดทดลอง) กับ Dashboard ให้ ต้องเปิดสองหน้าต่างนี้ค้างไว้'},
      {title: 'เปิด http://127.0.0.1:9090/', text: 'เข้าสู่ระบบด้วยบัญชีใน config/users.json (สร้างใหม่ได้ด้วย manage_users)', code: 'python -m defender.dashboard.manage_users --file config/users.json --username admin --name "Master Admin" --role master_admin'},
    ]},
    {id: 'trouble', title: 'แก้ปัญหา', lead: 'อาการที่พบบ่อยและวิธีแก้', table: {head: ['อาการ', 'สาเหตุ', 'วิธีแก้'], rows: [
      ['ฟีเจอร์ใหม่ขึ้น 404', 'Dashboard ยังรันโค้ดเก่า', 'ปิดแล้วเปิด Dashboard ใหม่ (systemctl restart trap-dashboard)'],
      ['Deploy: ติดต่อ agent ไม่ได้', 'service ไม่ทำงาน หรือ firewall ปิด 8091', 'systemctl status trap-deploy-agent · ufw allow from 10.10.10.1 port 8091'],
      ['Deploy: host ไม่อยู่ในรายการ', 'URL ไม่อยู่ใน allowed_targets', 'เพิ่ม host:port ใน /etc/trap/deploy-agent.json แล้ว restart agent'],
      ['Clone ได้หน้าเปล่า', 'เว็บเป็น SPA ที่สร้างหน้าด้วย JavaScript', 'ใช้ไฟล์ build ของหน้าเว็บแทนการ clone'],
      ['Rabbit Hole ไม่มีข้อมูล', 'trap-sync ไม่ได้ดึง log', 'รัน /opt/trap/deploy/trap-sync.sh เองแล้วดู error'],
      ['path ลวงใน Dashboard ไม่ตรงกับเว็บ', 'secret สองเครื่องไม่เหมือนกัน', 'scp -p secret จาก Honeypot มาที่ Defender อีกครั้ง'],
      ['preflight รายงาน blocked', 'ยังมี CHANGE_ME ใน config', 'แทนค่าให้ครบ นี่คือกลไกป้องกัน ไม่ใช่ bug'],
    ]}},
  ];

  let current = 'overview';

  async function liveStatus(id) {
    const chips = [];
    try {
      if (id === 'defender') {
        const s = await fetch('/api/status.json').then(r => r.ok ? r.json() : {});
        for (const [k, n] of [['suricata', 'Suricata'], ['nginx', 'Nginx'], ['decision_engine', 'Decision Engine']]) {
          const v = s[k] || 'unknown';
          chips.push([n, v === 'active' ? 'ทำงาน' : v, v === 'active' ? 'ok' : 'warn']);
        }
      }
      if (id === 'honeypot') {
        const d = await fetch('/api/web-deploy/status.json');
        if (d.ok) { const s = await d.json(); chips.push(['Deploy agent', s.dry_run ? 'โหมดทดลอง' : 'เชื่อมแล้ว', s.dry_run ? 'warn' : 'ok'], ['SNARE', s.healthy ? 'ตอบปกติ' : 'ไม่ตอบ', s.healthy ? 'ok' : 'bad']); }
        else chips.push(['Deploy agent', 'ยังไม่ได้เชื่อม', 'warn']);
        const r = await fetch('/api/rabbit-hole.json?window=24h');
        if (r.ok) { const s = await r.json(); chips.push(['Rabbit Hole', s.problems.length ? `config มีปัญหา ${s.problems.length} ข้อ` : (s.enabled ? 'config ถูกต้อง' : 'ปิดอยู่'), s.problems.length ? 'bad' : 'ok']); }
        else chips.push(['Rabbit Hole', 'ยังไม่ได้ตั้งค่า', 'warn']);
      }
    } catch (e) { chips.push(['สถานะ', 'ตรวจไม่ได้', 'warn']); }
    return chips;
  }

  function render() {
    const done = load();
    $g('guide-tabs').innerHTML = GUIDE.map(s => {
      const steps = s.steps || [], n = steps.filter((_, i) => done[`${s.id}:${i}`]).length;
      return `<button type="button" role="tab" data-guide-tab="${s.id}" class="${s.id === current ? 'active' : ''}" aria-selected="${s.id === current}">${esc(s.title)}${steps.length ? `<span class="guide-count">${n}/${steps.length}</span>` : ''}</button>`;
    }).join('');
    const s = GUIDE.find(x => x.id === current);
    const table = s.table ? `<div class="card"><div class="table-wrap"><table><thead><tr>${s.table.head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${s.table.rows.map(r => `<tr>${r.map(c => `<td>${esc(c).replace(/\n/g, '<br>')}</td>`).join('')}</tr>`).join('')}</tbody></table></div></div>` : '';
    const steps = (s.steps || []).map((st, i) => {
      const key = `${s.id}:${i}`, ok = !!done[key];
      return `<li class="guide-step ${ok ? 'done' : ''}"><div class="guide-step-head"><span class="guide-no">${i + 1}</span><h4>${esc(st.title)}</h4><label class="guide-check"><input type="checkbox" data-guide-done="${key}" ${ok ? 'checked' : ''}> ทำแล้ว</label></div>${st.text ? `<p>${esc(st.text)}</p>` : ''}${st.code ? `<div class="guide-code"><pre>${esc(st.code)}</pre><button type="button" class="tonal small guide-copy">คัดลอก</button></div>` : ''}${st.note ? `<p class="data-note">${esc(st.note)}</p>` : ''}</li>`;
    }).join('');
    $g('guide-body').innerHTML = `<div class="guide-head"><div>${s.machine ? `<span class="pill info">${esc(s.machine)}</span>` : ''}<p>${esc(s.lead)}</p></div><div class="guide-live" id="guide-live"></div></div>${s.diagram ? `<div class="card guide-diagram-card">${DIAGRAM}</div>` : ''}${table}${steps ? `<ol class="guide-steps">${steps}</ol>` : ''}${s.note ? `<p class="data-note">${esc(s.note)}</p>` : ''}`;
    liveStatus(s.id).then(chips => { const el = $g('guide-live'); if (el && current === s.id) el.innerHTML = chips.map(([n, v, c]) => `<span class="pill ${c}">${esc(n)}: ${esc(v)}</span>`).join(''); });
  }

  $g('guide-tabs').addEventListener('click', e => { const b = e.target.closest('[data-guide-tab]'); if (b) { current = b.dataset.guideTab; render(); } });
  $g('guide-body').addEventListener('change', e => { const c = e.target.closest('[data-guide-done]'); if (!c) return; const d = load(); if (c.checked) d[c.dataset.guideDone] = 1; else delete d[c.dataset.guideDone]; save(d); render(); });
  $g('guide-body').addEventListener('click', e => {
    const b = e.target.closest('.guide-copy'); if (!b) return;
    const text = b.parentElement.querySelector('pre').textContent;
    const ok = () => { b.textContent = 'คัดลอกแล้ว'; setTimeout(() => { b.textContent = 'คัดลอก'; }, 1500); };
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(ok).catch(() => { const r = document.createRange(); r.selectNodeContents(b.parentElement.querySelector('pre')); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); b.textContent = 'กด Ctrl+C'; });
  });
  document.querySelector('[data-view="guide"]').addEventListener('click', render);
  window.trapGuideRender = render;
})();
