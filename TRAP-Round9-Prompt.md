# TRAP — Round 9 test prompt

ทดสอบรอบ 9 บน lab 3 VM เดิม (SSH management 2221 Defender / 2222 Honeypot / 2223 Web ตาม TRAP-Access-Guide.md)
รูปแบบรายงาน Matrix, ZIP และ SHA เหมือนรอบ 8 ย้ายรายงานรอบ 8 ไป Previous-Reports ก่อนเริ่ม
ห้ามใส่รหัสผ่าน, TOTP secret หรือ cookie ในรายงาน ใช้ source IP ใหม่ทุกเคส

## สิ่งที่เปลี่ยนจากรอบ 8

- `deploy/isolation/` ใหม่: `honeypot.nft`, `web.nft`, `defender.nft`, `trap-isolation.service` (table `inet trap_isolation`)
- `honeypot/docker/compose.yaml`: cowrie `read_only: true` + tmpfs `/tmp`
- คู่มือในแอป: เปลี่ยนขั้น ufw เป็น isolation
- ปุ่ม Clone: Defender (Dashboard) เป็นคน clone แล้วอัปโหลดสำเนาไป deploy agent (`POST /v1/versions`);
  agent ไม่มี `/v1/clone` แล้ว ต้องเพิ่ม `"allowed_targets": ["10.10.10.3:8080"]` ใน `web_deploy` ของ `/etc/trap/trap.json`
  และลบ `allowed_targets`, `run_as`, `clone_timeout` ออกจาก `/etc/trap/deploy-agent.json` ได้ (ถูกละเว้น)

## Deploy

1. อ่านสถานะก่อนแก้ทุกเครื่อง: `docker ps`, `ss -lntu`, `nft list ruleset` เก็บเป็น before
2. สำรอง `nft list ruleset` ไป `/root/trap-backup/nftables.before-isolation.nft` ทั้ง 3 เครื่อง
3. sync working tree ไป `/opt/trap` ทั้ง 3 เครื่อง ตรวจ SHA manifest
4. ติดตั้ง isolation ทีละเครื่องตาม `deploy/isolation/README.md` (ROLE=web → honeypot → defender)
   และตั้ง timed rollback ก่อน apply (`docs/root-operations.md`)
5. Honeypot: `docker compose -p trap-honeypot -f /opt/trap/honeypot/docker/compose.yaml up -d` ให้ cowrie ถูกสร้างใหม่ด้วย read_only
6. unit test ทั้ง 3 เครื่อง (ต้องได้ 157 รวม `tests/test_isolation.py` และ `tests/test_deploy_agent.py` ชุดใหม่)

## ต้องวัด

| ข้อ | สิ่งที่วัด | ผ่านเมื่อ |
|---|---|---|
| D1 | `nft list table inet trap_isolation` ทุกเครื่อง, `systemctl is-enabled/is-active trap-isolation`, inspect cowrie | table ครบ, service active, cowrie `ReadonlyRootfs=true` |
| D2 | catalog เดิมของรอบ 8 ครบทุกคู่ (Honeypot-VM, cowrie, web-honeypot → Web/Defender/host-only/1.1.1.1) | ทุกคู่ที่รอบ 8 เป็น `FAIL isolation` ต้องต่อไม่ได้ (timeout) และ counter ของกฎที่ตรงกันขึ้น; container → 1.1.1.1:443 ต่อไม่ได้ |
| D2-host | Honeypot host → 1.1.1.1:443 | ยังต่อได้ (NAT management ไม่ถูกปิด) บันทึกเป็น observation |
| D3 | wget/curl ใน Cowrie ผ่าน redirect จริง + capture ฝั่ง Web/Defender | ไม่มี packet จาก 10.10.10.2 |
| D4 | Defender→Cowrie SSH/Telnet DNAT, Defender→web-honeypot 8084, web-honeypot→web-app, trap-sync (log มาที่ Dashboard), deploy agent `/v1/status` | ผ่านทุกข้อเหมือนรอบ 8 |
| D5 | low-risk SSH 22 / Telnet 23 จาก attacker ไป Web จริง, Nginx → Web 8080 | ยังเข้าได้ / HTTP 200 |
| D6 | `docker logs cowrie` หลัง start และหลัง D3 | ไม่มี error เขียนไฟล์ (Read-only file system) |
| D7 | reboot Honeypot 1 ครั้ง | table กลับมาก่อน container, cowrie/web-honeypot ฟังพอร์ต, D2 แถว container ยังต่อไม่ได้ |
| D8 Clone | ถ้าติดตั้ง SNARE + deploy agent: กด Clone `http://10.10.10.3:8080/` ใน Dashboard, ดูตัวอย่าง, Deploy | job สำเร็จ, capture ฝั่ง Web เห็น request จาก 10.10.10.1 เท่านั้น ไม่มีจาก 10.10.10.2, SNARE เสิร์ฟเวอร์ชันใหม่ ถ้าไม่ได้ติดตั้ง SNARE ให้บันทึก NOT_TESTABLE |
| Regression | D0 รอบ 8 (B3/B4/B7, Rabbit Hole, A3 HTTPS session) | ผลเหมือนรอบ 8 |

## ข้อห้าม

- ห้าม `nft flush ruleset` หรือแก้ table ของ Docker / `adaptive_defender`
- ถ้า apply แล้ว management SSH หลุด ให้ปล่อย timed rollback ทำงาน แล้วรายงานเป็น FAIL พร้อมหลักฐาน ห้ามแก้กฎเองหน้างาน
- ไม่แก้ implementation และไม่ commit
