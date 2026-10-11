| Container | Image / digest จาก VM | พอร์ตบน host | Volume จาก VM | Restart policy |
|---|---|---|---|---|
| cowrie | cowrie/cowrie@sha256:710f1e4601a663ac8591f58a42b44e4cd3b7ea170c7e6cdb9e54c430a30cd459<br>cowrie/cowrie@sha256:710f1e4601a663ac8591f58a42b44e4cd3b7ea170c7e6cdb9e54c430a30cd459 | 10.10.10.2:2222 → 2222/tcp, 10.10.10.2:2223 → 2223/tcp | /etc/trap/cowrie/cowrie.cfg → /cowrie/cowrie-git/etc/cowrie.cfg (ro)<br>/etc/trap/cowrie/userdb.txt → /cowrie/cowrie-git/etc/userdb.txt (ro)<br>/var/lib/docker/volumes/2ea4502644361c1597d9357905f3e84167bcf3bb72ef3ac5d11395342bc81983/_data → /cowrie/cowrie-git/var (rw)<br>/var/lib/docker/volumes/trap-honeypot_cowrie-var/_data → /cowrie/cowrie-git/var/lib/cowrie (rw)<br>/var/log/cowrie → /cowrie/cowrie-git/var/log/cowrie (rw)<br>/var/lib/trap/cowrie-fs → /cowrie/trapfs (ro)<br>/var/lib/docker/volumes/5d01f084e5ae9b5259ac00d5377ff04cfeaa41bb0ab8bce152bd0cc9b387d18f/_data → /cowrie/cowrie-git/etc (rw) | unless-stopped |
| web-honeypot | trap/web-honeypot:local<br>trap/web-honeypot@sha256:fd6d7993d6d0103551955a84cd342dfd41d8a2851765f6b828adbc743a21aa97 | 10.10.10.2:8084 → 8084/tcp | /var/lib/trap → /var/lib/trap (ro)<br>/var/log/trap → /var/log/trap (rw) | unless-stopped |

# TRAP รอบ 5: Docker Honeypot และการกู้คืน

Test-start UTC: `2026-10-10T13:23:20.868556+00:00`; ผลเคสที่ยืนยันล่าสุด: **PASS 31 / FAIL 1 / SUPERSEDED 2**. SUPERSEDED เก็บผล FAIL เดิมของเครื่องมือทดสอบไว้ พร้อมผลทดสอบซ้ำ; ไม่มีการลบหลักฐาน.

รอบนี้ทำเฉพาะ Honeypot และ sync ที่ Defender ใช้กับ Honeypot ไม่ทำงานรอบ 4 ซ้ำ ไม่แก้ code/config ของ Project-Web และไม่ commit. SID 2100492 ที่ FAIL ในรอบ 4 ไม่ได้ทดสอบซ้ำ จึงไม่มีข้อสรุปใหม่ต่อกฎนั้น.

## การติดตั้ง

Sync working tree รวมไฟล์ untracked ไป `/opt/trap` บน Honeypot; source-manifest เก็บ hash ก่อน deploy และ source-docs-final เก็บ hash ของไฟล์ที่ปรับตามอิมเมจจริง. ข้าม `.git`, runtime cache, generated evidence และ secret environment files. Unit test บน VM ผ่าน **123/123**; หลังเพิ่ม paused-state subcase ใน test เดิม ชุด watchdog ผ่าน **10/10**.

Cowrie อิมเมจจริงเป็น v3.1.1, UID/GID `999:999`, distroless ไม่มี `/bin/sh`. Default config อยู่ `/cowrie/cowrie-git/src/cowrie/data/etc/cowrie.cfg.dist`; override config/userdb ยังคง mount ที่ `/cowrie/cowrie-git/etc`. ตรวจ `[shell] filesystem`, `[honeypot] contents_path`, และ `[telnet] enabled/listen_endpoints` จากอิมเมจจริงแล้ว.

ย้าย config/userdb ไป `/etc/trap/cowrie`, filesystem+honeyfs ไป `/var/lib/trap/cowrie-fs`, log ไป `/var/log/cowrie/cowrie.json`. คง hostname/banner และข้อมูล Rabbit Hole เดิม. สร้าง account traprabbit ให้ตรง compose เพราะบริการเดิมใช้ account cowrie; ตั้ง UID/GID จาก account จริง. Web config ใช้ `0.0.0.0` และ trusted proxy `10.10.10.1/32`.

ปิดและ disable unit `cowrie`/`trap-rabbit-hole` เดิมโดยคงไฟล์ไว้. เปิด Docker, watchdog timer และ cowrie-sync timer. ใช้ config ใน `/var/lib/trap/rabbit-hole.json`; Defender push scenario ด้วย restricted rsync account และดึง log ด้วย restricted exporter เดิมที่เปลี่ยน path แล้ว. แก้ pull เดิมที่เขียน config ทับ Dashboard เพื่อให้ Dashboard เป็น config ต้นทาง. ระหว่างตั้ง sync พบ rsync ตั้งเวลา directory ไม่ได้; แก้ด้วย `--omit-dir-times` และยืนยัน sync สำเร็จ.

สำรอง native `/opt/cowrie`, `/var/lib/trap`, `/var/log/trap` และ unit เดิมไว้บน Honeypot ที่ `/root/trap-round5-backup/` (ไม่รวม backup ที่มี secret ใน zip). Hash backup และ log ก่อนย้ายอยู่ `host/backup.json`.

RAM host ก่อนเริ่ม **1.798 GB** ต่ำกว่าเกณฑ์ 2 GB และรายงานผู้ใช้ก่อนติดตั้งแล้ว. RAM available ของ Defender/Honeypot/Web ก่อนเริ่ม 1537/1540/1355 MB ตาม `host/baseline.json`; ไม่สรุปว่าความล่าช้าเกิดจาก RAM เพราะไม่มีหลักฐานยืนยันสาเหตุ.

NTP ทั้งสามเครื่อง active และ synchronized ตั้งแต่ baseline. วัดความต่างสูงสุดก่อน migration **0.0095 วินาที** ด้วย SSH RTT midpoint และเลือก sample RTT ต่ำสุด; ไม่มีความต่างสามนาทีในรอบนี้.

ไฟล์ repo ที่แก้ในรอบนี้:

- `honeypot/docker/README.md`: วิธีตรวจ distroless, path config, UID และข้อควรปรับสำหรับ lab เดิม
- `honeypot/docker/compose.yaml`: แก้คำอธิบายวิธีตรวจ path โดยไม่ใช้ shell
- `honeypot/docker/cowrie.cfg.example`: แก้ path ของ default config ในคำอธิบาย
- `tests/test_honeypot_watchdog.py`: เพิ่ม subcase ของ Docker Status=paused

## Decoy และ IP

SSH login สำเร็จด้วยบัญชีจำลอง sysadmin; hostname `trap-backup-01`, notes.txt ชี้ไป backup.conf และอ่านได้. Telnet ทดสอบจาก telnetd จริงผ่าน SID **2101251** แล้วเข้าถึง Cowrie. HTTP/HTTPS ผ่านเส้น `/backup/` → `config.json` → API และ SSH Rabbit Hole ทำงาน.

Immediate redirect HTTP 3 + HTTPS 3 ผ่าน **6/6**; อ่าน decision แล้วส่ง request ถัดไปทันทีโดยไม่มี sleep เพิ่ม. ทุก decision มี `nginx_ready=true`; nginx_ready_seconds min/median/max **0.157/0.161/0.192**. Nginx profile ไม่ใช่ real, upstream `10.10.10.2:8084`, origin log พบ request จาก source เดิม.

Cowrie มี hassh, version, duration_ms, username/password และ command/input. ค่า password ถูกปิดบังในหลักฐานเผยแพร่. Dashboard แสดง session/dwell time ได้. เพิ่มไฟล์ `/opt/backup/round5-probe.txt` ผ่าน scenario ใน Dashboard แล้ว push+sync ให้ Cowrie อ่านได้; คืน scenario linux-server และตรวจ filesystem ไม่เหลือ probe แล้ว.

Traffic ปกติ HTTP/HTTPS/SSH ไป Project-Web และไม่มี Honeypot event. Source IP เลือกจาก log เต็มของทั้ง Defender และ Honeypot แล้วตรวจว่าไม่เคยใช้; mapping อยู่ `defender/source-ips.json`. `source-IP-audit.json` ยืนยัน source ทุก event เป็น `192.168.56.x` และไม่พบ request/session จาก Honeypot/Docker เองตลอดรอบ. Cowrie dst_ip เป็น Docker IP ได้ตาม NAT; src_ip ต้องเป็นผู้เชื่อมต่อจริง.

## การกู้คืน

เวลาเป็นค่าที่เครื่องมือสังเกตว่าพอร์ตกลับมาฟัง และเวลาหลังตรวจ request/shell สำเร็จ รวมเวลาตรวจผ่าน SSH. บางกรณีช้ากว่าเป้าหมายประมาณ 20 วินาทีหรือประมาณหนึ่งนาที จึงไม่อ้างว่าผ่านเป้าหมายเวลา แม้การกู้คืนและ decoy หลัง recovery ทำงาน. แนบ watchdog JSONL ทั้งไฟล์และ ID เต็มในหลักฐาน.

| Container | Fault | ฟังพอร์ตอีกครั้ง (s) | ยืนยันใช้งานได้ (s) | ID ก่อน → หลัง | ผล |
|---|---|---:|---:|---|---|
| cowrie | kill | 20.49 | 26.25 | 4810c16aadcd → 4810c16aadcd | PASS |
| cowrie | remove | 17.18 | 22.83 | 4810c16aadcd → 8b61b6dbbffc | PASS |
| cowrie | stop | 8.53 | 14.38 | 8b61b6dbbffc → 24550fb3290f | PASS |
| cowrie | pause | 22.42 | 28.15 | 24550fb3290f → ee92960bb077 | PASS |
| cowrie | sigstop | 90.92 | 96.49 | ee92960bb077 → 319e0eec7e4d | PASS |
| web-honeypot | kill | 49.40 | 51.12 | 11e6d82da4e5 → 11e6d82da4e5 | PASS |
| web-honeypot | remove | 51.76 | 53.17 | 11e6d82da4e5 → 59b80b4a4487 | PASS |
| web-honeypot | stop | 12.26 | 14.08 | 59b80b4a4487 → fd6b9be7a900 | PASS |
| web-honeypot | pause | 26.79 | 28.48 | fd6b9be7a900 → e99840d8f1e7 | PASS |
| web-honeypot | sigstop | 80.19 | 82.12 | e99840d8f1e7 → ebb63bcc1fc0 | PASS |

kill process: ID เดิมและ RestartCount เพิ่ม ใช้ restart policy. remove/stop/pause/SIGSTOP: container ID เปลี่ยนโดย watchdog. SIGSTOP มีหลักฐาน process state T และ socket ยังฟัง; watchdog บันทึก unhealthy สองครั้งแล้ว replace เมื่อครบสามครั้ง. ทุกกรณีตามด้วย redirect จาก IP ใหม่, Rabbit Hole และ log ก่อนหน้ายังอยู่. ไม่ทดสอบ deadlock ที่ process ยังรันและ socket ฟังตามข้อจำกัดที่ระบุ.

## รีบูต

หลังบูตช่วงแรก NTP ยังไม่ synchronized; timesyncd ปรับเวลาเองเมื่อ 13:41:41 UTC และค่าหลัง synchronize ผ่านเกณฑ์หนึ่งวินาที. ไม่มี boot ค้างหรือการ reset/start ด้วยมือในรอบนี้.

รีบูตเฉพาะ Project-Honeypot. Boot ID เปลี่ยน และ Docker/container/watchdog/cowrie-sync กลับมาเองโดยไม่ได้สั่ง start. สังเกตกลับเข้าถึงผ่าน SSH หลังประมาณ **30.8 วินาที**; redirect SSH/HTTP จาก IP ใหม่ผ่าน. ความต่างนาฬิกาสูงสุดทั้งสาม VM หลังบูต **0.0040 วินาที**.

รายละเอียดการบูต, memory และการกระทำอยู่ `host/reboot-before.json`, `host/reboot-request.json`, `host/reboot-after.json` และ console evidence (ถ้ามี).

## หลักฐานและผลที่แก้ไข

รายงานรอบ 4 เก็บที่ `Previous-Reports/round4-before-round5-20261010T132320Z` พร้อมตรวจ SHA256 ตรงก่อน/หลัง. รอบ 4 evidence zip และหลักฐาน FAIL เดิมยังอยู่.

ผล FAIL เดิมของสคริปต์รอบนี้สองรายการ: Cowrie-fields ตรวจ `duration` แทนฟิลด์จริง `duration_ms`; Dashboard-session-dwell เรียก endpoint ที่ไม่มี แทน `/api/honeypot.json`. ผลทดสอบซ้ำผ่านและเก็บผลเดิมเป็น SUPERSEDED. Snapshot `paused-before-fix.json` ถูกถ่ายระหว่าง SIGSTOP หลัง pause กู้คืนแล้ว จึงไม่พิสูจน์ failure ของ pause; เก็บ correction และถอนข้อสรุปเดิม. ไม่มี watchdog bug ที่ยืนยันจาก snapshot นี้ และไม่มีการเปลี่ยน implementation watchdog ในผลสุดท้าย.

หลักฐานอยู่ `TRAP-Retest-Evidence/round5-20261010T132320Z`, มี log จากต้นทาง Honeypot, EVE/decision/Nginx จาก Defender และ origin log ของ Project-Web. ทุกเคสใช้ start_time >= test-start. ZIP ผ่าน CRC และตรวจค่ารหัสผ่าน/TOTP จริงใน memory ว่าไม่ปรากฏ; ไม่รวม secret environment file หรือ private backup. `manifest.json` ระบุ SHA256 รายไฟล์.

| เคส | ผลล่าสุด | ข้อผิดพลาด / หมายเหตุ |
|---|---|---|
| Installation-container-inventory | PASS |  |
| Redirect-SSH-and-Rabbit | PASS |  |
| Redirect-Telnet-real-SID2101251 | PASS |  |
| Redirect-HTTP-Rabbit | PASS |  |
| Redirect-HTTPS-Rabbit | PASS |  |
| Immediate-HTTP-1 | PASS |  |
| Immediate-HTTP-2 | PASS |  |
| Immediate-HTTP-3 | PASS |  |
| Immediate-HTTPS-1 | PASS |  |
| Immediate-HTTPS-2 | PASS |  |
| Immediate-HTTPS-3 | PASS |  |
| Normal-HTTP | PASS |  |
| Normal-HTTPS | PASS |  |
| Normal-SSH | PASS |  |
| Cowrie-fields | SUPERSEDED | Missing Cowrie fields: {'duration'} |
| Dashboard-session-dwell | SUPERSEDED | Session endpoint failed |
| Cowrie-fields-retest | PASS |  |
| Dashboard-session-dwell-retest | PASS |  |
| Dashboard-scenario-sync-Cowrie-and-restore | PASS |  |
| Dashboard-session-dwell-final | PASS |  |
| Recovery-cowrie-kill | PASS |  |
| Recovery-cowrie-remove | PASS |  |
| Recovery-cowrie-stop | PASS |  |
| Recovery-cowrie-pause | PASS |  |
| Recovery-cowrie-sigstop | PASS |  |
| Recovery-web-honeypot-kill | PASS |  |
| Recovery-web-honeypot-remove | PASS |  |
| Recovery-web-honeypot-stop | PASS |  |
| Recovery-web-honeypot-pause | PASS |  |
| Recovery-web-honeypot-sigstop | PASS |  |
| Reboot-containers-and-timers | PASS |  |
| Reboot-redirect-SSH | PASS |  |
| Reboot-redirect-HTTP | PASS |  |
| Timing-web-honeypot-remove | FAIL | Observed port availability 51.76s; requested approximately 20s target not met. Recovery itself succeeded. Root cause not proven. |
