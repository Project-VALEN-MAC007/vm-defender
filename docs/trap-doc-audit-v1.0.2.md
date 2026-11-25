# ตรวจระบบเทียบกับเอกสาร TRAP (V1.0.2)

ตรวจวันที่ 16 พฤศจิกายน 2026 เทียบ `TRAPedit_tomorrowV1.0.2.docx` (บทที่ 1–2 และเอกสารอ้างอิง)
กับโค้ดใน repository นี้ที่ commit `844d645` (branch `feat/nginx-prefilter`)

ผลทดสอบอัตโนมัติ: `python3 -m unittest discover -s tests` ผ่าน **192 รายการ (ข้าม 1)**
บน Python ของเครื่องพัฒนาที่รันบน Windows — ไม่ใช่ผลบน Ubuntu และไม่ได้ทดแทนการทดสอบ lab
หลักฐาน lab ล่าสุดยังเป็นรายงานรอบ 9 (`TRAP-Test-Report.md`, 11 ตุลาคม 2026)

ขอบเขตการตรวจ: อ่านโค้ด/เอกสาร/ไฟล์ config แบบ static + รัน unit test เท่านั้น
ไม่ได้รัน lab 3 VM ใหม่ และไม่ได้เทียบรูป 42 รูปในเล่มกับหน้าจอจริง

## สรุป

| ผล | จำนวนหัวข้อ |
|---|---:|
| ตรงกับระบบ | 41 |
| ตรงบางส่วน / ต้องเขียนเงื่อนไขกำกับ | 3 |
| ไม่ตรงกับระบบ | 3 |
| เอกสารยังไม่มีเนื้อหา (ช่องว่างของเล่ม) | 3 |
| ระบบมีเกินเอกสาร | 9 |

รายการที่ไม่ตรง 3 ข้อคือ §1.3.1 จำนวน "3 ส่วนหลัก" (§2.1), ถ้อยคำ "เสี่ยง → redirect" ที่ไม่กล่าวถึง
`monitor`/scan-only (§2.5) และ §1.5 ที่บอกว่าเก็บ log รวมไฟล์เดียว (§2.7)

## 1. ตรวจทีละหัวข้อ

### 1.1 บทนำ (บทที่ 1)

| หัวข้อเอกสาร § | ส่วนของระบบ | ผล |
|---|---|---|
| 1.2 วัตถุประสงค์: พัฒนาฮันนีพอตแบบปรับตัวและติดตั้งในสภาพแวดล้อมจำลอง | 3 VM: Defender / Honeypot / Web ตาม `defender/network/topology.md` | ตรง |
| 1.3.1 ส่วนประกอบของโครงงาน 3 ส่วนหลัก | `defender/`, `honeypot/`, `defender/dashboard/` | ตรง (ดูข้อ 2.1) |
| 1.3.2.1 Suricata + ET Open Default + เพิ่ม/แก้กฎได้ | ระบบใช้ `defender/suricata/rules/et-open-selected.rules` 13 กฎ | ตรง (แก้แล้วจาก V0.8.4) |
| 1.3.2.1 Decision Engine เทียบค่า Threshold | `RiskEngine` + `thresholds {monitor, redirect}` | ตรง |
| 1.3.2.1 Nginx เปลี่ยนเส้นทาง HTTP/HTTPS | `defender/nginx/adaptive-honeypot.conf.template` | ตรง |
| 1.3.2.1 nftables เปลี่ยนเส้นทาง SSH/Telnet | `defender/nftables/ssh-redirect.nft.template` (table `inet adaptive_defender`, set + timeout 30m) | ตรง |
| 1.3.2.2 Web Honeypot ปรับรูปแบบหน้าเว็บได้ | `webapp/` (snapshot + `BACKEND=real/decoy`) และ SNARE clone ผ่านหน้า Deploy | ตรง |
| 1.3.2.2 Web Honeypot บันทึก เวลา/ไอพี/พอร์ตต้น-ปลายทาง | `rabbit_hole/web.py:197-198` บันทึก `source_ip, source_port, dest_ip, dest_port` | **ตรงบางส่วน** (ดูข้อ 2.3) |
| 1.3.2.2 Remote Shell ใช้ Cowrie บันทึก เวลา/IP:port/โปรโตคอล/user-pass/ผล login/คำสั่ง/เวลา/Session ID | `honeypot/docker/compose.yaml` + `dashboard/scope.py:86-109` | ตรง |
| 1.3.2.3 Login + TOTP ป้องกัน Flush | `dashboard/security.py` (TOTP 30 วินาที, challenge 5 นาที, 5 ครั้ง) + `/api/logs/flush` บังคับ TOTP | ตรง |
| 1.3.2.3 ภาพรวม: จำนวนเหตุการณ์/IP/Rank/Honeypot/สถานะ 3 บริการ | `app.py:108-118` เรียก `systemctl is-active` suricata/nginx/adaptive-defender | ตรง |
| 1.3.2.3 แจ้งเตือน: เวลา/IP/ประเภท redirect/กฎ+severity/เวลาใน Honeypot, อ่านแล้ว, ลบ | `scope.event_notifications()` + `/api/events/update` | ตรง (ลบ = ซ่อนในมุมมองผู้ใช้ ไม่ลบ log ต้นฉบับ) |
| 1.3.2.3 ค้นหา Log ย้อนหลัง + ตัวกรอง | `/api/logs.json`, `search_logs()` | ตรง |
| 1.3.2.3 ดูเส้นทาง Rabbit Hole ราย Session (เวลา/IP/โปรโตคอล/ความลึก) | `dashboard/rabbit.py`, `/api/rabbit-hole/*` | ตรง |
| 1.3.2.3 รายงาน + เวลาเฉลี่ยใน Honeypot แต่ละแบบ + CSV | `scope.extend_analytics()`, `/api/reports.csv` (UTF-8 BOM) | ตรง |
| 1.3.2.3 Master Admin จัดการบัญชี/สิทธิ์, Default Password ต้องเปลี่ยนครั้งแรก | `security.py` + `config.py` (`force_default_password_change` default true) | ตรง |
| 1.3.2.3 ตั้ง Threshold ผ่านหน้าเว็บ | `thresholds_path` + `/api/thresholds` (`docs/redirect-policy.md`) | ตรง (ต้องติดตั้ง helper) |
| 1.3.2.3 เพิ่ม/แก้/เปิด-ปิดกฎผ่านหน้าเว็บ | `defender/suricata/apply_rules.py` + `trap-apply-rules.path` | **ตรงบางส่วน** (ดูข้อ 2.4) |
| 1.3.2.3 ตรวจกฎใหม่ก่อนอนุมัติ (รายละเอียด/หลักฐาน/ผลทดสอบ) | `scope`+`app.py` `/api/candidates/save` และ `/api/candidates/approve`, ฟิลด์ `evidence`, `test_results.gates` | ตรง |
| 1.3.2.3 สำรองกฎก่อนแก้ + คืนค่า | `backups/rules`, `/api/rule-backups.json` | ตรง |
| 1.3.3 Rabbit Hole Web: robots → /backup/ → config.json → API | scenario `web-backup-api` | ตรง |
| 1.3.3 Rabbit Hole Shell: notes.txt/.bash_history → /opt/backup → /var/backups/db | scenario `linux-server` + Cowrie bundle | ตรง |
| 1.4.1.1 รายชื่อ ET Open 13 กฎ | มีครบทุกชื่อใน `et-open-selected.rules` | ตรง 13/13 |
| 1.4.1.2 Decision Engine ใช้ IP/รหัสกฎ/severity/ประเภทการเชื่อมต่อ + ประวัติ | `risk.py:39-91` | ตรง (แต่เอกสารไม่เขียนสูตร — ข้อ 2.2) |
| 1.4.2 HTTP พอร์ต 80 / HTTPS 443 ถอดรหัสให้ Suricata เห็น | template listen 80/443 + hop `127.0.0.1:18443` + `https-inspection.yaml` | ตรง |
| 1.4.3 SSH/Telnet DNAT ไป Cowrie | template `dnat ip to __COWRIE_IP__:__COWRIE_PORT__` | ตรง |
| 1.5 ภาพรวม: Log JSON รวมศูนย์ → Dashboard | `paths.decisions/eve_paths/honeypot_paths` | **ตรงบางส่วน** (แยกหลายไฟล์ JSONL ไม่ใช่ไฟล์เดียว — ข้อ 2.7) |
| 1.6 ตัวอย่างหน้าจอ 13 หน้า (รูป 1.16–1.28) | view: overview, alerts, logs, rules, reports, rabbit, account | ตรง |
| 1.6 รหัสผ่าน ≥12 ตัว มีพิมพ์เล็ก/ใหญ่/อักขระพิเศษ | `security.password_problem()` (12–128) | ตรง |
| 1.6 เปลี่ยนรหัสผ่านแล้วต้องเข้าสู่ระบบใหม่ | `_change_password()` ลบ session + expired cookie | ตรง |
| 1.7 ประโยชน์ที่คาดว่าจะได้รับ | — | **เอกสารยังไม่มีเนื้อหา** (เป็นหัวข้อเปล่า) |
| 1.8 อุปกรณ์ เครื่องมือ และภาษาในการพัฒนา | Ubuntu, Kali, VirtualBox, Docker, Suricata, Nginx, nftables, Cowrie, Python, Shell, HTML, CSS, JS | ตรงกับ stack จริง |
| 1.9 แผนการดำเนินงาน | ตารางว่างทุกช่อง | **เอกสารยังไม่มีเนื้อหา** |

### 1.2 ทฤษฎีและงานวิจัย (บทที่ 2)

| หัวข้อเอกสาร § | ส่วนของระบบ | ผล |
|---|---|---|
| 2.1.1 IDS: แนวคิด IDS/IDPS และข้อจำกัดของการแจ้งเตือน | ใช้ Suricata โหมด IDS | ตรง |
| 2.1.2 Suricata Runmode workers + AF_PACKET 2 interface (outer + loopback) เธรดละ interface | `https-inspection.conf` ใช้ `--af-packet --runmode=workers`, `https-inspection.yaml` ตั้ง `threads: 1` ทั้ง lo และ trap-out | ตรง |
| 2.1.2.2 การติดตั้งผ่าน PPA + `suricata --build-info` + `ip addr` | `docs/production-defender.md` ใช้ apt + ตรวจ `suricata --build-info` | ตรง |
| 2.1.2.3 กฎ alert + SID + ET Open | 13 กฎใน `et-open-selected.rules` | ตรง |
| 2.1.3 Honeypot 3 ระดับ + Web Honeypot + Cowrie โหมด shell | Cowrie `read_only: true` + `honeyfs`/`fs.pickle` จาก Rabbit Hole | ตรง |
| 2.1.4 Decision Engine | `adaptive_defender/` | ตรง |
| 2.1.5 Threshold | `thresholds.json` + reload ทุก cycle | ตรง |
| 2.1.6 Nginx Reverse Proxy + `proxy_pass` | template `map` → `proxy_pass $adaptive_backend` | ตรง |
| 2.1.7 nftables NAT ที่ hook prerouting | chain `prerouting` type nat priority dstnat | ตรง |
| 2.1.8 Docker/Compose + volume log | `honeypot/docker/compose.yaml` + `deploy/logrotate/trap` | ตรง |
| 2.2 HoneyDOC / HoneyProxy ใช้ SDN, TRAP ใช้ Nginx+nftables | ไม่มี SDN ในโค้ด | ตรงตามที่เอกสารอ้าง |
| 2.3 ตารางเปรียบเทียบ: ข้อมูลที่ใช้เลือก = Suricata + คะแนนเทียบเกณฑ์ | `risk.py` | ตรง |
| 2.3 ตารางเปรียบเทียบ: รวบรวมเหตุการณ์/ผลตัดสินใจ/คำขอเว็บ/user-pass/คำสั่ง | `decisions.jsonl`, `rabbit-hole-web.jsonl`, `cowrie.json` | ตรง |

## 2. ไม่ตรงหรือต้องแก้ในเอกสาร (เรียงตามความสำคัญ)

### 2.1 §1.3.1 "3 ส่วนหลัก" แต่ §1.3.3 Rabbit Hole เป็นหัวข้อระดับเดียวกัน

V1.0.2 ยังคงเป็นเช่นเดียวกับฉบับ V0.8.4 เอกสารบอก 3 ส่วนหลัก แต่ Rabbit Hole ถูกเขียนเป็น
§1.3.3 แยกออกมา และในระบบ Rabbit Hole เป็นโมดูลจริง (`defender/rabbit_hole/`) ที่มีฉาก ตัวสร้าง
ไฟล์ลวง และหน้าจอของตัวเอง

**ข้อเสนอ:** ระบุว่า Rabbit Hole เป็นส่วนย่อยของระบบ Honeypot (ตาม §1.3.1.2) หรือเปลี่ยนเป็น
4 องค์ประกอบ แล้วปรับข้อความในบทคัดย่อและ §1.5 ให้ตรงกัน

### 2.2 §1.4.1.2 ไม่มีสูตรให้คะแนนและค่า Threshold ที่ระบบใช้จริง

เอกสารบอกเพียง "นำ IP รหัสกฎ ระดับความรุนแรง และประเภทการเชื่อมต่อ มาคำนวณคะแนนความเสี่ยงร่วมกับประวัติ"
แต่โค้ดกำหนดตัวเลขตายตัว (`defender/decision_engine/adaptive_defender/risk.py:48-66`):

| องค์ประกอบ | ค่า |
|---|---|
| severity 1 / 2 / 3 / อื่น ๆ | +35 / +25 / +12 / +8 |
| protocol scan / ssh / telnet / http,https,tls / อื่น ๆ | +25 / +10 / +10 / +5 / +3 |
| มีประวัติสแกน / SSH / Telnet ที่ยังไม่หมดอายุ | +20 / +10 / +10 |
| decay | −1.0 คะแนน/นาที |
| expiry ของสถานะ IP | 1800 วินาที |
| threshold | `monitor: 15`, `redirect: 40` (แก้ใน `lab.json`, `live.json`, `thresholds.json`) |

**ข้อเสนอ:** เพิ่มตารางนี้ใน §1.4.1.2 หรือ §2.1.4 และระบุว่าเกณฑ์ปรับได้จากหน้า Dashboard

### 2.3 §1.3.2.2 บันทึกพอร์ต/ไอพีปลายทางของ Web Honeypot ขึ้นกับ profile ที่ใช้

| profile | พอร์ตต้นทาง | ไอพี/พอร์ตปลายทาง |
|---|---|---|
| `rabbithole` (`rabbit_hole/web.py:197-198`) | มี (`source_port`, ใช้ `X-Real-Port` เมื่อผ่าน Nginx) | มีทั้งคู่ |
| `snare` (`dashboard/scope.py:36-70`) | มี (`peer.port`) | มี `dest_port` แต่ **ไม่มี `dest_ip`** |

**ข้อเสนอ:** เขียนเงื่อนไขว่า "เมื่อใช้ Rabbit Hole web decoy จะบันทึกครบทุกฟิลด์" และถ้าจะใช้ SNARE
ต้องเพิ่มการส่งไอพีปลายทางหรือแก้ข้อความในเล่มให้ตรง

### 2.4 §1.3.2.3 การเพิ่ม/แก้ไขกฎผ่านหน้าเว็บยังไม่ทำงานจนติดตั้ง helper

การแก้กฎจริงถูกปิดด้วย `rules.allow_deploy: false` ฝั่ง Dashboard ตอบ
`live_rule_edit_requires_deployment_helper` จนกว่าจะรัน
`deploy/install-dashboard-helpers.sh` บนเครื่องจริง (ตั้ง `trap-apply-rules.path`)

**ข้อเสนอ:** ระบุในเล่มว่าการจัดการกฎในโหมดเดโม่เป็นการบันทึกลงไฟล์สำเนา และการเปลี่ยนกฎจริง
ต้องติดตั้ง helper ที่ตรวจ `suricata -T` ก่อน

### 2.5 §1.4.1.2 / §1.5 ไม่กล่าวถึง action `monitor` และนโยบาย scan-only

โค้ดมี 3 ผลลัพธ์ (`allow`, `monitor`, `redirect_web|ssh|telnet`) และ SID 2017616 (Masscan)
ถูกบังคับเป็น `monitor` ทุกกรณี (`scan_only_signatures`) ขณะที่เอกสารภาพรวมเขียนว่า
"IP ที่มีความเสี่ยงจะถูกส่งไป Honeypot" ซึ่งอ่านแล้วเหมือนทุก alert ที่ถึงเกณฑ์จะถูก redirect

**ข้อเสนอ:** เพิ่มประโยคอธิบายว่าระบบมีระดับเฝ้าระวังก่อนส่งต่อ และสแกนเครือข่าย (Masscan)
เป็นแจ้งเตือนอย่างเดียวโดยเจตนา

### 2.6 §1.3.2.2 / §1.4.3 Telnet ต้องอ้างเฉพาะ Cowrie

repo ยังมี `defender/telnet/server.py` ซึ่งเป็นบริการทดสอบ login ไม่มี Shell
ถ้าเขียนในเล่มว่าเก็บ "คำสั่งที่ถูกป้อน" ต้องระบุว่าได้จาก Cowrie Telnet (`:2223`) เท่านั้น

### 2.7 §1.5 "จัดเก็บรวมกันในไฟล์ Log (JSON)" ไม่ตรงรายละเอียด

ของจริงแยกไฟล์ JSONL ตามแหล่ง: `/var/log/suricata/eve.json`, `decisions.jsonl`,
`/var/log/trap/honeypot/rabbit-hole-web.jsonl`, `cowrie.json` (`paths.*` ใน `config/trap.example.json`)

**ข้อเสนอ:** เปลี่ยนเป็น "จัดเก็บเป็นไฟล์ JSONL แยกตามแหล่ง แล้ว Dashboard รวมอ่าน"

### 2.8 §1.9 ตารางแผนการดำเนินงานยังว่าง

ตารางที่ 1.1 ไม่มีการติ๊กเดือนและไม่มีช่วงเวลาเริ่ม–สิ้นสุด (ข้อความ "ระหว่างเดือน ถึง" ยังว่าง)

### 2.9 หน้าลงนาม/กิตติกรรมประกาศยังเป็นแบบฟอร์ม

ชื่อประธาน/กรรมการ/ผู้ประสานงานว่าง และกิตติกรรมประกาศยังมีวงเล็บ "(ขอบคุณผู้เชี่ยวชาญ...)" อยู่

### 2.10 §1.7 และ §1.8 ยังเป็นหัวข้อเปล่า

"ประโยชน์ต่อผู้ใช้งาน/องค์กร" เป็น Heading 4 6 หัวข้อ ไม่มีคำอธิบาย และ §1.8 อุปกรณ์
เป็นรายการบรรทัดเดียว ควรเขียนเป็นตารางหรือประโยคให้อ่านเป็นเนื้อหา

## 3. ระบบมีเกินเอกสาร (ถ้าไม่เขียนถึง ต้องกันเป็น "งานเพิ่มเติม")

| ส่วน | ไฟล์/ที่มา | สถานะ |
|---|---|---|
| Nginx request prefilter (path/User-Agent) | `defender/nginx/README.md` §prefilter, branch `feat/nginx-prefilter` | ใช้งานได้, มี test |
| HTTPS inspection hop ผ่าน `127.0.0.1:18443` + `X-Trap-Client-IP` | `defender/suricata/https-inspection.yaml`, template | ใช้งานได้ |
| Isolation 3 เครื่อง (`inet trap_isolation`) | `deploy/isolation/` | ผ่านรอบ 9 (66 คู่ + post-reboot) |
| Deploy หน้าเว็บ: clone + ส่งสำเนาไป agent `/v1/versions` | `defender/deploy_agent/`, `defender/dashboard/web_deploy.py` | ผ่าน unit test, **NOT_TESTABLE ใน lab** |
| SNARE + TANNER | `honeypot/snare-tanner/` | ไม่ได้ติดตั้งใน lab รอบ 9 |
| Jev AI วิเคราะห์ Session | `defender/rabbit_hole/jev.py`, `docs/rabbit-hole.md` §Jev | ผ่าน unit test, ต้องมี API key |
| Honeypot watchdog + log sync | `honeypot/docker/watchdog.py`, `deploy/trap-sync.sh` | ใช้งานใน lab |
| Threshold/rule helper | `deploy/install-dashboard-helpers.sh`, `defender/suricata/apply_rules.py` | ใช้งานได้ |
| Demo mode + ข้อมูลจำลอง | `generate_demo_data.py`, `config/trap.demo.json` | ใช้ในเดโม่เท่านั้น |

## 4. จุดที่ตรวจแล้วตรงกับโค้ด (ใช้เป็นหลักฐานในเล่มได้)

- 13 กฎ ET Open ตรงชื่อและ SID กับ §1.4.1.1 (`defender/suricata/rules/et-open-selected.rules`)
- TOTP 30 วินาที, challenge 5 นาที, จำกัด 5 ครั้ง, ใช้รหัสซ้ำไม่ได้ (`security.py:33,124,144`)
- รหัสผ่าน 12–128 ตัว ต้องมีพิมพ์เล็ก พิมพ์ใหญ่ และอักขระพิเศษ (`security.py:46-56`)
- Threshold 15/40 และ decay 1 คะแนน/นาที (`risk.py`, `config/lab.json`)
- nftables ใช้ table `inet adaptive_defender`, set `flags timeout 30m`, chain `prerouting` priority `dstnat`
- Nginx listen `__OUTER_IP__:80` / `:443 ssl` และ 503 แบบ managed เมื่อ backend ล่ม
- Suricata `--af-packet --runmode=workers` + `threads: 1` ต่อ interface ตาม §2.1.2
- Dashboard บังคับ CSRF ทุก POST ยกเว้น `/api/login` และจำกัดสิทธิ์ master_admin ตาม §1.3.2.3

## 5. ผลต่างจาก audit ฉบับ V0.8.4

| ข้อใน `trap-doc-audit.md` (V0.8.4) | สถานะใน V1.0.2 |
|---|---|
| กฎ Default ไม่ตรง (เขียนเอง 6 กฎ) | **แก้แล้ว** — ระบุ ET Open และตรงกับ 13 กฎในระบบ |
| SNARE/TANNER ไม่มีตัวแปลง log และไม่ส่งพอร์ตต้นทาง | **แก้แล้วบางส่วน** — `tanner_event()` มี `src_port`/`dest_port` แต่ยังไม่มี `dest_ip` |
| §1.3.2.2 ประโยค "ตั้งค่าฮันนีพอตเพื่อเพิ่มความเนียน" เขียนไม่จบ | **แก้แล้ว** — ข้อความใน V1.0.2 ครบถ้วน |
| nftables redirect ยังไม่ทดสอบ packet จริง | **ผ่านใน lab** — D4 มี SSH/Telnet DNAT ที่เข้าถึง Cowrie จริง และ D2 มี counter ยืนยันการตัดสินใจ แต่ยังไม่ทดสอบ topology อื่น |
| Telnet ไม่ควรอ้าง `defender/telnet` | **ยังต้องระวัง** — โค้ดยังมีอยู่ |
| §1.3.1 "3 ส่วนหลัก" กับ Rabbit Hole | **ยังไม่แก้** |
| Decision Engine มี allow/monitor/redirect แต่เอกสารบอกแค่เปลี่ยนเส้นทาง | **ยังไม่แก้** |

## 6. ข้อจำกัดของการตรวจครั้งนี้

- เป็น static review + unit test บน Windows ไม่ได้แตะ `systemctl`, `nginx -t`, `nft --check`, Suricata จริง
- ไม่ได้รัน lab 3 VM ใหม่ ตัวเลข lab ทั้งหมดอ้างรายงานรอบ 9
- ไม่ได้ตรวจความถูกต้องเชิงวิชาการของ §2.1 (ทฤษฎี) และ §2.2 (งานวิจัย) ตรวจเฉพาะว่าโค้ดสอดคล้องกับข้อความ
- ไม่ได้เทียบรูปที่ 1.1–2.12 กับหน้าจอ/ผลทดสอบจริงใน repository

## 7. คำสั่งตรวจซ้ำ

```bash
python3 -m unittest discover -s tests -v
python3 -m defender.validation.production --config /etc/trap/trap.json --pretty
python3 -m defender.validation.readiness --pretty
rg -n 'sid:' defender/suricata/rules/et-open-selected.rules   # ต้องได้ 13 กฎ
```
