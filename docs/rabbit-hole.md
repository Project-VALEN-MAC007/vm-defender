# Rabbit Hole: ระบบเส้นทางหลอกลวงต่อเนื่อง

อ้างอิงหัวข้อ 1.3.3 ในเอกสาร TRAP ระบบนี้จัดหน้าเว็บ ไฟล์ และข้อมูลจำลองให้เชื่อมโยงกันเป็นเส้นทาง
แต่ละจุดมีเบาะแสที่ชี้ไปยังจุดถัดไป เพื่อหลอกล่อให้ผู้โจมตีสำรวจลึกลงไปและอยู่ในระบบนานขึ้น

## แนวคิดสำหรับผู้ใช้งานจริง

ไฟล์ลวงไม่ได้เขียนตายตัว ระบบใช้ **แม่แบบฉาก (scenario)** + **ข้อมูลองค์กร** + **ค่าสุ่มต่อ Session**

1. ผู้ดูแลเลือกฉากในหน้า Dashboard → Rabbit Hole → ตั้งค่าและฉาก
2. กรอกชื่อองค์กร โดเมน ชื่อเซิร์ฟเวอร์ ชื่อบัญชีผู้ดูแล ฯลฯ
3. ระบบสร้างไฟล์ลวงให้อัตโนมัติ เช่น `.env` ที่มีชื่อบริษัทและโดเมนจริงขององค์กรนั้น
4. ค่าลับ (รหัสผ่าน API Key Hash) สุ่มจาก secret ของแต่ละการติดตั้งและ Session
   กลับมาเปิดไฟล์เดิมจะเห็นค่าเดิม แต่คนละ Session ได้ค่าต่างกัน และแต่ละองค์กรได้ไฟล์ไม่ซ้ำกัน
5. Path ที่มีวันที่หรือรหัส เช่น `/internal/admin-xxxxxx/` คงที่ตลอดอายุการติดตั้ง

ข้อมูลทุกค่าเป็นข้อมูลปลอมที่สร้างขึ้น ไม่มีข้อมูลจริงขององค์กร

## ฉากที่มีให้

| ฉาก | ช่องทาง | เส้นทางตัวอย่าง |
|---|---|---|
| `web-backup-api` | Web | `/robots.txt` → `/backup/` → `config.json` (มี API Key) → `/api/v1/` → `/api/v1/users` |
| `web-env-admin` | Web | `/.env` หรือ `/.git/config` → หน้าแอดมินที่ซ่อน → `exports/` → `customers_*.csv` |
| `linux-server` | SSH/Telnet (Cowrie) | `notes.txt`, `.bash_history` → `/opt/backup/backup.conf` → `/var/backups/db/*.sql` |

ทุกฉากผ่านขอบเขตเริ่มต้น: ลึกสูงสุด 5 ชั้น และทางแยกไม่เกิน 2 ทางต่อจุด
เพิ่มฉากเองได้โดยวางไฟล์ JSON รูปแบบเดียวกับ `defender/rabbit_hole/scenarios/` ในโฟลเดอร์ที่ระบุใน `extra_scenario_dirs`

ตัวแทนค่าในแม่แบบ: `{{org.name}}`, `{{org.domain}}`, `{{node:<id>}}` (path ของจุดอื่น),
`{{date:-3}}`, `{{ip:db}}`, `{{secret:password:db}}`, `{{secret:token:api}}`,
`{{secret:hex:6:label}}`, `{{person:2:email}}`, `{{people_csv:25}}`

## ออกแบบฉากเอง (Dashboard → Rabbit Hole → ตั้งค่าและฉาก)

Master Admin สร้างฉากของตัวเองได้โดยไม่ต้องแก้ไฟล์

1. **คลังฉาก** แบ่งเป็น "ฉากของฉัน" และ "เทมเพลต" เทมเพลตแก้ไม่ได้ กด **ใช้เป็นต้นแบบ** เพื่อคัดลอก
   หรือกด **+ สร้างฉาก Web / SSH/Telnet** เพื่อเริ่มจากจุดเดียว
2. **แผนผังเส้นทาง** แสดงจุดแยกตามชั้น คลิกจุดเพื่อแก้ในแผง **แก้ไขจุด**
   - Path, ชนิด (ไฟล์, โฟลเดอร์, API, หน้า Login, API รายชื่อคน), ชนิดเนื้อหา
   - **เป็นจุดเริ่ม**: ผู้โจมตีเจอได้เองโดยไม่ต้องมีเบาะแส
   - **ชี้ไปที่**: จุดถัดไปที่เบาะแสพาไป (ไม่เกินทางแยกสูงสุด) ชั้นคำนวณจากตรงนี้อัตโนมัติ
   - ปุ่ม **แทรกเบาะแสไปยัง** ใส่ path ของจุดถัดไปลงในเนื้อหา และปุ่ม **แทรกค่าอัตโนมัติ** ใส่ชื่อองค์กร รหัสผ่านสุ่ม ฯลฯ
3. แถบสถานะตรวจทุกครั้งที่แก้: ข้อผิดพลาดสีแดงต้องแก้ก่อนบันทึก (ไม่มีจุดเริ่ม, จุดที่ไปไม่ถึง, ลึกหรือแยกเกิน,
   path ไม่ถูกต้อง, ค่าอัตโนมัติที่ไม่รู้จัก) คำเตือนสีส้มบันทึกได้ (รหัสผ่านที่พิมพ์เอง, เบาะแสที่ยังไม่ได้ใส่ในเนื้อหา, path ซ้ำกับฉากอื่น)
4. กด **ดูสิ่งที่ผู้โจมตีเห็น** เพื่อดูเนื้อหาที่แทนค่าแล้ว แล้วกด **บันทึกฉาก**
5. ติ๊ก **ใช้ฉากนี้** แล้วกด **บันทึกการตั้งค่า** Web decoy ใช้ฉากใหม่กับคำขอถัดไปโดยไม่ต้องรีสตาร์ต
   ส่วน SSH/Telnet ต้องดาวน์โหลดไฟล์สำหรับ Cowrie ไปติดตั้งใหม่

ฉากที่สร้างเองเก็บที่ `config/rabbit-hole-scenarios/` (ตั้งค่าได้ด้วย `custom_scenario_dir`)
ทุกครั้งที่บันทึกหรือลบ ระบบเก็บฉบับเดิมไว้ใน `.backups/` และบันทึกใน Audit Log
ลบฉากที่กำลังเปิดใช้ไม่ได้ ขอบเขต: ไม่เกิน 40 จุดต่อฉาก เนื้อหาไม่เกิน 32 KB ต่อจุด

## ติดตั้ง

### Web decoy

```bash
cp config/rabbit-hole.example.json config/rabbit-hole.json   # แก้ข้อมูลองค์กร
python3 -m defender.rabbit_hole check --config config/rabbit-hole.json
python3 -m defender.rabbit_hole preview --config config/rabbit-hole.json
python3 run_rabbit_hole.py --config config/rabbit-hole.json     # ฟังที่ 127.0.0.1:8084
```

บนเครื่อง Honeypot ให้ตั้ง `web.host` เป็น IP ฝั่ง inner และ `web.trusted_proxies` เป็น IP ของ Defender แบบ /32
ใน Nginx แทน `__RABBIT_HOLE_IP__`/`__RABBIT_HOLE_PORT__` และตั้ง `web_profile: "rabbithole"`
ใน config ของ Decision Engine เมื่อต้องการให้ทราฟฟิกเว็บที่ถึงเกณฑ์ไปที่เส้นทางลวง
ไฟล์ `config/rabbit-hole.secret` สร้างอัตโนมัติครั้งแรก ต้องเก็บเป็นความลับและไม่ commit

### SSH/Telnet (Cowrie)

```bash
python3 -m defender.rabbit_hole cowrie-bundle --config config/rabbit-hole.json --out bundle.zip
```

หรือกดดาวน์โหลดจากหน้า Dashboard ไฟล์ zip มี `honeyfs/` (เนื้อหาไฟล์) และ `fsctl-commands.txt`
(สร้างรายการไฟล์ใน `fs.pickle`) ทำตาม `README.txt` ในไฟล์ zip ตรวจคำสั่ง `fsctl` กับ Cowrie รุ่นที่ติดตั้งจริงก่อน
และ export ใหม่ทุกครั้งที่แก้ข้อมูลองค์กรหรือฉาก SSH

### Dashboard

เพิ่มใน `config/trap.json`:

```json
"paths": {
  "rabbit_hole_config": "config/rabbit-hole.json",
  "rabbit_hole_logs": ["evidence/rabbit-hole/web.jsonl"],
  "honeypot_paths": ["/path/to/cowrie.json"]
}
```

ฝั่ง SSH/Telnet อ่านจาก Cowrie JSON ใน `honeypot_paths` แล้วแปลงคำสั่งที่แตะ path ลวงเป็นเหตุการณ์ Rabbit Hole

## ข้อมูลที่บันทึก (Web)

วันเวลา, Session ID และวิธีเชื่อม Session (Cookie / IP+User-Agent / API Key), IP และพอร์ตต้นทาง,
IP และพอร์ตปลายทาง, HTTP Method, Path, Query, Headers (ปกปิด Cookie/Authorization), User-Agent,
Payload (สูงสุด 4 KB), HTTP Status, ฉาก, รหัสทรัพยากรลวง, ชั้น, เบาะแสที่พามา, การถึงขอบเขต

## วิธีวัดผล

- **ช่วงการติดตาม** เริ่มเมื่อเปิดทรัพยากรลวงสำเร็จครั้งแรก
- **เวลาโต้ตอบ** = เวลากิจกรรมสุดท้าย − เวลากิจกรรมแรก ไม่รวมเวลารอ Idle Timeout
- เงียบเกิน Idle Timeout แล้วกลับมา นับเป็นช่วงการติดตามใหม่
- มีกิจกรรมเดียว รายงานว่า "เข้าถึงครั้งเดียว" ไม่มีเวลาโต้ตอบ
- SSH/Telnet แสดงเวลาเชื่อมต่อแยกจากเวลาโต้ตอบ
- การพิมพ์ `cat ไฟล์` บน Shell เป็นหลักฐานการพยายามเข้าถึง ไม่ใช่การยืนยันว่าอ่านสำเร็จ
- การเห็นชื่อไฟล์จาก `ls` ไม่นับเป็นการเดินตามเบาะแส
- IP+User-Agent เป็นการเชื่อมแบบหลวม หน้า Dashboard แสดงวิธีเชื่อมของทุก Session

## ข้อจำกัด

- บอตที่ยิง URL จากรายการตายตัวมักไม่เดินตามเบาะแส ซึ่งเป็นผลที่ต้องรายงานตามจริง
- การเปรียบเทียบกับ Honeypot แบบคงที่ใช้ได้เมื่อจุดเริ่มต้น ระยะเวลาทดลอง และกลุ่มผู้ทดสอบเหมือนกัน
- ข้อมูลในโหมดเดโม่เป็นข้อมูลสังเคราะห์ ห้ามนำตัวเลขไปสรุปผลการทดลอง
- ฝั่ง Shell ยังไม่สร้างไฟล์ใหม่ตามคำสั่งระหว่าง Session (ขอบเขตเริ่มต้นใช้เส้นทางที่เตรียมไว้)

## โหมด Jev คุมเส้นทาง (HTTP, HTTPS, SSH, Telnet)

ตั้งแต่ 19 พ.ย. 2569 ฝั่งเว็บเลือกได้ 2 แบบที่ Dashboard → Rabbit Hole → ตั้งค่าและฉาก → **วิธีวางเบาะแสฝั่งเว็บ**

| โหมด | ทำงานอย่างไร | ใช้เมื่อ |
|---|---|---|
| `jev` — Jev คุมเส้นทาง | ไม่มีฉากตายตัว มีแต่ **คลังข้อมูลลวง** (`defender/rabbit_hole/pool/web.json` + ชิ้นที่ Admin เพิ่มใน `config/rabbit-hole-pool/`) แต่ละชิ้นมีช่องเบาะแส `{{clue:<ชื่อ>}}` ที่ถูกเติมต่างกันในแต่ละผู้โจมตี | ใช้งานจริง |
| `fixed` — เส้นทางคงที่ | ใช้ฉาก Web ที่เลือกไว้แบบเดิม | กลุ่มเปรียบเทียบในการทดลอง / ย้อนกลับ |

config เดิมที่ไม่มีคีย์ `strategy` ถือเป็น `fixed` เพื่อไม่ให้พฤติกรรมเครื่องที่ติดตั้งแล้วเปลี่ยนเอง
`config/rabbit-hole.example.json` ตั้งเป็น `jev`

| โปรโตคอล | ใครเติมเบาะแส | คลังข้อมูล |
|---|---|---|
| HTTP / HTTPS | web decoy (`defender/rabbit_hole/web.py`) — HTTPS ถูก Nginx ถอดรหัสแล้วส่งเข้าตัวเดียวกัน | `pool/web.json` + ของ Admin |
| SSH / Telnet | plugin ของ Cowrie `honeypot/cowrie/traprabbit.py` | `pool/shell.json` (12 ชิ้น) |

ในโหมด `fixed` ฝั่ง SSH/Telnet ใช้ฉาก `linux-server` ตามเดิม

### ใครตัดสินใจ และเมื่อไร

```text
Suricata + Decision Engine ──(redirect_web)──┐
Rabbit Hole web log (sync จาก Honeypot) ─────┤
                                             ▼
          Defender: Jev planner  ──ถาม Jev (choice)──▶  api.typesafe.ai
                │  เขียน /var/lib/trap/rabbit-hole-plan.json (แผนต่อ IP)
                ▼  trap-sync.sh plan (rsync ผ่าน SSH เดิม)
          Honeypot: web decoy อ่านแผนเมื่อไฟล์เปลี่ยน
```

- **Honeypot ไม่เรียก Jev เอง** (`honeypot.nft` ห้ามเครื่อง Honeypot เปิดการเชื่อมต่อออก) ผู้โจมตีจึงหน่วง decoy หรือเผาโควตา Jev ไม่ได้
- planner อ่านสัญญาณตั้งแต่ตอนถูก redirect (เช่น sqlmap, ขอไฟล์ `.env`) แผนแรกจึงพร้อมก่อนผู้โจมตีเปิดเบาะแสถัดไป และปรับต่อเมื่อ log จาก Honeypot sync มา (ทุกนาทีตาม `trap-sync.sh`)
- state ที่ส่งให้ Jev **ไม่มี IP** มีเฉพาะชื่อกฎที่โดน, การตัดสินใจ, path/สถานะที่เปิดใน decoy และหมวดที่เปิดไปแล้ว
- คำถามแต่ละข้อเป็นแบบ `choice` ที่ตัวเลือกคือชิ้นในคลังเท่านั้น Jev จึงพาไปได้แค่ข้อมูลลวงที่ผ่านการตรวจแล้ว สร้างเนื้อหาใหม่ไม่ได้
- ถามรวมในคำขอเดียวต่อรอบ (ช่องที่เปิดได้ไม่เกิน 12 ช่อง + เป้าหมายของผู้โจมตี)

### SSH/Telnet: plugin ของ Cowrie

Cowrie ปกติเสิร์ฟไฟล์ชุดเดียวให้ทุก Session plugin `traprabbit` (โหลดเป็น output plugin `[output_traprabbit]`)
ดักการอ่านไฟล์ลวง (`cat`, `less`, `head`, `tail` …) แล้วเติม `{{clue:…}}` ตามแผนของ IP นั้น หรือตัวเลือกสำรอง

- `trap-cowrie-sync` (cowrie-install) ติดตั้งไฟล์ลวงทุกชิ้นใน `fs.pickle`/`honeyfs` (เนื้อหาสำรองแบบคงที่) และเขียน
  `trap-shell-pool.json` ไว้ข้าง `fs.pickle` — เป็นแม่แบบที่แทนค่าทุกอย่างแล้วยกเว้นเบาะแส **ไม่มี secret ของระบบ**
- แผนของ Jev ถูก `trap-sync.sh` ส่งไปที่ `/var/lib/trap/cowrie-fs/rabbit-hole-plan.json` ซึ่ง container Cowrie เห็นแบบอ่านอย่างเดียว
- plugin เขียน event `rabbit_hole.shell` (มี `clue_choices`, `clue_by`, `clue_confidence`) ลง
  `/var/log/cowrie/trap-rabbit-shell.jsonl` ใช้ Session ID เดียวกับ `cowrie.json` แล้ว Defender sync กลับมา
  (เพิ่ม path นี้ใน `paths.rabbit_hole_logs` ของ `trap.json` และ `--web-log` ของ planner)
- planner ถามช่องเบาะแสฝั่ง Shell เมื่อ IP ถูก `redirect_ssh` / `redirect_telnet` หรือมี event Shell
- ไม่แก้ผลของ `ls` (Cowrie แสดงไฟล์ลวงทุกชิ้นในโฟลเดอร์เหมือนเดิม) Jev คุมว่าเนื้อหาไฟล์ชี้ไปที่ไหน
- ปลอดภัยไว้ก่อน: ไม่มี bundle, plugin error หรือ Cowrie รุ่นที่ hook ไม่ได้ → Cowrie เสิร์ฟไฟล์ลวงแบบคงที่ตามปกติ
- ติดตั้ง: ดู `honeypot/docker/README.md` หัวข้อ Rabbit Hole Jev plugin

### ราวกั้นที่ Jev ข้ามไม่ได้

- ความลึกสูงสุด (`max_depth`) — ที่ชั้นสุดท้ายไม่มีเบาะแสใหม่ (บรรทัดที่มีเบาะแสถูกตัดออก)
- ทางแยกสูงสุดต่อชิ้น (`max_branches`) — ตรวจตอนโหลดคลัง
- ตัวเลือกของ Jev ต้องอยู่ในรายชื่อผู้สมัครของช่องนั้นตอนแสดงผล ไม่งั้นใช้ตัวเลือกสำรอง
- ความมั่นใจต่ำกว่า `ai.min_confidence` → ไม่ใช้คำตอบนั้น
- จำกัดการเรียก Jev ต่อ IP ต่อชั่วโมง (`ai.plan_max_calls_per_ip_hour`) และไม่ถามซ้ำถ้าสถานะเดิม
- เมื่อเบาะแสแสดงให้ผู้โจมตีแล้ว **ล็อกไว้ทั้ง Session** แผนใหม่มีผลกับเบาะแสที่ยังไม่แสดงเท่านั้น
- ไม่มีแผน / Jev ปิด / ไม่มีคีย์ / Jev ล่ม → ตัวเลือกสำรองแบบ deterministic ต่อ Session (ชิ้นที่น่าสนใจกว่าก่อน สลับลำดับด้วย HMAC)

### ติดตั้ง

บน Defender:

```bash
sudo cp deploy/trap-rabbit-planner.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now trap-rabbit-planner
journalctl -u trap-rabbit-planner -f        # สถานะ: disabled / missing_api_key / ok
```

- planner ใช้คีย์ Jev เดียวกับที่บันทึกในหน้า Dashboard (`ai.api_key_path`) และต้องเปิด "วิเคราะห์ด้วย Jev"
- การ push ทันทีใช้ `trap-sync.sh plan` ซึ่งต้องอ่าน SSH key ของ trapsync ได้ ถ้าบัญชี `trap-dashboard` อ่านไม่ได้ ให้ลบ `--push-command` ออก แผนจะไปถึง Honeypot ในรอบ sync ปกติ (ทุกนาที)
- บน Honeypot ตั้ง `web.plan_path` ใน `/var/lib/trap/rabbit-hole.json` เป็น `/var/lib/trap/rabbit-hole-plan.json`
- ทดสอบหนึ่งรอบ: `python3 -m defender.rabbit_hole plan --config ... --decisions ... --web-log ... --once`

### เพิ่มข้อมูลลวงเอง

Dashboard → การ์ด **คลังข้อมูลลวง** → **+ เพิ่มชิ้นข้อมูลลวง** (JSON) ตัวอย่าง:

```json
{"id": "smtp-bak", "kind": "file", "category": "credential", "lure": 2,
 "path": "/backup/smtp.ini.bak", "description": "SMTP settings backup with a password",
 "body_lines": ["password = {{secret:password:smtp}}", "panel = {{clue:panel}}"],
 "slots": {"panel": {"categories": ["admin"], "kinds": ["form"]}}}
```

- `category`: recon, notes, backup, config, credential, api, admin, data
- `description` คือสิ่งที่ Jev อ่านเพื่อเลือก ควรบอกว่าชิ้นนี้มีอะไร
- `slots.<ชื่อ>`: `categories` (บังคับ), `kinds`, `under: true` (โฟลเดอร์: เลือกเฉพาะชิ้นที่อยู่ใต้ path), `count`
- ระบบตรวจทั้งคลังก่อนบันทึก (path ซ้ำ, ช่องไม่มีผู้สมัคร, ทางแยกเกิน, ตัวแทนค่าผิด) ไม่ผ่านจะไม่บันทึก
- ชิ้นในตัว (builtin) แก้หรือลบไม่ได้ ชิ้นที่แก้/ลบเก็บสำเนาใน `.backups/`

### วัดผล

- event ของ decoy มี `clue_choices` (ช่อง, ชิ้นที่เลือก, `by: jev|fallback`, ความมั่นใจ) และเมื่อผู้โจมตีเดินตามเบาะแสจะมี `clue_by`, `clue_confidence`
- หน้าเส้นทางราย Session แสดง "Jev เลือกเบาะแสนี้ (78%)" หรือ "ตัวเลือกสำรอง"
- สรุปมี `followed_clue_by` นับเบาะแสที่ถูกเดินตามแยกเป็น Jev / สำรอง / ฉากคงที่ ใช้เทียบโหมด `jev` กับ `fixed` ได้ (ภายใต้จุดเริ่ม ระยะเวลา และกลุ่มผู้ทดสอบเดียวกัน)

## วิเคราะห์ผู้โจมตีด้วย AI (Jev)

ใช้ [Jev](https://docs.typesafe.ai/) ของ TypeSafe AI ประเมินแต่ละ Session ในหน้า Dashboard → Rabbit Hole
เมื่อเลือก Session จะมีกล่อง **วิเคราะห์ผู้โจมตีด้วย Jev** อยู่เหนือเส้นทางที่เดิน แสดง:

| คำถาม | ชนิด | ผลลัพธ์ |
|---|---|---|
| เจตนา | choice | สำรวจระบบ / หารหัสผ่าน/คีย์ / ขโมยข้อมูล / โจมตีช่องโหว่ / พยายามฝังตัว / ไม่ชัดเจน |
| บอทหรือคน | noul | ความน่าจะเป็นที่เป็นเครื่องมืออัตโนมัติ |
| ระดับฝีมือ | score | มือใหม่ / ปานกลาง / ชำนาญ |
| การตามเบาะแส | noul | ผู้โจมตีเชื่อไฟล์ลวงและตามลึกลงไปหรือไม่ |

Jev ไม่สร้างข้อความ ตอบได้แค่ตัวเลือกที่กำหนดไว้พร้อมความน่าจะเป็น ผลที่ความมั่นใจต่ำกว่า `min_confidence` จะขึ้นป้าย "ความมั่นใจต่ำ"
ผลจาก AI ใช้ประกอบการวิเคราะห์ ไม่ใช่ข้อสรุป

**ความปลอดภัย**
- เรียก Jev จากเครื่อง Dashboard (Defender) เท่านั้น Honeypot ไม่ต้องมีทางออกอินเทอร์เน็ต และผู้โจมตีทำให้ decoy ช้าไม่ได้
- ไม่ส่ง Source IP ไปที่ Jev ส่งเฉพาะ path/คำสั่ง สถานะ เวลา ความลึก และ User-Agent (สูงสุด 60 ขั้น, 12 KB)
- Prompt injection ใน path หรือคำสั่งทำได้แค่เบี่ยงตัวเลือก ไม่สามารถทำให้ AI ตอบข้อความกลับไปหาผู้โจมตี
- API Key อ่านจากตัวแปรสภาพแวดล้อมเท่านั้น ไม่เก็บใน config ไม่ลง Log และหน้า Dashboard แก้ค่า `ai` ไม่ได้
- ผลลัพธ์ถูก cache ต่อ Session จึงไม่เรียกซ้ำเมื่อเปิดดูหลายครั้ง

**เปิดใช้จากหน้า Dashboard (Master Admin)**
1. ขอ API Key จาก https://console.typesafe.ai/
2. Dashboard → Rabbit Hole → ตั้งค่าและฉาก → การ์ด **วิเคราะห์ผู้โจมตีด้วย AI (Jev)**
3. ใส่ API Key ติ๊ก **เปิดใช้** แล้วกด **บันทึก AI** จากนั้นกด **ทดสอบการเชื่อมต่อ**
4. เครื่อง Defender ต้องออก `https://api.typesafe.ai` ได้

คีย์ถูกเก็บในไฟล์ `config/jev.key` (สิทธิ์ 600, อยู่ใน `.gitignore`, ตั้งตำแหน่งได้ด้วย `ai.api_key_path`)
หน้าเว็บแสดงแค่ 4 ตัวท้าย ไม่ส่งคีย์กลับมา และ Audit Log บันทึกแค่ว่ามีการเปลี่ยนคีย์
ถ้าตั้งตัวแปรสภาพแวดล้อม `TYPESAFE_API_KEY` ไว้ ค่านั้นจะมีผลก่อนคีย์ในไฟล์
ค่าอื่น (URL, model, timeout) แก้ได้เฉพาะในไฟล์ `config/rabbit-hole.json`
