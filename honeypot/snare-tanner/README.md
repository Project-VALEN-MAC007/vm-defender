# SNARE + TANNER for MIMIC

ชุด Docker สำหรับเว็บลวงทั่วไป ใช้ SNARE เป็น sensor, TANNER วิเคราะห์คำขอ
และ Redis เก็บ session ไม่ใช้ WordPress ตัวต้นฉบับอยู่ที่
[SNARE](https://github.com/mushorg/snare) และ [TANNER](https://github.com/mushorg/tanner)
เวอร์ชัน source ตรึงตาม commit ใน `bootstrap.py`; source/license อยู่ใน `vendor/`
ซึ่งไม่ commit เข้า repository และดาวน์โหลดใหม่ได้

## เริ่มในเครื่องที่มี Docker Linux engine

```bash
cd honeypot/snare-tanner
python bootstrap.py
docker compose --env-file settings.env.example config --quiet
docker compose --env-file settings.env.example up -d --build
docker compose ps
curl -f http://127.0.0.1:8083/
docker compose logs --tail 100 snare tanner
```

หน้าเริ่มต้นเป็น demo สำหรับตรวจระบบ ยังไม่ใช่สำเนาเว็บจริง
SNARE bind loopback พอร์ต 8083; Redis/TANNER ไม่มี host port
network ของบริการเป็น internal; ไม่มี Docker socket หรือ external log shipping
ค่าเริ่มต้นเปิด SQLi, XSS และ CRLF; PHP, command execution, template injection,
RFI, LFI และ XXE ยังปิดไว้ ต้องเตรียม sandbox และทดสอบก่อนเพิ่ม

## Clone เว็บใน lab

เลือก URL ของเว็บต้นแบบที่เข้าถึงได้จาก container แล้วรัน เช่น:

```bash
docker compose --profile tools run --rm clone --target http://LAB_WEB_HOST:8080 --max-depth 2
```

แทน `LAB_WEB_HOST` ด้วย host จริง (localhost ใน container ไม่ใช่ host เครื่องคุณ)
SNARE จะสร้าง `data/snare/pages/<hostname>`; ตั้ง `SNARE_PAGE_DIR` ในไฟล์ env
ให้ตรงชื่อ directory แล้ว recreate SNARE ด้วย env file นั้น
อย่า clone ผ่าน URL ที่อาจ redirect กลับ SNARE เอง
clone ไม่ได้ย้าย session/login/API backend; ต้องตรวจ links, assets, forms,
headers, cookies และ error pages เทียบก่อน/หลังสลับ backend

## เชื่อม Defender

1. ตั้ง SNARE_BIND_IP เป็น IP ฝั่ง inner ของเครื่อง Honeypot ที่ตรวจแล้ว
   และยืนยันว่า Defender เข้า `http://HONEY_IP:8083/` ได้
2. ตั้ง MIMIC_TRUSTED_PROXY_CIDRS เป็น IP ของ proxy ที่ SNARE เห็นจริงแบบ /32
   หรือ /128 ตรวจ log ก่อนกำหนด; ไม่ใช้ทั้ง subnet โดยไม่จำเป็น
   Docker NAT อาจทำให้ peer address ต่างจาก IP Defender
3. ใช้ `../../defender/nginx/adaptive-honeypot.conf.template` หรือ `nginx-snare.conf.template`
   ซึ่งรองรับ profile `snare` และ X-Request-ID
   แทน tokens ทุกตัว รวม __SNARE_IP__/__SNARE_PORT__; ตรวจ nginx -t ก่อน reload
   รักษา public domain และ TLS เดิม
4. config ตัวอย่าง `../../defender/decision_engine/config/lab.json` และ `live.json`
   ตั้ง `"web_profile": "snare"` แล้ว หากมี config ที่ติดตั้งไว้เดิม ให้เพิ่มค่านี้
   ใน `/etc/adaptive-defender/live.json` ด้วย แล้วเริ่มใน dry_run ก่อน
   config นี้เป็นของ Decision Engine ไม่ใช่ dashboard mimic.json
5. ทดสอบ source IP, expiry, benign traffic และความต่อเนื่องของเว็บก่อนเปิดจริง

การแก้ repository ไม่ได้เปลี่ยน live Nginx/firewall หรือ config ที่ติดตั้งไว้เดิม
backend ต้องเข้าถึงจาก Defender เท่านั้น เพื่อไม่ให้ใครปลอม X-Real-IP ผ่าน proxy ที่ไว้ใจ
SNARE patch รับ X-Real-IP เฉพาะ peer ที่ตรง trusted CIDR
ยังไม่ได้ส่งต่อ client source port; ค่า peer port ใน TANNER เป็น connection ของ proxy

### นำไปลองบน VM Linux

บนเครื่อง Honeypot คัดลอก `settings.env.example` เป็น `settings.env`
ตั้ง `SNARE_BIND_IP` เป็น IP ฝั่ง inner ที่ยืนยันแล้ว และตั้ง trusted proxy ตามข้อ 2
จากนั้นรันจาก directory นี้:

```bash
python3 bootstrap.py
docker compose --env-file settings.env config --quiet
docker compose --env-file settings.env up -d --build
docker compose --env-file settings.env ps
docker compose --env-file settings.env logs --tail 100 snare tanner
```

บน Defender ตรวจ `curl -fsS http://HONEY_IP:8083/` ก่อนเปิด redirect
generated config ใช้ `10.10.10.2:8083` เป็นตัวอย่างเท่านั้น ต้องตรงกับ SNARE ที่เปิดจริง
TANNER ไม่มี public port; Nginx ต้องส่งไป SNARE ไม่ใช่ TANNER
สำรอง Nginx config, map และ Decision Engine config ตาม `docs/root-operations.md`
ก่อนติดตั้ง template ที่แทน token ครบ แล้วรัน `sudo nginx -t` ก่อน reload
ตรวจการตัดสินใจด้วย config ที่ติดตั้งไว้ในโหมด dry-run:

```bash
cd /opt/mimic
python3 -m defender.decision_engine.adaptive_defender.cli \
  --config /etc/adaptive-defender/live.json --dry-run --once
```

dry-run ไม่เขียน map หรือเปิด redirect จริง เมื่อ backend และผลการตัดสินใจผ่านแล้ว
จึงใช้ service เดิมที่อ่าน config นี้ใน apply mode ทดสอบ source ที่ถึงเกณฑ์ redirect
ว่า audit มี `profile: snare`, Nginx ส่งเข้า SNARE และมี event ใน `data/tanner/events.jsonl`
ตรวจ source ปกติว่ายังเข้า Real Web และ source ที่หมดอายุกลับเข้า Real Web

## Logs / หยุด / ย้อนคืน

TANNER เขียน `data/tanner/events.jsonl`, `tanner.log`, `tanner.err`
SNARE เขียน `data/snare/snare.log`, `snare.err`
events.jsonl เป็น upstream schema; Dashboard ของ MIMIC ยังไม่มี adapter สำหรับ log นี้
และ SNARE upstream เน้น form POST ไม่ใช่การเก็บ raw body ทุกชนิด
log อาจมี payload/cookies/ข้อมูล login สำหรับ lab ต้องจำกัดสิทธิ์การอ่าน

```bash
docker compose down
```

ไม่ใช้ -v เพื่อเก็บ Redis volume และ log ไว้ หากเปิด redirect แล้วต้องคืน
Nginx map/config และ web_profile ก่อนหยุด backend

## สถานะตรวจสอบ 3 ตุลาคม 2026

Compose syntax และการเลือก profile ในโค้ดตรวจได้ แต่การ build/start ยังไม่ยืนยัน
รอบนี้แก้เฉพาะโปรเจกต์ตามคำขอ ห้ามถือว่าชุดนี้ติดตั้งและรันสำเร็จแล้ว
ต้องตรวจ health, GET/POST, SQLi/XSS และ events.jsonl บน Docker engine ที่ทำงานได้
constraints เลือกให้รองรับ API ของ upstream บน Python 3.10 ยังรอ build ยืนยัน
