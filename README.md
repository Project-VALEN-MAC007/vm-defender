# TRAP Defender

TRAP Defender คือระบบตรวจจับ วิเคราะห์ และตอบสนองต่อทราฟฟิกที่น่าสงสัย
โดยรับเหตุการณ์จาก Suricata ประเมินความเสี่ยงด้วย Decision Engine แล้วสั่ง
Nginx หรือ nftables ให้เฝ้าระวังและเปลี่ยนเส้นทางตามนโยบาย

เอกสารใน repository นี้เป็นข้อมูลอ้างอิงหลักของโครงการ เนื้อหาในไฟล์ภายนอก
เช่น Word หรือเอกสารที่นำเข้ามาใน `evidence/` ไม่ใช่ข้อกำหนดที่ระบบนำไปใช้
โดยอัตโนมัติ

## ขอบเขตปัจจุบัน

รอบพัฒนาปัจจุบันเน้นเครื่อง Defender ก่อน ยังไม่รวมการติดตั้งเครื่อง Honeypot
แบบอัตโนมัติ ส่วน endpoint ของ WordPress, phpMyAdmin, Cowrie และ Telnet
จึงถือเป็นค่าภายนอกที่ต้องยืนยันก่อนเปิดใช้งานจริง

| ส่วนประกอบ | หน้าที่ | สถานะ |
|---|---|---|
| Suricata | ตรวจจับ HTTP, TLS, SSH, Telnet และการสแกน | กฎพร้อมทดสอบแบบออฟไลน์ |
| Decision Engine | รวมประวัติ คำนวณคะแนน และเลือก action | ชุดทดสอบผ่าน |
| Nginx | รับ HTTP/HTTPS และเลือก backend ตาม source IP | config พร้อมตรวจสอบ ยังไม่ activate บนเครื่องจริง |
| nftables | เปลี่ยนเส้นทาง SSH/Telnet | template พร้อม ยังรอชื่อ interface จริง |
| Dashboard | แสดงสถานะ เหตุการณ์ รายงาน และจัดการ rule | พร้อมใช้งานบน loopback |
| Deploy หน้าเว็บ | Clone เว็บด้วย SNARE และสลับหน้าเว็บ Honeypot ผ่าน Dashboard (agent บนเครื่อง Honeypot) | ชุดทดสอบผ่าน; ต้องติดตั้ง agent ตาม `honeypot/deploy-agent/README.md` |
| Rabbit Hole | เส้นทางลวงต่อเนื่อง Web + ไฟล์ลวงสำหรับ Cowrie และหน้า Dashboard | ชุดทดสอบผ่าน; ต้องติดตั้งบนเครื่อง Honeypot จริง |
| Validation Pipeline | ตรวจ rule 5 gates พร้อม backup/rollback | ชุดทดสอบผ่าน; live deploy ปิดไว้เป็นค่าเริ่มต้น |

สถานะโดยละเอียดอยู่ที่ `docs/project-status.md`
ผลตรวจระบบเทียบกับเอกสาร TRAP อยู่ที่ `docs/trap-doc-audit.md`
วิธีใช้ Rabbit Hole อยู่ที่ `docs/rabbit-hole.md`

กฎ Default ปัจจุบันใช้ ET Open 13 กฎใน
`defender/suricata/rules/et-open-selected.rules` โดยตัดกฎเขียนเองเดิมออกแล้ว
ดู [รายการกฎและขอบเขตการตรวจจับ](defender/suricata/et-open-selection.md)
ชุดนี้ไม่มีกฎตรวจ TLS รุ่นเก่าโดยตรง; TLS ยังคงเก็บเป็น telemetry ได้

## หลักความปลอดภัย

- Dashboard ต้อง bind เฉพาะ `127.0.0.1`, `::1` หรือ `localhost`
- ไฟล์ `config/trap.example.json` เป็นแม่แบบ ห้ามใช้ก่อนแทนค่า `CHANGE_ME`
- โหมด lab ต้องใช้ `dry_run: true`
- ห้ามกำหนด outer/inner IP ให้ interface ที่มี default route
- ก่อนเปลี่ยน network หรือ firewall ต้องสำรองค่าและตั้ง timed rollback
- Dashboard ห้ามทำงานด้วยสิทธิ์ root
- `rules.allow_deploy` ต้องเป็น `false` จนกว่าจะมี privileged helper ที่ผ่านการทบทวน

## เริ่มใช้งานในเครื่อง

ต้องใช้ Python 3.8 ขึ้นไป การทดสอบล่าสุดผ่านทั้ง Python 3.8 และ 3.12

```bash
python3 -m unittest discover -s tests -v
cp config/trap.local.example.json config/trap.json
python3 -m defender.dashboard.manage_users \
  --file config/users.json \
  --username admin \
  --name "Master Admin" \
  --role master_admin
python3 run_dashboard.py --config config/trap.json
```

เปิด Dashboard ที่ `http://127.0.0.1:9090/`

Dashboard ใช้ชื่อ TRAP: Threat Redirection and Analysis Platform
หน้า Login รองรับรหัส TOTP 6 หลักตาม [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)
ตั้งค่าได้ที่ จัดการบัญชี → บัญชีของฉัน → ตั้งค่า Authenticator โดยกรอกรหัสผ่านปัจจุบัน
แล้วเพิ่มคีย์ในแอป Authenticator แบบอิงเวลาและยืนยันรหัสภายใน 5 นาที
เมื่อเปิดใช้แล้วต้องกรอก TOTP ทุกครั้งที่เข้าสู่ระบบ รหัสที่ใช้สำเร็จแล้วใช้ซ้ำไม่ได้
หน้า Login ให้กรอก Username และ Password ก่อน เมื่อกำหนด `security.require_totp: true` ทุกบัญชีต้องไปหน้ากรอก TOTP แยก
และได้รับ session หลังยืนยัน TOTP สำเร็จเท่านั้น บัญชีที่ยังไม่ได้ตั้งค่าจะได้รับคีย์สำหรับเพิ่ม
ในแอป Authenticator ที่หน้านี้ และต้องยืนยันรหัสก่อนเข้า Dashboard
การเปลี่ยนหรือรีเซ็ตรหัสผ่านไม่ปิด TOTP
หากสูญเสีย Authenticator ผู้ดูแลเครื่องต้องกู้บัญชีแบบออฟไลน์: หยุด Dashboard
สำรอง `config/users.json` แล้วลบเฉพาะ `totp_secret` และ `totp_last_counter` ของบัญชีนั้น
ก่อนเปิด Dashboard และตั้งค่า Authenticator ใหม่ เก็บไฟล์ผู้ใช้และสำรองไว้เป็นความลับ

หน้า Overview และ Reports เลือกสถิติย้อนหลัง 24 ชั่วโมง, 7 วัน, 30 วัน หรือทั้งหมดที่เก็บไว้ได้
โดยแสดงแนวโน้ม Alert, Source IP ที่ไม่ซ้ำ, โปรโตคอล, ระดับความรุนแรง และผลการตัดสินใจ
หน้า Log Search ค้นหา Suricata, Decision Engine และ Honeypot จากข้อมูลที่เก็บไว้ทั้งหมดก่อนแบ่งหน้า
พร้อมกรองเวลา, Source IP, โปรโตคอล, แหล่งข้อมูล และความรุนแรง
สถิติเป็น snapshot ของ log ที่ Dashboard เก็บได้สูงสุดตาม `dashboard.maximum_rows`
จึงไม่ใช่ยอดสะสมถาวร รองรับ Cowrie JSONL และข้อมูล Session ที่แปลงรูปแบบแล้วจาก Web Honeypot
ผ่าน `paths.honeypot_paths` เพื่อคำนวณเวลาระหว่าง Action แรกและ Action สุดท้าย
รายละเอียดขอบเขตและข้อจำกัดอยู่ใน [ขอบเขต Dashboard 1.3.2.3](docs/dashboard-scope-1.3.2.3.md)
การ Flush ประวัติที่แสดงต้องยืนยัน TOTP เสมอ รวมถึงในโหมดเดโม่ และเก็บไฟล์ Log ต้นฉบับไว้

## ข้อมูลเดโม่ Dashboard

สร้างข้อมูลจำลอง 18,000 Alerts และ 12,000 Decisions ย้อนหลัง 45 วัน:

```bash
python generate_demo_data.py
python run_dashboard.py --config config/trap.demo.json
```

ข้อมูลอยู่ใน `evidence/demo/` แยกจากหลักฐานจริง
config เดโม่กำหนด `security.require_totp: false` เพื่อเข้าสู่ระบบด้วย Username/Password ได้ทันที
config ปกติยังบังคับ TOTP ตามค่าเริ่มต้น
สถานะบริการในโหมดนี้เป็นข้อมูลจำลอง การสร้างข้อมูลไม่แก้บัญชีผู้ใช้หรือ log เดิม
กลับไปอ่านข้อมูลเดิมโดยหยุด Dashboard แล้วรัน `python run_dashboard.py --config config/trap.json`

## ตรวจสอบก่อนติดตั้งจริง

แก้ `/etc/trap/trap.json` ให้ตรงกับเครื่องปลายทางก่อน แล้วรันคำสั่งที่อ่าน
สถานะอย่างเดียวต่อไปนี้:

```bash
python3 -m unittest discover -s tests -v
python3 -m defender.validation.production \
  --config /etc/trap/trap.json --pretty
python3 -m defender.validation.readiness --pretty
```

ห้ามดำเนินการต่อหากรายงานมีสถานะ `blocked`

## โครงสร้างสำคัญ

```text
config/                         แม่แบบการตั้งค่าระบบ
defender/dashboard/             Dashboard, authentication และ API
defender/decision_engine/       ตัวอ่าน EVE, risk engine และ adapters
defender/network/               แบบเครือข่ายและขั้นตอนเตรียม interface
defender/nginx/                 template และ generated config ของ Nginx
defender/rabbit_hole/           เส้นทางลวงต่อเนื่อง: ฉาก, web decoy, Cowrie bundle, การวัดผล
defender/nftables/              template สำหรับ redirect
defender/suricata/              กฎตรวจจับและแผนทดสอบ
defender/validation/            readiness และ rule validation pipeline
deploy/                         ไฟล์ประกอบการติดตั้ง เช่น logrotate
docs/                           คู่มือและสถานะโครงการ
evidence/                       หลักฐานการทดสอบ ห้ามถือเป็น config หลัก
tests/                          ชุดทดสอบอัตโนมัติ
```

## เอกสาร

ชุดทดลองเว็บลวง SNARE + TANNER อยู่ที่
[`honeypot/snare-tanner/README.md`](honeypot/snare-tanner/README.md)
config ตัวอย่างของ Decision Engine (`lab.json` และ `live.json`) ตั้ง
`web_profile: "snare"` แล้ว Nginx template รองรับ SNARE ที่พอร์ต 8083
ทราฟฟิกเว็บที่ถึงเกณฑ์ redirect จะส่งไป SNARE ซึ่งเชื่อม TANNER ภายใน;
ทราฟฟิกปกติยังเข้า Real Web ต้องยืนยัน build และ endpoint ก่อนใช้งานจริง

เริ่มอ่านจาก `docs/README.md` ซึ่งอธิบายลำดับการอ่าน คำศัพท์ และเอกสารหลัก
ของแต่ละงาน
