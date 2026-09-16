# MIMIC Defender

MIMIC Defender คือระบบตรวจจับ วิเคราะห์ และตอบสนองต่อทราฟฟิกที่น่าสงสัย
โดยรับเหตุการณ์จาก Suricata ประเมินความเสี่ยงด้วย Decision Engine แล้วสั่ง
Nginx หรือ nftables ให้เฝ้าระวัง เปลี่ยนเส้นทาง หรือบล็อกต้นทางตามนโยบาย

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
| nftables | เปลี่ยนเส้นทาง SSH/Telnet และบล็อกชั่วคราว | template พร้อม ยังรอชื่อ interface จริง |
| Dashboard | แสดงสถานะ เหตุการณ์ รายงาน และจัดการ rule | พร้อมใช้งานบน loopback |
| Validation Pipeline | ตรวจ rule 5 gates พร้อม backup/rollback | ชุดทดสอบผ่าน; live deploy ปิดไว้เป็นค่าเริ่มต้น |

สถานะโดยละเอียดอยู่ที่ `docs/project-status.md`

## หลักความปลอดภัย

- Dashboard ต้อง bind เฉพาะ `127.0.0.1`, `::1` หรือ `localhost`
- ไฟล์ `config/mimic.example.json` เป็นแม่แบบ ห้ามใช้ก่อนแทนค่า `CHANGE_ME`
- โหมด lab ต้องใช้ `dry_run: true`
- ห้ามกำหนด outer/inner IP ให้ interface ที่มี default route
- ก่อนเปลี่ยน network หรือ firewall ต้องสำรองค่าและตั้ง timed rollback
- Dashboard ห้ามทำงานด้วยสิทธิ์ root
- `rules.allow_deploy` ต้องเป็น `false` จนกว่าจะมี privileged helper ที่ผ่านการทบทวน

## เริ่มใช้งานในเครื่อง

ต้องใช้ Python 3.8 ขึ้นไป การทดสอบล่าสุดผ่านทั้ง Python 3.8 และ 3.12

```bash
python3 -m unittest discover -s tests -v
cp config/mimic.local.example.json config/mimic.json
python3 -m defender.dashboard.manage_users \
  --file config/users.json \
  --username admin \
  --name "Master Admin" \
  --role master_admin
python3 run_dashboard.py --config config/mimic.json
```

เปิด Dashboard ที่ `http://127.0.0.1:9090/`

## ตรวจสอบก่อนติดตั้งจริง

แก้ `/etc/mimic/mimic.json` ให้ตรงกับเครื่องปลายทางก่อน แล้วรันคำสั่งที่อ่าน
สถานะอย่างเดียวต่อไปนี้:

```bash
python3 -m unittest discover -s tests -v
python3 -m defender.validation.production \
  --config /etc/mimic/mimic.json --pretty
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
defender/nftables/              template สำหรับ redirect และ block
defender/suricata/              กฎตรวจจับและแผนทดสอบ
defender/validation/            readiness และ rule validation pipeline
deploy/                         ไฟล์ประกอบการติดตั้ง เช่น logrotate
docs/                           คู่มือและสถานะโครงการ
evidence/                       หลักฐานการทดสอบ ห้ามถือเป็น config หลัก
tests/                          ชุดทดสอบอัตโนมัติ
```

## เอกสาร

เริ่มอ่านจาก `docs/README.md` ซึ่งอธิบายลำดับการอ่าน คำศัพท์ และเอกสารหลัก
ของแต่ละงาน
