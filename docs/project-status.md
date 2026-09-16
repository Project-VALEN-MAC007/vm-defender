# สถานะโครงการ MIMIC Defender

ปรับปรุงล่าสุด: 17 กันยายน 2026

เอกสารนี้เป็นแหล่งข้อมูลหลักสำหรับสถานะงาน ข้อความว่า `ผ่าน` ใช้เฉพาะงานที่
มีการทดสอบและหลักฐานรองรับเท่านั้น

## สรุป

| งาน | สถานะ | ผลที่ยืนยันได้ | สิ่งที่ยังขาด |
|---|---|---|---|
| Network และ isolation | กำลังดำเนินการ | ยืนยัน management `enp0s9`, outer `enp0s3` และ inner `ztpp6hfkv2` แล้ว | ต้องเปิด UFW บน Real Product และทดสอบว่าเข้า backend โดยอ้อมไม่ได้ |
| Suricata | กำลังดำเนินการ | syntax และ HTTP replay แบบออฟไลน์ผ่าน | ต้องทดสอบ live traffic ครบทุก protocol |
| Detection rules | กำลังดำเนินการ | มีกฎ 8 รายการและ test matrix | TLS/SSH/Telnet/scan ยังต้อง replay บน topology จริง |
| Nginx redirect | ผ่านระดับ integration | Real Web และ WordPress Honeypot ตอบ `200` ผ่าน `https://defender.lab`; map และ timeout ทดสอบแล้ว | ต้องทดสอบ redirect จาก alert จริงและทดสอบหลัง reboot |
| nftables redirect | ติดขัด | สร้างคำสั่ง nft แบบ dry-run และตรวจ input ได้ | ต้องยืนยัน interface/endpoint และทดสอบ packet จริง |
| Decision Engine | ผ่านระดับซอฟต์แวร์ | checkpoint, retry, expiry และ state restart มี test | ต้องทดสอบร่วมกับ Nginx/nftables บน Ubuntu จริง |
| Dashboard | ผ่านระดับซอฟต์แวร์ | auth, RBAC, CSRF, rate limit, pagination และ audit มี test | ต้องติดตั้งเป็น systemd และทดสอบระยะยาว |
| Rule validation | ผ่านระดับซอฟต์แวร์ | validation 5 gates และ rollback มี test | live deploy ยังปิดไว้จนกว่าจะมี privileged helper |

## ผลทดสอบล่าสุด

- Python 3.12: ผ่าน 33 รายการทดสอบ
- Python 3.8: ผ่าน 33 รายการทดสอบ
- Real Web `10.10.10.3:8080` ตอบ `200` ผ่าน Defender
- WordPress Honeypot `10.10.10.2:8081` ตอบ `200` ผ่าน proxy headers
- phpMyAdmin `10.10.10.2:8082` และ Cowrie `2222/2223` เข้าถึงจาก Defender ได้
- WordPress ทั้งสองฝั่งใช้ URL ภายนอก `https://defender.lab`
- API ที่ไม่มี session ตอบ `401`
- role `user` เข้า Rule Management API ไม่ได้
- logout และ rule actions ต้องมี CSRF token
- login ถูกจำกัดจำนวนครั้งเมื่อกรอกรหัสผิดซ้ำ
- adapter ที่ทำงานล้มเหลวไม่ทำให้ event ถูก checkpoint ทิ้ง
- web redirect มี expiry และโหลด state กลับหลัง restart
- หน้า Login ผ่านการตรวจ viewport desktop และ mobile โดยไม่มี horizontal overflow

คำสั่งตรวจซ้ำ:

```bash
python3 -m unittest discover -s tests -v
```

## ปัญหาที่ต้องแก้บนเครื่องปลายทาง

1. เปิด UFW บน Real Product โดยอนุญาต SSH และเว็บจาก Defender เท่านั้น
2. แทนค่า `CHANGE_ME` ใน production config ด้วยชื่อ interface ที่ยืนยันแล้ว
3. สำรอง network และ firewall ด้วยสิทธิ์ root
4. ทดสอบ `suricata -T` และ `nft --check`
5. ทดสอบ redirect จาก Suricata alert จริง
6. ทดสอบ service และเส้นทางทั้งหมดหลัง reboot

Production preflight ปัจจุบันถูกออกแบบให้รายงาน `blocked` เมื่อยังมี
`CHANGE_ME` นี่เป็นกลไกป้องกัน ไม่ใช่ข้อผิดพลาดของโปรแกรม

## สิ่งที่ยังไม่ควรทำ

- อย่า bind Dashboard ออกสู่ network โดยตรง
- อย่าเปลี่ยน `lab.json` เป็น live mode
- อย่าเปิด `rules.allow_deploy` เพียงเพื่อให้ปุ่ม Deploy ทำงาน
- อย่า apply nftables partial render ที่ยังมี token
- อย่าสรุปค่า accuracy/FPR จาก fixture สังเคราะห์ว่าเป็นผล production
