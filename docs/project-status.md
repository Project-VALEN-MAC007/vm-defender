# สถานะโครงการ MIMIC Defender

ปรับปรุงล่าสุด: 16 กันยายน 2026

เอกสารนี้เป็นแหล่งข้อมูลหลักสำหรับสถานะงาน ข้อความว่า `ผ่าน` ใช้เฉพาะงานที่
มีการทดสอบและหลักฐานรองรับเท่านั้น

## สรุป

| งาน | สถานะ | ผลที่ยืนยันได้ | สิ่งที่ยังขาด |
|---|---|---|---|
| Network และ isolation | ติดขัด | มี topology, checklist และ rollback plan | ต้องเพิ่ม outer/inner NIC และยืนยันชื่อจริง |
| Suricata | กำลังดำเนินการ | syntax และ HTTP replay แบบออฟไลน์ผ่าน | ต้องทดสอบ live traffic ครบทุก protocol |
| Detection rules | กำลังดำเนินการ | มีกฎ 8 รายการและ test matrix | TLS/SSH/Telnet/scan ยังต้อง replay บน topology จริง |
| Nginx redirect | กำลังดำเนินการ | map update/rollback มี unit test; outer IP แก้แล้ว | ต้องติดตั้ง Nginx, certificate และทดสอบ backend จริง |
| nftables redirect | ติดขัด | สร้างคำสั่ง nft แบบ dry-run และตรวจ input ได้ | ต้องยืนยัน interface/endpoint และทดสอบ packet จริง |
| Decision Engine | ผ่านระดับซอฟต์แวร์ | checkpoint, retry, expiry และ state restart มี test | ต้องทดสอบร่วมกับ Nginx/nftables บน Ubuntu จริง |
| Dashboard | ผ่านระดับซอฟต์แวร์ | auth, RBAC, CSRF, rate limit, pagination และ audit มี test | ต้องติดตั้งเป็น systemd และทดสอบระยะยาว |
| Rule validation | ผ่านระดับซอฟต์แวร์ | validation 5 gates และ rollback มี test | live deploy ยังปิดไว้จนกว่าจะมี privileged helper |

## ผลทดสอบล่าสุด

- Python 3.12: ผ่าน 31 รายการทดสอบ
- Python 3.8: ผ่าน 31 รายการทดสอบ
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

1. เพิ่ม interface แยกสำหรับ outer และ inner network
2. แทนค่า `CHANGE_ME` ใน production config ด้วยชื่อ interface ที่ตรวจพบจริง
3. ติดตั้ง Nginx และ conntrack แล้วตรวจสถานะ service
4. สำรอง network และ firewall ด้วยสิทธิ์ root
5. ทดสอบ `suricata -T`, `nginx -t` และ `nft --check`
6. ยืนยัน endpoint ภายในก่อนเปิด redirect

Production preflight ปัจจุบันถูกออกแบบให้รายงาน `blocked` เมื่อยังมี
`CHANGE_ME` นี่เป็นกลไกป้องกัน ไม่ใช่ข้อผิดพลาดของโปรแกรม

## สิ่งที่ยังไม่ควรทำ

- อย่า bind Dashboard ออกสู่ network โดยตรง
- อย่าเปลี่ยน `lab.json` เป็น live mode
- อย่าเปิด `rules.allow_deploy` เพียงเพื่อให้ปุ่ม Deploy ทำงาน
- อย่า apply nftables partial render ที่ยังมี token
- อย่าสรุปค่า accuracy/FPR จาก fixture สังเคราะห์ว่าเป็นผล production
