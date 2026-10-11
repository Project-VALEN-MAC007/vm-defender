# Company web app (real + decoy)

โค้ดและเทมเพลตชุดเดียวกันรันทั้งเว็บจริงและเว็บลวง หน้าเว็บสาธารณะเหมือนกันทุก byte
ต่างกันแค่ backend (`webapp/backends/`): `real` = ข้อมูลจริง, `decoy` = ข้อมูลปลอมแยกขาด
ไม่มีรหัสผ่านหรือความลับจริงในโค้ด และ backend ปลอมไม่มีบัญชีจริง

เลือก backend ด้วย env `BACKEND`:

```bash
BACKEND=real  python3 -m webapp.app --host 0.0.0.0 --port 8080   # Project-Web (เครื่องจริง)
BACKEND=decoy python3 -m webapp.app --host 0.0.0.0 --port 8080   # Honeypot (เว็บลวง)
```

## บทบาทในระบบ

- **Project-Web (10.10.10.3):** รัน BACKEND=real เป็นเว็บจริง Defender ส่ง low-risk มาที่นี่
- **Honeypot (10.10.10.2):** รัน BACKEND=decoy container `web-app` Rabbit Hole (พอร์ต 8084) อยู่ด้านหน้า
  เส้นทางลวง (`/backup/`, `/.env`, `/api/...`) Rabbit Hole ตอบเองและ log ด้วย node_id
  ส่วน request อื่นถูกส่งต่อ (`web.upstream`) ไปที่เว็บลวงนี้ แล้ว log เป็น request ธรรมดา

เว็บลวงใน Honeypot ต้องไม่ออกอินเทอร์เน็ตและไม่ต่อกับบริการจริง (compose ตัด network ออก)

## เปลี่ยนเป็นเว็บขององค์กรจริง

แทนที่ `webapp/backends/real.py` ด้วยแหล่งข้อมูลจริงขององค์กร (หรือเปลี่ยนทั้ง image เป็นเว็บจริง
ขององค์กร) ส่วน `decoy.py` ทำสำเนา schema เดียวกันแต่ใส่ข้อมูลปลอม แล้วชี้ `web.upstream` ของ
Rabbit Hole ไปที่เว็บลวงนั้น
