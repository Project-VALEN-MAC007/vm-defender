# CS MSU snapshot web app (real + decoy)

โค้ดและ snapshot ชุดเดียวกันรันทั้งเว็บจริงและเว็บลวง หน้าเว็บสาธารณะเหมือนกันทุก byte
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

## Offline public-site snapshot

`site/` เก็บ snapshot แบบคงที่จาก `https://cs.it.msu.ac.th/` เฉพาะหน้าและ asset ที่อนุมัติ
ให้บริการตาม query string ผ่าน `routes.json`; ไม่มีการดึงหน้า admin และหน้าไม่พึ่งอินเทอร์เน็ต
ทรัพยากรฝังจากโดเมนภายนอกถูกแทนด้วย placeholder ส่วน `/robots.txt` ยังคงใช้ค่าที่ตรงกับ
Rabbit Hole node ทุกตัวอักษร

ไลบรารีที่หน้าใช้ถูกเก็บไว้ใน `site/assets/vendor/` ตามเวอร์ชันที่หน้า CS MSU เรียกใช้:
Poppins/Noto Sans Thai, Font Awesome 6.4.0, Alpine.js, jQuery 3.6.0, Slick 1.8.1,
Leaflet 1.9.4 และ Tailwind CDN. Tailwind runtime ถูกแปลงเป็น `tailwind.css` แบบออฟไลน์
ที่รวม utility classes จากทุก route; Font Awesome CSS/font ถูก subset เฉพาะ glyph ที่หน้าใช้
เพื่อให้ asset ที่เบราว์เซอร์โหลดผ่าน Rabbit Hole มีขนาดต่ำกว่า 65,536 ไบต์ต่อ response.
ฟอนต์ทั้งหมดและ URL ใน CSS ชี้กลับเข้า snapshot ในเครื่อง.

เนื้อหา HTML ถูกแบ่งเป็น fragment ขนาดต่ำกว่า 65,536 ไบต์เพื่อให้ผ่านขีดจำกัด response ของ
Rabbit Hole โดยหน้าในเบราว์เซอร์ประกอบกลับจาก fragment ในเครื่อง รูปขนาดใหญ่ถูกทำเป็น WebP
offline derivative ขนาดไม่เกิน 58 KB. YouTube/TikTok ถูกแทนด้วยกรอบ placeholder ที่คง
อัตราส่วนภาพเดิม; CSS/JS และฟอนต์ที่เบราว์เซอร์ต้องใช้ทั้งหมดอยู่ใน `site/`.

หน้า login, portal, contact POST, logout และ health check ยังเป็น route ของแอปและใช้ backend
เดิม โดยหน้า dynamic ใช้ธีมท้องถิ่นจาก `site/offline.css` ไม่มี credential จริงใน snapshot

ไฟล์ Acme ก่อนปรับเก็บสำรองไว้ใน `acme-backup/` เพื่อสลับกลับเฉพาะ app/template ได้

## Reverting to Acme

คืนไฟล์หน้าเว็บจากสำรอง แล้ว rebuild/recreate เว็บจริงและเว็บลวงด้วยขั้นตอน deploy ใน TRAP:

```bash
cp webapp/acme-backup/app.py webapp/app.py
cp webapp/acme-backup/content.py webapp/content.py
```

ถ้าต้องกลับ VM ที่ deploy แล้ว Acme source และ image ถูกเก็บไว้ที่
`/opt/trap/backups/webapp-live-before-csmsu-20261014` และ `trap/web-app:acme-backup-20261014`.
Project-Web สามารถ restore source, retag image เป็น `trap/web-app:local` แล้ว recreate
`trap-web` ด้วยพอร์ต `10.10.10.3:8080:8080`, `BACKEND=real` และ restart policy
`unless-stopped`. Honeypot ให้ restore source, retag image แล้วใช้ compose project
`trap-honeypot` สร้างและเปิด service `web-app` อีกครั้ง.

## Replacing the public site

แทนที่ `webapp/backends/real.py` ด้วยแหล่งข้อมูลจริงขององค์กร (หรือเปลี่ยนทั้ง image เป็นเว็บจริง
ขององค์กร) ส่วน `decoy.py` ทำสำเนา schema เดียวกันแต่ใส่ข้อมูลปลอม แล้วชี้ `web.upstream` ของ
Rabbit Hole ไปที่เว็บลวงนั้น
