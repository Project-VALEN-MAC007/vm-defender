# การตั้งค่า Nginx สำหรับเปลี่ยนเส้นทางเว็บ

Nginx รับ HTTP/HTTPS ที่ outer IP เลือก backend จาก source IP ใน
`redirect_map.conf` และบันทึกผลให้ตรวจสอบย้อนหลังได้

## ไฟล์

| ไฟล์ | หน้าที่ |
|---|---|
| `adaptive-honeypot.conf.template` | template ที่ต้องแทน token ก่อนใช้ |
| `generated/adaptive-honeypot.http.conf` | generated config สำหรับ outer IP ตัวอย่าง |
| `generated/redirect_map.conf` | map ที่ Decision Engine จัดการ |
| `redirect_map.conf.example` | ตัวอย่างรูปแบบ map |

## ค่าที่ต้องยืนยัน

- outer IP ของ Defender
- certificate และ private key
- Real Web: `10.10.10.10:80`
- WordPress Honeypot: `10.10.10.2:8081`
- phpMyAdmin Honeypot: `10.10.10.2:8082`
- health path ของทุก backend
- path ของ redirect map

ห้ามเดาค่า endpoint และห้ามใช้ config ที่ยังมี `__TOKEN__`

ต้นแบบต้องแทนค่า `__REAL_WEB_IP__`, `__REAL_WEB_PORT__`,
`__WORDPRESS_IP__`, `__WORDPRESS_PORT__`, `__PHPMYADMIN_IP__` และ
`__PHPMYADMIN_PORT__` ก่อนติดตั้ง ห้ามแก้ไฟล์ใน `generated/` แล้วถือเป็น
แหล่งตั้งค่าหลัก

## ขั้นตอนตรวจสอบ

```bash
rg '__[A-Z0-9_]+__' /etc/nginx/sites-available/mimic
curl -fsS http://BACKEND_IP:BACKEND_PORT/HEALTH_PATH
sudo nginx -t
```

ผ่านครบแล้วจึง reload:

```bash
sudo systemctl reload nginx
sudo systemctl --no-pager --full status nginx
```

## ผลที่คาดหวัง

| กรณี | ผล |
|---|---|
| HTTP | redirect ไป HTTPS |
| source ไม่มี mapping | ใช้ profile `real` |
| source มี mapping | ใช้ backend ตาม profile |
| backend ใช้งานไม่ได้ | ตอบ managed `503` |
| config ผิด | `nginx -t` ไม่ผ่านและห้าม reload |

## ตารางเปลี่ยนเส้นทาง

Decision Engine เขียน map แบบ atomic และเก็บ expiry ใน state file คู่กัน
เมื่อ restart ระบบจะโหลด state กลับและลบรายการที่หมดอายุ

ตัวอย่าง:

```nginx
# generated atomically; do not edit
default real;
192.0.2.30 wordpress;
```

## การย้อนคืน

หาก validation หรือ reload ล้มเหลว adapter จะคืน map ก่อนหน้า สำหรับการคืน
Nginx ทั้งชุดให้ใช้ backup และคำสั่งใน `docs/root-operations.md`
