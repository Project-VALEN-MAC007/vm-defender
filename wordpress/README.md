# แบ็กเอนด์ WordPress สำหรับทดสอบ

directory นี้มี Docker Compose สำหรับสร้าง WordPress backend แยกจาก Decision
Engine ใช้เป็นเป้าหมายของ profile `wordpress` หลังจากผู้ดูแลยืนยัน endpoint แล้ว

การติดตั้งบริการนี้ยังไม่ใช่ส่วนหนึ่งของขั้นตอนติดตั้ง Defender ปัจจุบัน

## บริการภายใน Docker Compose

| Service | หน้าที่ |
|---|---|
| `wordpress` | WordPress บน Apache/PHP |
| `db` | MariaDB สำหรับ WordPress |

ค่า bind เริ่มต้นเป็น loopback:

```text
127.0.0.1:8081 -> wordpress:80
```

## เตรียมตัวแปรสภาพแวดล้อม

ต้องกำหนดค่าต่อไปนี้ก่อนเริ่ม container:

```dotenv
WORDPRESS_BIND_IP=127.0.0.1
WORDPRESS_PORT=8081
WORDPRESS_DB_NAME=wordpress_honeypot
WORDPRESS_DB_USER=wordpress
WORDPRESS_DB_PASSWORD=CHANGE_TO_A_LONG_RANDOM_VALUE
WORDPRESS_DB_ROOT_PASSWORD=CHANGE_TO_A_DIFFERENT_LONG_RANDOM_VALUE
```

ห้ามใช้ค่า `change-me-wordpress` หรือ `change-me-root` จาก fallback ของ compose
ในระบบที่เปิดใช้งานจริง

## เริ่มและตรวจสอบ

```bash
docker compose config
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8081/wp-login.php
```

## ข้อตกลงข้อมูลสำหรับ Defender

หลังยืนยันจากเครื่องที่รัน service แล้ว ให้ส่งค่าต่อไปนี้ตาม
`docs/person2-contract.md`:

```json
{
  "profiles": {
    "wordpress": {
      "ip": "REQUIRED",
      "port": 8081,
      "health_path": "/wp-login.php",
      "expected_status": 200
    }
  }
}
```

Defender ต้องตรวจ health endpoint ผ่าน inner network ก่อนเปิด profile

## หยุดระบบ

```bash
docker compose down
```

คำสั่งนี้ไม่ลบ named volumes หากต้องการลบข้อมูลต้องทบทวน target และนโยบาย
เก็บหลักฐานก่อนทุกครั้ง
