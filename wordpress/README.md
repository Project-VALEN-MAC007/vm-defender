# WordPress honeypot backend

ไดเรกทอรีนี้กำหนด WordPress backend สำหรับ Defender profile `wordpress`
มันแยก WordPress ออกจาก Python decision engine ในขณะที่ให้ Nginx มีเป้าหมาย
ภายในที่เสถียร

## ค่า Local backend

ใช้ค่าเหล่านี้เมื่อ render `defender/nginx/adaptive-honeypot.conf.template`
จาก VM-Defender ไปยัง inner honeypot VM:

```text
__WORDPRESS_IP__=10.10.10.2
__WORDPRESS_PORT__=8081
health_path=/wp-login.php
expected_status=200
```

รายการ person-2 contract ที่ตรงกันคือ:

```json
{
  "profiles": {
    "wordpress": {
      "port": 8081,
      "health_path": "/wp-login.php",
      "expected_status": 200
    }
  }
}
```

## การรัน

คัดลอกไฟล์ environment ตัวอย่างและแทนที่รหัสผ่าน placeholder ก่อนเริ่ม stack:

```bash
cd "/home/yakult/Desktop/Default Project/wordpress"
cp .env.example .env
docker compose up -d
curl -fsS http://127.0.0.1:8081/wp-login.php
```

ถ้า VM นี้ยังไม่มี Docker ให้ติดตั้งก่อนจาก local operations runbook
บน VM-Defender ให้ route traffic ผ่าน Defender Nginx template ไปยัง
`10.10.10.2:8081` ห้าม bind Docker ไปยัง `10.10.10.2` เว้นแต่ stack
กำลังรันบน honeypot VM ที่เป็นเจ้าของที่อยู่นั้น
