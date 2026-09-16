# การติดตั้ง D4 อย่างปลอดภัย

Nginx ยังไม่ได้ติดตั้งบน VM ที่สังเกตการณ์ การตั้งค่ายังคงเป็นเทมเพลตเนื่องจาก
lab outer address และพอร์ต/health endpoints ของ backend person-2 
ยังไม่ได้รับการตรวจสอบ

การตั้งค่า lab ที่สร้างขึ้นจะ redirect HTTP ไปยัง HTTPS และยุติ TLS บน
Nginx ก่อนที่จะ proxy ไปยัง inner backend ที่เลือก เส้นทางใบรับรองที่ใช้โดย
`defender/nginx/generated/adaptive-honeypot.http.conf` คือ:

```text
/etc/adaptive-defender/tls/defender.lab.crt
/etc/adaptive-defender/tls/defender.lab.key
```

สร้างใบรับรองแบบ self-signed สำหรับ lab เท่านั้นที่เส้นทางเหล่านั้นก่อนรัน
`nginx -t` หรือแทนที่เส้นทางด้วยใบรับรองและคีย์ที่ยืนยันแล้ว

ขั้นตอนการติดตั้ง:

1. สำรองข้อมูล `/etc/nginx` พร้อม timestamp UTC
2. Render ทุก `__TOKEN__`; ปฏิเสธผลลัพธ์ถ้ายังมี token เหลืออยู่
3. ตรวจสอบ health-check ของแต่ละ backend ที่ยืนยันแล้วจาก inner interface ของ Defender
4. เขียน map ไปยังไฟล์ชั่วคราวและเปลี่ยนชื่อแบบ atomic
5. รัน `sudo nginx -t`; reload เฉพาะเมื่อ exit 0
6. ยืนยัน HTTP 308 redirect, HTTPS proxying, source-IP log fields และ managed 503 response
7. หากล้มเหลว ให้กลับคืนสู่การสำรองข้อมูล รัน `nginx -t` แล้ว reload

ไม่มีใบรับรอง ข้อมูลรับรอง หรือค่า backend จริงถูกเก็บไว้ที่นี่

สำหรับ inner WordPress honeypot backend ให้ render:

```text
__WORDPRESS_IP__=10.10.10.2
__WORDPRESS_PORT__=8081
```

ตรวจสอบก่อนเปิดใช้งาน Nginx:

```bash
curl -fsS http://10.10.10.2:8081/wp-login.php
```
