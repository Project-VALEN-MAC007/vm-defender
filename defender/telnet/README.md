# บริการ Telnet จำลอง

โมดูลนี้เป็นบริการจำลองขนาดเล็กสำหรับทดสอบการเชื่อมต่อและการบันทึก login
attempt ในเครื่อง ไม่ใช่ Telnet server เต็มรูปแบบและไม่มี shell จำลอง

## ความสามารถปัจจุบัน

- bind ที่ `127.0.0.1:2323` เป็นค่าเริ่มต้น
- แสดง banner และรับ username/password
- รองรับความพยายามเข้าสู่ระบบสองรอบต่อ connection
- บันทึกเหตุการณ์เป็น JSONL
- ปิด connection หลังตอบ `Login incorrect`

ตัวแปร `commands` ในโค้ดยังไม่ได้ใช้เก็บคำสั่ง เพราะระบบปัจจุบันไม่มี shell
จึงห้ามอธิบายโมดูลนี้ว่าเก็บ command history

## เริ่มใช้งานในเครื่อง

```bash
python3 run_telnet.py
```

เชื่อมต่อจาก terminal อื่น:

```bash
telnet 127.0.0.1 2323
```

Log เริ่มต้นอยู่ที่:

```text
evidence/telnet-logs/telnet.jsonl
```

## รูปแบบเหตุการณ์

```json
{
  "timestamp": "2026-09-15T10:30:45.123456",
  "session_id": "192.168.1.100:54321_1726395045.123",
  "remote_addr": "192.168.1.100:54321",
  "event_type": "connection",
  "data": {
    "status": "established"
  }
}
```

| `event_type` | ความหมาย |
|---|---|
| `connection` | เปิดหรือปิด session |
| `login_attempt` | รับ username รอบแรก |
| `auth_attempt` | รับ username/password และผล authentication |
| `login_retry` | รับ username รอบที่สอง |

## การคุ้มครองข้อมูล

โค้ดปัจจุบันบันทึกรหัสผ่านที่ส่งเข้ามาใน log เพื่อใช้ทดสอบพฤติกรรม ดังนั้น:

- ใช้เฉพาะข้อมูลทดสอบ ห้ามส่ง credential จริง
- จำกัด permission ของ log ให้เฉพาะผู้ดูแล
- ห้าม commit log เข้า repository
- กำหนด retention และลบ log เมื่อหมดวัตถุประสงค์
- ก่อนใช้จริงควรเปลี่ยนเป็นค่า hash หรือ redacted value ตามนโยบายข้อมูล

## การทดสอบ

```bash
python3 -m unittest tests.test_telnet -v
```

ตรวจ log ด้วย:

```bash
tail -f evidence/telnet-logs/telnet.jsonl
```

## ข้อจำกัดด้านเครือข่าย

ค่าเริ่มต้น bind เฉพาะ loopback ห้ามเปลี่ยนเป็น `0.0.0.0` หรือ port 23 บน
เครื่องจริงจนกว่าจะมี network isolation, firewall policy, log protection และ
การอนุมัติขอบเขตการทดสอบ

การนำ Telnet ไปเป็น endpoint ภายในจริงยังอยู่นอกขอบเขตของรอบพัฒนาปัจจุบัน
