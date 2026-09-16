# การตั้งค่า Telnet Honeypot

## ภาพรวม

Telnet honeypot จำลองบริการ telnet ที่มีช่องโหว่เพื่อดึงดูดและบันทึกพฤติกรรมของผู้โจมตี 
การเชื่อมต่อและความพยายามในการยืนยันตัวตนทั้งหมดจะถูกบันทึกเพื่อการวิเคราะห์

## เริ่มต้นใช้งาน

### ทดสอบในเครื่องอย่างปลอดภัย (localhost เท่านั้น):

```bash
cd "/home/yakult/Desktop/Default Project"
python3 run_telnet.py
```

เชื่อมต่อจาก terminal อื่น:
```bash
telnet 127.0.0.1 2323
```

### ตัวเลือกการตั้งค่า

คลาส `TelnetHoneypot` รับพารามิเตอร์:

- `host`: IP address ที่จะ bind (ค่าเริ่มต้น: "127.0.0.1" เพื่อความปลอดภัย)
- `port`: พอร์ตที่จะ listen (ค่าเริ่มต้น: 2323, ไม่ต้องใช้สิทธิ์พิเศษ)
- `log_path`: เส้นทางไฟล์ log ในรูปแบบ JSONL

## รูปแบบ Log

Session ของ Telnet จะถูกบันทึกไปยัง `evidence/telnet-logs/telnet.jsonl` ในรูปแบบ JSONL:

```json
{
  "timestamp": "2026-09-15T10:30:45.123456",
  "session_id": "192.168.1.100:54321_1726395045.123",
  "remote_addr": "192.168.1.100:54321",
  "event_type": "connection",
  "data": {"status": "established"}
}
```

ประเภทของ Event:
- `connection`: เริ่มต้น/สิ้นสุด Session
- `login_attempt`: มีการส่ง Username
- `auth_attempt`: มีการส่ง Password (บันทึกเพื่อวิเคราะห์ภัยคุกคาม)
- `login_retry`: มีการพยายาม login หลายครั้ง

## ข้อควรระวังด้านความปลอดภัย

⚠️ **การตั้งค่าเริ่มต้น bind ที่ localhost เท่านั้น** เพื่อป้องกันการเปิดเผยโดยไม่ตั้งใจ

หากต้องการเปิดให้เข้าถึงผ่านเครือข่าย (ในสภาพแวดล้อม lab เท่านั้น):

```python
honeypot = TelnetHoneypot(host="10.10.10.1", port=23, log_path=log_path)
```

**พอร์ต 23 ต้องใช้สิทธิ์ root:**
```bash
sudo python3 run_telnet.py  # ถ้า bind ที่พอร์ต 23
```

## การผสานรวมกับ VM-Defender

Log ของ telnet honeypot สามารถถูกวิเคราะห์โดย decision engine เพื่อการตอบสนองแบบปรับตัว:

1. แยกวิเคราะห์ `evidence/telnet-logs/telnet.jsonl` เพื่อหาความพยายามในการยืนยันตัวตน
2. ดึง IP ต้นทางและรูปแบบการโจมตี
3. ป้อนเข้าสู่ระบบให้คะแนนความเสี่ยง
4. เรียกใช้การบลอกหรือเปลี่ยนเส้นทางด้วย nftables ตามระดับภัยคุกคาม

## การทดสอบ

ทดสอบ honeypot ด้วย:

```bash
# Terminal 1: เริ่ม honeypot
python3 run_telnet.py

# Terminal 2: เชื่อมต่อในฐานะผู้โจมตี
telnet 127.0.0.1 2323
# ลอง username: admin
# ลอง password: password123

# Terminal 3: ดู logs
tail -f evidence/telnet-logs/telnet.jsonl
```

## การติดตั้งในโหมดจริง

สำหรับการติดตั้ง honeypot ในโหมดจริง:

1. ตั้งค่า network interface ที่เหมาะสม (เช่น `10.10.10.1`)
2. ใช้พอร์ต telnet มาตรฐาน 23 (ต้องใช้สิทธิ์ root)
3. ตรวจสอบให้แน่ใจว่ากฎ firewall อนุญาตการเข้าถึงจากภายนอก
4. ติดตาม logs เพื่อหากิจกรรมที่น่าสงสัย
5. ผสานรวมกับ decision engine เพื่อการตอบสนองอัตโนมัติ

ดู `docs/root-operations.md` สำหรับการใช้งานที่ต้องการสิทธิ์สูง
