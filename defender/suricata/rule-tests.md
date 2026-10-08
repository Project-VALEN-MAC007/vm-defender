# แผนทดสอบกฎ ET Open

ตรวจ syntax ของกฎ Default ทั้ง 13 กฎ และ replay positive/benign PCAP
ด้วย config เดียวกัน ตรวจ SID, IP, เวลา และ severity จาก eve.json

```bash
suricata -T -c /etc/suricata/suricata.yaml -S /opt/trap/defender/suricata/rules/et-open-selected.rules
```

กรณีทดสอบหลัก:

| SID | Positive case | Negative case |
|---|---|---|
| 2002677 | User-Agent ของ Nikto ถึง threshold | curl หรือคำขอต่ำกว่า threshold |
| 2008538 | User-Agent เริ่มด้วย sqlmap | curl |
| 2009359 | User-Agent มี Nmap NSE | curl |
| 2017616 | User-Agent เริ่มด้วย masscan/ | curl |
| 2031502 | GET /.env | GET /health |
| 2101071 | GET /.htpasswd | GET /login |
| 2049400 | GET /etc/passwd | GET /health |
| 2006446 | UNION SELECT ใน URI ตามกฎ | URI ปกติ |
| 2053468 | UNION SELECT ใน request body ตามกฎ | request body ปกติ |
| 2001219 | SYN ไปพอร์ต 22 ถึง threshold | SYN ต่ำกว่า threshold |
| 2006546 | banner ของ libssh ถึง threshold | banner ปกติ/ต่ำกว่า threshold |
| 2101251 | Telnet ตอบ Login incorrect | ข้อความปกติ |
| 2100492 | Telnet ตอบ Login failed | ข้อความปกติ |

ทดสอบ Decision Engine เพิ่มเติมว่า alert ตอบกลับ Telnet ระบุ IP ผู้ใช้
จาก dest_ip ไม่ใช่ src_ip ของเซิร์ฟเวอร์ และ alert ของเครื่องมือสแกนสร้าง
ประวัติความเสี่ยงได้ ทดสอบ HTTP หลัง TLS กับการเชื่อมโยง IP ผู้ใช้จริงแยกต่างหาก

เก็บหลักฐานปัจจุบันใต้ `evidence/test-results/et-open-default-20261002/`
วันที่ 2 ตุลาคม 2026 ตรวจด้วย Suricata 7.0.3 โหลดครบ 13 กฎ ไม่มีข้อผิดพลาด
replay .htpasswd, .env, /etc/passwd, Nmap NSE, Masscan และ sqlmap ได้ SID
ตามที่คาดหวัง ส่วน /health กับ curl ไม่เกิด alert
ผลเก่าของชุด ET Open+local 22 กฎเป็นหลักฐานประวัติ ไม่ใช่ชุด Default ปัจจุบัน
การผ่าน syntax และ HTTP ตัวอย่างไม่เท่ากับผ่านทุก SID หรือ redirect บน VM จริง
