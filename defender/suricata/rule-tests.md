# แผนทดสอบกฎ Suricata

ทดสอบเฉพาะ PCAP หรือ address ที่ได้รับอนุญาต และต้องมีทั้ง positive case กับ
benign/negative case ห้ามสรุปว่ากฎผ่านจาก syntax check เพียงอย่างเดียว

| SID | Positive case | Benign/negative case | Alert ที่คาดหวัง |
|---|---|---|---|
| `2200001` | `GET /wp-admin/` | `GET /health` | WordPress path, severity high |
| `2200002` | `GET /phpmyadmin/` | `GET /index.html` | phpMyAdmin probe, severity high |
| `2200003` | `User-Agent: sqlmap-lab` | `User-Agent: curl/8` | scanner user agent, severity medium |
| `2200101` | TLS SNI ลงท้าย `.lab` | SNI อื่น | TLS metadata, severity low |
| `2200201` | SSH version ที่ไม่ใช่ OpenSSH | OpenSSH version | client version alert |
| `2200202` | SYN 5 ครั้งใน 30 วินาทีไป port 22 | ต่ำกว่า threshold | SSH burst alert |
| `2200203` | SYN 5 ครั้งใน 30 วินาทีไป port 23 | ต่ำกว่า threshold | Telnet burst alert |
| `2200301` | SYN 10 ครั้งใน 5 วินาที | connection ปกติหนึ่งครั้ง | scan-history alert |

## ขั้นตอนมาตรฐาน

1. ตรวจ syntax ของ rule file
2. replay positive PCAP และเก็บ `eve.json`
3. replay benign PCAP ด้วย config เดียวกัน
4. ตรวจ SID, severity, protocol, source และ timestamp
5. ตรวจว่า benign case ไม่สร้าง alert ที่ไม่คาดหวัง
6. เก็บ command, exit code และ output ใต้ `evidence/test-results/`

```bash
sudo suricata -T \
  -c /etc/suricata/suricata.yaml \
  -S defender/suricata/rules/local.rules
```

กฎ scan-history ใช้เพิ่มความเสี่ยงของ connection ถัดไป ไม่ได้เปลี่ยนเส้นทาง
scan ที่จบไปแล้ว

สถานะผลทดสอบล่าสุดให้อ้างอิง `docs/project-status.md` เพียงแห่งเดียว
