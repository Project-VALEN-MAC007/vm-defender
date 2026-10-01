# แผนทดสอบกฎ Suricata

ทดสอบเฉพาะ PCAP หรือ address ที่ได้รับอนุญาต และต้องมีทั้ง positive case กับ
benign/negative case ห้ามสรุปว่ากฎผ่านจาก syntax check เพียงอย่างเดียว

| SID | Positive case | Benign/negative case | Alert ที่คาดหวัง |
|---|---|---|---|
| `2200003` | `User-Agent: sqlmap-lab` | `User-Agent: curl/8` | `scanner_user_agent` |
| `2200004` | `GET /.env` | `GET /health` | `env_file_access` |
| `2200005` | `GET /.git/config` | `GET /index.html` | `git_config_access` |
| `2200007` | `GET /../../etc/passwd` | `GET /docs/etc/passwd` | `path_traversal` |
| `2200008` | `GET /.htpasswd` | `GET /login` | `password_file_access` |
| `2200009` | `GET /.svn/entries` | `GET /source` | `svn_metadata_access` |
| `2200102` | เจรจา HTTPS บน port 443 สำเร็จด้วย TLS 1.0 | TLS 1.2/1.3 หรือ server ปฏิเสธ TLS 1.0 | `tls_1_0_negotiated` |
| `2200103` | เจรจา HTTPS บน port 443 สำเร็จด้วย TLS 1.1 | TLS 1.2/1.3 หรือ server ปฏิเสธ TLS 1.1 | `tls_1_1_negotiated` |
| `2200202` | SYN 5 ครั้งใน 30 วินาทีไป port 22 | ต่ำกว่า threshold | `ssh_connection_burst` |
| `2200203` | SYN 5 ครั้งใน 30 วินาทีไป port 23 | ต่ำกว่า threshold | `telnet_connection_burst` |
| `2200301` | SYN 10 ครั้งใน 5 วินาที | connection ปกติหนึ่งครั้ง | `syn_burst`; ไม่ยืนยันว่าคนละ port |

`2200001`, `2200002` และ `2200006` เลิกใช้แล้วเพราะผูกกับบริการเว็บเดิม
ส่วน `2200101` และ `2200201` เลิกใช้เพราะ SNI `.lab` และ client SSH ที่
ไม่ใช่ OpenSSH ไม่ใช่หลักฐานการโจมตีลำพัง

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
  -S /opt/mimic/defender/suricata/rules/local.rules
```

ตั้ง `HOME_NET` ให้ตรงกับ outer IP ที่รับทราฟฟิกจริง เช่น
`[192.168.56.10/32]` แล้วทดสอบทั้ง source ในวง lab และ source ภายนอก
กฎ SYN burst ใช้เพิ่มความเสี่ยงของ connection ถัดไป ไม่ได้เปลี่ยนเส้นทาง
scan ที่จบไปแล้ว และไม่แยก SYN retransmission ออกจากการเชื่อมต่อใหม่

สถานะผลทดสอบล่าสุดให้อ้างอิง `docs/project-status.md` เพียงแห่งเดียว
