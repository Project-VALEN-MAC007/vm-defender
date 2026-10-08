# ตรวจระบบเทียบกับเอกสาร TRAP (V0.8.4)

ตรวจวันที่ 8 ตุลาคม 2026 เทียบหัวข้อ 1.2–1.4 ของ `TRAPedit_tomorrowV0.8.4_edit.docx` กับโค้ดใน repository
ผลทดสอบอัตโนมัติ: `python3 -m unittest discover -s tests` ผ่าน 72 รายการ

## ตรงตามเอกสาร

| หัวข้อในเอกสาร | ส่วนของระบบ |
|---|---|
| Suricata ตรวจจับ แจ้งเตือน บันทึกเหตุการณ์ เพิ่ม/แก้ไขกฎได้ | `defender/suricata/`, หน้า จัดการกฎ |
| Decision Engine อ่าน eve.json คำนวณความเสี่ยงร่วมกับประวัติ IP ตั้ง Threshold ได้ | `defender/decision_engine/`, หน้า จัดการกฎ → เกณฑ์คะแนน |
| Nginx เปลี่ยนเส้นทาง HTTP/HTTPS | `defender/nginx/` (ยังไม่ activate บนเครื่องจริง) |
| Dashboard ทุกข้อใน 1.3.2.3 (Login, TOTP Flush, ภาพรวม, แจ้งเตือน, ค้นหา Log, รายงาน, CSV, จัดการผู้ใช้, Default Password, กฎและการอนุมัติ, สำรองกฎ) | `defender/dashboard/` ดู `docs/dashboard-scope-1.3.2.3.md` |
| Web Honeypot ที่เลือกหรือปรับแต่งรูปแบบหน้าเว็บได้ | หน้า **Deploy หน้าเว็บ**: clone เว็บด้วย SNARE ตรวจหาความลับ ดูตัวอย่าง แล้ว Deploy/ย้อนกลับผ่าน Dashboard และ Rabbit Hole web decoy |
| 1.3.3 ระบบเส้นทางหลอกลวงต่อเนื่อง (Rabbit Hole) | **เพิ่มใหม่** `defender/rabbit_hole/`, หน้า Rabbit Hole ดู `docs/rabbit-hole.md` |

## ไม่ตรงหรือยังไม่ครบ

1. **กฎ Default ในข้อ 1.3.2.1 ไม่ตรงกับระบบและไม่ตรงกับข้อ 1.4.1.1 ของเอกสารเอง**
   ข้อ 1.3.2.1 ระบุกฎเขียนเอง 6 ชื่อ (scanner_user_agent, path_traversal, ssh_connection_burst,
   telnet_connection_burst, syn_burst ฯลฯ) แต่ระบบใช้ ET Open 13 กฎ ตรงกับข้อ 1.4.1.1
   และ**ไม่มีกฎ SYN burst ทุกพอร์ต** ควรแก้ข้อ 1.3.2.1 ในเอกสารให้ตรงกับ ET Open
2. **Web Honeypot บันทึกฟิลด์ไม่ครบตามข้อ 1.3.2.2** สำหรับ SNARE/TANNER ยังไม่มีตัวแปลง log
   และไม่ส่งพอร์ตต้นทางของ client ต่อ (ดู README ของ snare-tanner)
   Rabbit Hole web decoy บันทึกครบทุกฟิลด์แล้ว ถ้าใช้ `web_profile: "rabbithole"` ข้อนี้จะครบ
3. **nftables redirect ยังติดขัด** ยังไม่ทดสอบ packet จริง (ตาม `docs/project-status.md`)
4. **Telnet**: เอกสารใช้ Cowrie สำหรับ Telnet ส่วน `defender/telnet/` เป็นบริการทดสอบ login
   ที่ไม่มี Shell ไม่ควรอ้างในเล่มว่าเก็บคำสั่ง
5. **ข้อ 1.3.2.2 "ตั้งค่าฮันนีพอตเพื่อเพิ่มความเนียน โดยตั้งค่า" ยังเขียนไม่จบ**
   เสนอให้เติมว่าใช้ข้อมูลองค์กรและไฟล์ลวงของ Rabbit Hole ใน Cowrie (hostname, ไฟล์ใน home, ไฟล์สำรอง)
6. **ข้อ 1.3.1 บอกว่ามี 3 ส่วนหลัก** ถ้านับ Rabbit Hole เป็นส่วนที่ 4 ต้องแก้ ถ้าถือเป็นส่วนย่อยของ Honeypot ใช้ได้ตามเดิม
7. **Decision Engine มี action `temporary_block`** ซึ่งเอกสารไม่ได้กล่าวถึง Dashboard ซ่อนยอด Block ตามขอบเขตเดิมแล้ว

## Rabbit Hole เทียบกับข้อ 1.3.3.1–1.3.3.7

| ข้อ | สถานะ |
|---|---|
| 1.3.3.1 เส้นทางลวง Web ฉากไฟล์สำรองและ API จำลอง เลือกเบาะแสตามสถานะ Session | ครบ (`web-backup-api`, `web-env-admin`) |
| 1.3.3.2 ไฟล์และโฟลเดอร์ลวงใน Cowrie สำหรับ SSH/Telnet แบบเตรียมไว้ล่วงหน้า | ครบ (`linux-server` + Cowrie bundle) ต้องติดตั้งบน Cowrie จริง |
| 1.3.3.3 ข้อมูลสอดคล้องใน Session กำหนดทางแยก ความลึก จำนวนทรัพยากร อายุ เปิด/ปิดผ่าน Dashboard | ครบ |
| 1.3.3.4 บันทึกวันเวลา Session โปรโตคอล IP คำขอ/คำสั่ง ทรัพยากร ลำดับ ผลตอบกลับ | ครบ |
| 1.3.3.5 วัดเวลาโต้ตอบ ไม่รวม Idle Timeout | ครบ มี unit test ตามตัวอย่าง 2 นาที 30 วินาที |
| 1.3.3.6 User/Master Admin ดูเส้นทาง ความลึก เวลา ผ่าน Dashboard | ครบ (ตั้งค่าได้เฉพาะ Master Admin) |
| 1.3.3.7 เปรียบเทียบ Honeypot แบบคงที่กับ Rabbit Hole แยกตามโปรโตคอล | ระบบคำนวณให้แล้ว ต้องทำการทดลองจริงเพื่อได้ตัวเลข |
