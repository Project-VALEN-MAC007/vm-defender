# Dashboard ตามขอบเขต 1.3.2.3

อ้างอิงหัวข้อ “ระบบ Web Application / Dashboard” ในไฟล์
`MIMIC(edit tomorrowV0.8.2).docx` ตามคำขอผู้ใช้วันที่ 3 ตุลาคม 2026
เอกสารนี้บันทึกการเทียบขอบเขตของหน้า Dashboard โดยเฉพาะ ไม่เปลี่ยนระบบเครือข่ายจากเนื้อหาใน Word

| ขอบเขต | ส่วนที่รองรับ |
|---|---|
| Login Username/Password และเปลี่ยนรหัสผ่าน | Login และบัญชีของฉัน ไม่มีสมัครสมาชิกเอง |
| TOTP ป้องกัน Flush ข้อมูล | ต้องยืนยัน TOTP ที่ยังไม่ใช้พร้อมพิมพ์ FLUSH แม้โหมดเดโม่จะข้าม OTP ตอน Login |
| ภาพรวมตามช่วงเวลา จำนวนเหตุการณ์และ Source IP | เลือก 24 ชั่วโมง / 7 วัน / 30 วัน / ทั้งหมด |
| Rank เหตุการณ์รุนแรงสูง | 10 อันดับ Source IP ตามจำนวน Alert ระดับ 1 |
| จำนวนส่งต่อ Honeypot และสถานะบริการ | Suricata, Nginx, Decision Engine |
| ข้อความแจ้งเตือนจาก Decision Engine | เวลา, Source IP, ประเภทการ Redirect, ชื่อ/SID กฎ, Severity, เวลาใน Honeypot |
| เรียงล่าสุด อ่านแล้ว/ยังไม่อ่าน และลบข้อความ | เก็บสถานะแยกตามผู้ใช้และคงอยู่หลังรีสตาร์ต |
| ค้นหา Log ย้อนหลังตามเวลา | Suricata, Decision Engine และ Honeypot พร้อมกรองเวลา/IP/โปรโตคอล/Severity |
| รายงานแยกประเภทการเชื่อมต่อและ Severity | สรุปเหตุการณ์ Decision Engine ตามช่วงเวลาที่เลือก |
| รายงานจำนวนส่งต่อบริการจริงและ Honeypot | allow/monitor เป็นบริการจริง, redirect_* เป็น Honeypot |
| เวลาเฉลี่ยใน Honeypot แต่ละแบบ | คำนวณจาก Action แรกถึง Action สุดท้ายของ Session ในช่วงที่เลือก |
| Export รายงาน CSV | รายงานสรุปตามช่วงเวลา พร้อมเวลาเฉลี่ย Honeypot; UTF-8 BOM สำหรับภาษาไทย |
| Master Admin เพิ่ม/ลบ/แก้ไขผู้ใช้และสิทธิ์ | แก้ชื่อและ User/Master Admin ได้ ป้องกันลบ/ลดสิทธิ์ Master Admin ที่ใช้งานได้คนสุดท้าย |
| เปลี่ยน Default Password ครั้งแรก | บังคับใน config ปกติ บัญชี Master Admin ที่สร้างผ่าน CLI ถูกทำเครื่องหมายให้เปลี่ยนรหัส |
| ตั้ง Threshold ของ Decision Engine | เฝ้าระวังและ Redirect; บันทึกลง config ที่กำหนดและ engine โหลดเกณฑ์ใหม่ในรอบถัดไป |
| เพิ่ม/แก้ไข/เปิดปิดกฎ | ใช้งานได้กับชุดกฎสำเนาในเดโม่ |
| ตรวจรายละเอียด หลักฐาน ผลทดสอบ และอนุมัติกฎที่เสนอ | คิวกฎรออนุมัติ บันทึกผล validation และตรวจซ้ำก่อนเพิ่มกฎ |
| สำรองและคืนค่ากฎ | สำรองก่อนทุกการแก้/เปิดปิด/อนุมัติ/คืนค่า และเลือกชุดสำรองจากหน้าเว็บ |

## ส่วนที่ตัดจากหน้าเว็บ

- ยอด Block และตัวกรอง Block ตามขอบเขตที่ผู้ใช้ยืนยันก่อนหน้านี้
- ค่า decision latency และ redirect latency ในรายงาน เพราะหัวข้อนี้กำหนดให้รายงานเวลาใน Honeypot
- หน้า Decision แยกในเมนูหลัก: รายละเอียดอยู่ในแจ้งเตือน รายงาน และ Log Search
- Export Alert/Decision ดิบในหน้าแจ้งเตือน: ใช้ Export รายงานสรุปที่หน้า Reports แทน
- สถานะ nftables ในภาพรวม: เอกสารกำหนดสามบริการข้างต้น

## การใช้ข้อมูลจริงและข้อจำกัด

ตั้ง `paths.honeypot_paths` เป็นรายการไฟล์ JSONL จาก Cowrie หรือข้อมูล Web Honeypot
ที่มี `session_id`, `source_ip`, `profile`, `first_action`, `last_action`, `actions`
และ `decision_id` หากต้องการเชื่อมกับ Decision ที่แน่นอน
Cowrie รองรับ event ที่มี `session`, `timestamp`, `eventid`, `src_ip` โดยตรง
ไม่นับ connect/disconnect/client.version เป็น Action สำหรับคำนวณเวลา
ถ้าไม่มีข้อมูล Session จะไม่แสดงเวลาขึ้นเอง และไม่นำระยะหมดอายุของ Redirect มาแทน
ไฟล์ SNARE/TANNER ดิบต้องแปลงเป็นรูปแบบ Session นี้ก่อน

Flush ล้างประวัติที่ Dashboard แสดงด้วยจุดเริ่มต้นการเก็บใหม่ในไฟล์ state
ไม่ลบไฟล์ Log ของ Suricata หรือ Honeypot; ข้อความแจ้งเตือนที่ลบก็ไม่ลบหลักฐานต้นฉบับ
ข้อมูลใน Dashboard ยังเป็น snapshot จำกัดด้วย `dashboard.maximum_rows`

โหมดเดโม่ยังใช้ `admin/admin` และข้าม OTP ตอน Login ตามคำขอก่อนหน้า
จึงตั้ง `security.force_default_password_change: false` เฉพาะ config เดโม่
Default Password และ OTP สำหรับ Flush เป็นคนละขั้นตอนกัน

การจัดการกฎในเดโม่เป็นการบันทึกลงไฟล์สำเนา ไม่ใช่การ Deploy Suricata ที่กำลังทำงานจริง
ผล validation ที่แสดงใช้ pipeline และ Baseline ที่ตั้งไว้ ไม่ใช่ผล Suricata replay บนเครื่องจริง
config ปกติยังปิด live deployment ตามข้อกำหนดเดิม และต้องเชื่อม privileged helper
ก่อนเปิดการแก้กฎบนระบบจริง
