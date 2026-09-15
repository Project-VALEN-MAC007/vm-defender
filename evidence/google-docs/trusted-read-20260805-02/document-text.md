# Untitled document

- Document ID: 1bSS_tgDU6w4BLzImWZq7kXSF8veEGTAAS4tIqiojRfY
- Revision ID: AIroW34tNZPA0oPi_A1buOffBU2Z-aGnlQp_cykx4FfHYhuJIUzFKWvqq4YbBOjdmIH8lIQ3lcvl_E-VGdpzL1mlfGUxms71bu0XO0ZOHJY
- Selected tab: all
- Protected controls: 0
- Opaque controls: 0
- Authoritative dropdowns: 0

Protected-control annotations are preservation instructions. Do not insert their displayed placeholder text to recreate a native control.

## Tab 1 (t.0)

[P00001 | 1:41 | TITLE]
บันทึกการดำเนินงานคนที่ 1 — VM-Defender

[P00002 | 41:42 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00003 | 42:83 | NORMAL_TEXT]
โครงงาน Adaptive Honeypot ควบคุมด้วย IDS

[P00004 | 83:245 | NORMAL_TEXT]
เอกสารนี้ใช้บันทึกสิ่งที่ดำเนินการจริงบน VM-Defender โดยให้กรอกข้อมูลหลังตรวจสอบหรือทดสอบแล้วเท่านั้น ห้ามระบุว่า “ผ่าน” หากไม่มีคำสั่ง ผลลัพธ์ หรือหลักฐานรองรับ

[P00005 | 245:246 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00006 | 246:264 | HEADING_1]
ข้อมูลสภาพแวดล้อม

[P00007 | 264:265 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00008 | 265:294 | NORMAL_TEXT]
วันที่เริ่มดำเนินงาน: [กรอก]

[P00009 | 294:316 | NORMAL_TEXT]
ผู้รับผิดชอบ: คนที่ 1

[P00010 | 316:350 | NORMAL_TEXT]
ระบบปฏิบัติการและเวอร์ชัน: [กรอก]

[P00011 | 350:367 | NORMAL_TEXT]
Hostname: [กรอก]

[P00012 | 367:387 | NORMAL_TEXT]
VM Platform: [กรอก]

[P00013 | 387:416 | NORMAL_TEXT]
Repository/Commit ID: [กรอก]

[P00014 | 416:443 | NORMAL_TEXT]
IP วงนอกที่ใช้จริง: [กรอก]

[P00015 | 443:469 | NORMAL_TEXT]
IP วงในที่ใช้จริง: [กรอก]

[P00016 | 469:493 | NORMAL_TEXT]
Interface วงนอก: [กรอก]

[P00017 | 493:516 | NORMAL_TEXT]
Interface วงใน: [กรอก]

[P00018 | 516:595 | NORMAL_TEXT]
สถานะรวม: ☐ ยังไม่เริ่ม  ☐ กำลังดำเนินการ  ☐ พร้อม Integration  ☐ เสร็จสมบูรณ์

[P00019 | 595:596 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00020 | 596:612 | HEADING_1]
หลักการบันทึกผล

[P00021 | 612:613 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00022 | 613:669 | NORMAL_TEXT]
• บันทึกค่าจริงจาก VM ไม่คัดลอกค่าตัวอย่างโดยไม่ตรวจสอบ

[P00023 | 669:736 | NORMAL_TEXT]
• ทุกหัวข้อต้องระบุไฟล์ที่สร้างหรือแก้ และสำรองไฟล์เดิมก่อนเปลี่ยน

[P00024 | 736:788 | NORMAL_TEXT]
• เก็บคำสั่งทดสอบ ผลที่คาดหวัง ผลจริง และ Exit Code

[P00025 | 788:850 | NORMAL_TEXT]
• แนบ Screenshot, Log, PCAP หรือ Commit ID ที่ตรวจย้อนกลับได้

[P00026 | 850:895 | NORMAL_TEXT]
• ระบุปัญหาที่ยังค้างและวิธีย้อนกลับทุกครั้ง

[P00027 | 895:962 | NORMAL_TEXT]
• ห้ามบันทึก Password, API Key, Private Key หรือข้อมูลจริงลงเอกสาร

[P00028 | 962:1016 | NORMAL_TEXT]
• ทดสอบเฉพาะ VM Lab ที่ได้รับอนุญาต ห้ามยิงระบบภายนอก

[P00029 | 1016:1017 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00030 | 1017:1055 | HEADING_1]
D1 การเตรียม VM-Defender และเครือข่าย

[P00031 | 1055:1056 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00032 | 1056:1069 | HEADING_2]
วัตถุประสงค์

[P00033 | 1069:1187 | NORMAL_TEXT]
เตรียม VM-Defender ให้มีเครือข่ายสองวง แยก VM-Attacker ออกจาก VM-Honeypot และรองรับการตรวจจับกับ Redirect ในขั้นถัดไป

[P00034 | 1187:1188 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00035 | 1188:1204 | HEADING_2]
รายการดำเนินการ

[P00036 | 1204:1241 | NORMAL_TEXT]
☐ ตรวจ OS, Kernel, CPU, RAM และ Disk

[P00037 | 1241:1292 | NORMAL_TEXT]
☐ ตรวจชื่อและ MAC Address ของทุก Network Interface

[P00038 | 1292:1339 | NORMAL_TEXT]
☐ ตั้ง Static IP วงนอกสำหรับติดต่อ VM-Attacker

[P00039 | 1339:1385 | NORMAL_TEXT]
☐ ตั้ง Static IP วงในสำหรับติดต่อ VM-Honeypot

[P00040 | 1385:1426 | NORMAL_TEXT]
☐ ตรวจ Routing Table และ Default Gateway

[P00041 | 1426:1483 | NORMAL_TEXT]
☐ เปิด IP Forwarding เฉพาะเมื่อจำเป็นสำหรับ SSH Redirect

[P00042 | 1483:1546 | NORMAL_TEXT]
☐ ตั้ง Forward Policy เป็น Drop และเปิดเฉพาะ Traffic ที่จำเป็น

[P00043 | 1546:1594 | NORMAL_TEXT]
☐ ตั้งเวลาเครื่องและ Timezone ให้ตรงกับ VM อื่น

[P00044 | 1594:1641 | NORMAL_TEXT]
☐ ทดสอบว่า Attacker เข้า Honeypot โดยตรงไม่ได้

[P00045 | 1641:1642 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00046 | 1642:1656 | HEADING_2]
ค่าที่ใช้จริง

[P00047 | 1656:1677 | NORMAL_TEXT]
วงนอก/Subnet: [กรอก]

[P00048 | 1677:1697 | NORMAL_TEXT]
วงใน/Subnet: [กรอก]

[P00049 | 1697:1727 | NORMAL_TEXT]
Route ที่เพิ่มหรือแก้: [กรอก]

[P00050 | 1727:1751 | NORMAL_TEXT]
Firewall Policy: [กรอก]

[P00051 | 1751:1772 | NORMAL_TEXT]
NTP/Timezone: [กรอก]

[P00052 | 1772:1773 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00053 | 1773:1793 | HEADING_2]
ไฟล์ที่สร้างหรือแก้

[P00054 | 1793:1826 | NORMAL_TEXT]
• [พาธไฟล์] — [อธิบายสิ่งที่แก้]

[P00055 | 1826:1859 | NORMAL_TEXT]
• [พาธไฟล์สำรอง] — [วันที่สำรอง]

[P00056 | 1859:1860 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00057 | 1860:1874 | HEADING_2]
คำสั่งตรวจสอบ

[P00058 | 1874:1888 | NORMAL_TEXT]
• ip -br addr

[P00059 | 1888:1899 | NORMAL_TEXT]
• ip route

[P00060 | 1899:1913 | NORMAL_TEXT]
• timedatectl

[P00061 | 1913:1942 | NORMAL_TEXT]
• sysctl net.ipv4.ip_forward

[P00062 | 1942:1961 | NORMAL_TEXT]
• nft list ruleset

[P00063 | 1961:1998 | NORMAL_TEXT]
• ping/curl ตาม Test Matrix ที่กำหนด

[P00064 | 1998:1999 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00065 | 1999:2010 | HEADING_2]
ผลการทดสอบ

[P00066 | 2010:2074 | NORMAL_TEXT]
Positive Test — Defender ติดต่อ Attacker และ Honeypot: [ผลจริง]

[P00067 | 2074:2144 | NORMAL_TEXT]
Negative Test — Attacker ติดต่อ Honeypot โดยตรง: [ต้องล้มเหลว/ผลจริง]

[P00068 | 2144:2199 | NORMAL_TEXT]
Recovery Test — คืนค่า Network/Firewall เดิม: [ผลจริง]

[P00069 | 2199:2253 | NORMAL_TEXT]
สถานะ D1: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00070 | 2253:2300 | NORMAL_TEXT]
หลักฐาน: [ลิงก์/พาธ Screenshot, Log หรือ PCAP]

[P00071 | 2300:2320 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00072 | 2320:2392 | NORMAL_TEXT]
ข้อมูลส่งต่อคนที่ 2: IP, Interface, Port และข้อจำกัด Network ที่ใช้จริง

[P00073 | 2392:2393 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00074 | 2393:2426 | HEADING_1]
D2 การติดตั้งและตั้งค่า Suricata

[P00075 | 2426:2427 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00076 | 2427:2440 | HEADING_2]
วัตถุประสงค์

[P00077 | 2440:2561 | NORMAL_TEXT]
ให้ Suricata ตรวจ Traffic จากวงนอก วงใน และ Loopback พร้อมสร้าง eve.json ที่ Decision Engine และระบบ Correlation อ่านได้

[P00078 | 2561:2562 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00079 | 2562:2578 | HEADING_2]
รายการดำเนินการ

[P00080 | 2578:2620 | NORMAL_TEXT]
☐ บันทึกเวอร์ชัน Suricata และแหล่งติดตั้ง

[P00081 | 2620:2652 | NORMAL_TEXT]
☐ สำรอง suricata.yaml ก่อนแก้ไข

[P00082 | 2652:2685 | NORMAL_TEXT]
☐ ตั้ง HOME_NET และ EXTERNAL_NET

[P00083 | 2685:2733 | NORMAL_TEXT]
☐ ตั้ง Interface ที่เฝ้าดูตามชื่อจริงของเครื่อง

[P00084 | 2733:2790 | NORMAL_TEXT]
☐ เปิด Event Type: alert, http, tls, ssh, flow และ stats

[P00085 | 2790:2838 | NORMAL_TEXT]
☐ เพิ่ม local.rules และกำหนดช่วง SID ของโครงงาน

[P00086 | 2838:2888 | NORMAL_TEXT]
☐ ตั้งสิทธิ์อ่าน eve.json ให้โปรแกรมที่เกี่ยวข้อง

[P00087 | 2888:2926 | NORMAL_TEXT]
☐ ตรวจ Configuration ด้วย suricata -T

[P00088 | 2926:2964 | NORMAL_TEXT]
☐ ทดสอบ Start, Stop, Restart และ Boot

[P00089 | 2964:2965 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00090 | 2965:2979 | HEADING_2]
ค่าที่ใช้จริง

[P00091 | 2979:3004 | NORMAL_TEXT]
Suricata Version: [กรอก]

[P00092 | 3004:3021 | NORMAL_TEXT]
HOME_NET: [กรอก]

[P00093 | 3021:3040 | NORMAL_TEXT]
Interfaces: [กรอก]

[P00094 | 3040:3058 | NORMAL_TEXT]
Rule Path: [กรอก]

[P00095 | 3058:3080 | NORMAL_TEXT]
eve.json Path: [กรอก]

[P00096 | 3080:3097 | NORMAL_TEXT]
ช่วง SID: [กรอก]

[P00097 | 3097:3098 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00098 | 3098:3118 | HEADING_2]
ไฟล์ที่สร้างหรือแก้

[P00099 | 3118:3157 | NORMAL_TEXT]
• /etc/suricata/suricata.yaml — [สรุป]

[P00100 | 3157:3186 | NORMAL_TEXT]
• [พาธ local.rules] — [สรุป]

[P00101 | 3186:3208 | NORMAL_TEXT]
• [ไฟล์อื่น] — [สรุป]

[P00102 | 3208:3209 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00103 | 3209:3220 | HEADING_2]
ผลการทดสอบ

[P00104 | 3220:3247 | NORMAL_TEXT]
Config Test: [คำสั่งและผล]

[P00105 | 3247:3268 | NORMAL_TEXT]
Service Status: [ผล]

[P00106 | 3268:3301 | NORMAL_TEXT]
Test Alert: [SID/เวลา/Source IP]

[P00107 | 3301:3325 | NORMAL_TEXT]
Log Rotation Test: [ผล]

[P00108 | 3325:3379 | NORMAL_TEXT]
สถานะ D2: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00109 | 3379:3421 | NORMAL_TEXT]
หลักฐาน: [พาธ config, log และ screenshot]

[P00110 | 3421:3441 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00111 | 3441:3509 | NORMAL_TEXT]
ข้อมูลส่งต่อคนที่ 2: Schema และตัวอย่าง Alert/Flow ที่ใช้ Correlate

[P00112 | 3509:3510 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00113 | 3510:3553 | HEADING_1]
D3 กฎตรวจจับ HTTP, HTTPS/TLS, SSH และ Scan

[P00114 | 3553:3554 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00115 | 3554:3567 | HEADING_2]
วัตถุประสงค์

[P00116 | 3567:3652 | NORMAL_TEXT]
สร้างกฎตรวจจับที่มี Test Case ชัดเจน ครอบคลุมสี่ช่องทาง และควบคุม False Positive ได้

[P00117 | 3652:3653 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00118 | 3653:3658 | HEADING_2]
HTTP

[P00119 | 3658:3716 | NORMAL_TEXT]
☐ ตรวจ URI/Path ที่เกี่ยวข้องกับ WordPress และ phpMyAdmin

[P00120 | 3716:3762 | NORMAL_TEXT]
☐ ตรวจ User-Agent หรือรูปแบบ Scanner ที่กำหนด

[P00121 | 3762:3795 | NORMAL_TEXT]
☐ มี Benign Test และ Attack Test

[P00122 | 3795:3796 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00123 | 3796:3806 | HEADING_2]
HTTPS/TLS

[P00124 | 3806:3854 | NORMAL_TEXT]
☐ ตรวจ Traffic หลัง TLS Termination บน Loopback

[P00125 | 3854:3888 | NORMAL_TEXT]
☐ เก็บ TLS/JA3 Metadata ที่จำเป็น

[P00126 | 3888:3918 | NORMAL_TEXT]
☐ ยืนยัน Source IP หลัง Proxy

[P00127 | 3918:3919 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00128 | 3919:3923 | HEADING_2]
SSH

[P00129 | 3923:3969 | NORMAL_TEXT]
☐ ตรวจ Version String หรือ Connection Pattern

[P00130 | 3969:4019 | NORMAL_TEXT]
☐ ตรวจ Connection Burst/Brute-force ตาม Threshold

[P00131 | 4019:4056 | NORMAL_TEXT]
☐ ทดสอบโดยไม่สร้างภาระเกินขอบเขต Lab

[P00132 | 4056:4057 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00133 | 4057:4070 | HEADING_2]
Network Scan

[P00134 | 4070:4099 | NORMAL_TEXT]
☐ ตรวจ SYN/Port-scan Pattern

[P00135 | 4099:4153 | NORMAL_TEXT]
☐ นำ Alert ไปเพิ่ม Risk Score สำหรับ Connection ถัดไป

[P00136 | 4153:4217 | NORMAL_TEXT]
☐ บันทึกข้อจำกัดว่า Scan ที่จบแล้วไม่สามารถ Redirect กลางทางได้

[P00137 | 4217:4218 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00138 | 4218:4228 | HEADING_2]
ทะเบียนกฎ

[P00139 | 4228:4248 | NORMAL_TEXT]
Rule ID/SID: [กรอก]

[P00140 | 4248:4265 | NORMAL_TEXT]
Protocol: [กรอก]

[P00141 | 4265:4282 | NORMAL_TEXT]
เงื่อนไข: [กรอก]

[P00142 | 4282:4299 | NORMAL_TEXT]
Severity: [กรอก]

[P00143 | 4299:4322 | NORMAL_TEXT]
Expected Alert: [กรอก]

[P00144 | 4322:4344 | NORMAL_TEXT]
Benign Result: [กรอก]

[P00145 | 4344:4366 | NORMAL_TEXT]
Attack Result: [กรอก]

[P00146 | 4366:4395 | NORMAL_TEXT]
False Positive ที่พบ: [กรอก]

[P00147 | 4395:4414 | NORMAL_TEXT]
การปรับแก้: [กรอก]

[P00148 | 4414:4415 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00149 | 4415:4469 | NORMAL_TEXT]
สถานะ D3: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00150 | 4469:4521 | NORMAL_TEXT]
หลักฐาน: [พาธ Rule, PCAP, eve.json และ Test Matrix]

[P00151 | 4521:4541 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00152 | 4541:4623 | NORMAL_TEXT]
ข้อมูลส่งต่อคนที่ 2: SID/Severity Mapping และ Expected Artifact ของแต่ละ Protocol

[P00153 | 4623:4624 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00154 | 4624:4658 | HEADING_1]
D4 HTTP/HTTPS Redirect ด้วย Nginx

[P00155 | 4658:4659 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00156 | 4659:4672 | HEADING_2]
วัตถุประสงค์

[P00157 | 4672:4788 | NORMAL_TEXT]
แยก Traffic ปกติไป Real Server และ Traffic เสี่ยงไป Web Honeypot Profile ที่เหมาะสม โดยตรวจ Config และ Rollback ได้

[P00158 | 4788:4789 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00159 | 4789:4805 | HEADING_2]
รายการดำเนินการ

[P00160 | 4805:4864 | NORMAL_TEXT]
☐ สร้าง Real Server ที่ 127.0.0.1:8080 หรือค่าจริงที่กำหนด

[P00161 | 4864:4897 | NORMAL_TEXT]
☐ ตั้ง Reverse Proxy สำหรับ HTTP

[P00162 | 4897:4940 | NORMAL_TEXT]
☐ ตั้ง TLS Termination สำหรับ HTTPS ใน Lab

[P00163 | 4940:4976 | NORMAL_TEXT]
☐ ส่ง X-Real-IP และ X-Forwarded-For

[P00164 | 4976:5008 | NORMAL_TEXT]
☐ กำหนด Access/Error Log Format

[P00165 | 5008:5061 | NORMAL_TEXT]
☐ สร้าง Redirect Map: real, wordpress และ phpmyadmin

[P00166 | 5061:5085 | NORMAL_TEXT]
☐ อัปเดต Map แบบ Atomic

[P00167 | 5085:5121 | NORMAL_TEXT]
☐ รัน nginx -t ก่อน Reload ทุกครั้ง

[P00168 | 5121:5151 | NORMAL_TEXT]
☐ ทำ Health Check ของ Backend

[P00169 | 5151:5209 | NORMAL_TEXT]
☐ เตรียม Backup และ Rollback เมื่อ Config/Backend ผิดพลาด

[P00170 | 5209:5210 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00171 | 5210:5229 | HEADING_2]
Backend ที่ใช้จริง

[P00172 | 5229:5252 | NORMAL_TEXT]
Real Server: [IP:Port]

[P00173 | 5252:5282 | NORMAL_TEXT]
WordPress Honeypot: [IP:Port]

[P00174 | 5282:5313 | NORMAL_TEXT]
phpMyAdmin Honeypot: [IP:Port]

[P00175 | 5313:5338 | NORMAL_TEXT]
Certificate Path: [กรอก]

[P00176 | 5338:5364 | NORMAL_TEXT]
Redirect Map Path: [กรอก]

[P00177 | 5364:5365 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00178 | 5365:5376 | HEADING_2]
ผลการทดสอบ

[P00179 | 5376:5406 | NORMAL_TEXT]
Benign IP → Real Server: [ผล]

[P00180 | 5406:5432 | NORMAL_TEXT]
Test IP → WordPress: [ผล]

[P00181 | 5432:5459 | NORMAL_TEXT]
Test IP → phpMyAdmin: [ผล]

[P00182 | 5459:5475 | NORMAL_TEXT]
HTTP Test: [ผล]

[P00183 | 5475:5492 | NORMAL_TEXT]
HTTPS Test: [ผล]

[P00184 | 5492:5520 | NORMAL_TEXT]
Backend Down/502 Test: [ผล]

[P00185 | 5520:5540 | NORMAL_TEXT]
Rollback Test: [ผล]

[P00186 | 5540:5594 | NORMAL_TEXT]
สถานะ D4: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00187 | 5594:5642 | NORMAL_TEXT]
หลักฐาน: [พาธ Config, Log, Screenshot และ PCAP]

[P00188 | 5642:5662 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00189 | 5662:5742 | NORMAL_TEXT]
ข้อมูลที่ต้องรับจากคนที่ 2: Backend Port, Health Endpoint และ Expected Response

[P00190 | 5742:5743 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00191 | 5743:5773 | HEADING_1]
D5 SSH Redirect ด้วย nftables

[P00192 | 5773:5774 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00193 | 5774:5787 | HEADING_2]
วัตถุประสงค์

[P00194 | 5787:5904 | NORMAL_TEXT]
Redirect การเชื่อมต่อ SSH จาก Source IP ที่อยู่ใน Set ไปยัง Cowrie พร้อม Return Path ที่ถูกต้องและกู้คืน Ruleset ได้

[P00195 | 5904:5905 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00196 | 5905:5921 | HEADING_2]
รายการดำเนินการ

[P00197 | 5921:5978 | NORMAL_TEXT]
☐ สร้าง Table/Chain: prerouting, forward และ postrouting

[P00198 | 5978:6025 | NORMAL_TEXT]
☐ สร้าง Set ชื่อ ssh_redirect หรือชื่อที่กำหนด

[P00199 | 6025:6066 | NORMAL_TEXT]
☐ ทำ DNAT จาก Defender Port 22 ไป Cowrie

[P00200 | 6066:6106 | NORMAL_TEXT]
☐ ทำ SNAT/Masquerade สำหรับ Return Path

[P00201 | 6106:6149 | NORMAL_TEXT]
☐ จำกัด Forwarding เฉพาะ Traffic ที่จำเป็น

[P00202 | 6149:6184 | NORMAL_TEXT]
☐ เพิ่ม/ลบ Source IP พร้อม Timeout

[P00203 | 6184:6229 | NORMAL_TEXT]
☐ ตรวจ Connection ด้วย tcpdump และ conntrack

[P00204 | 6229:6267 | NORMAL_TEXT]
☐ บันทึก Ruleset ให้คงอยู่หลัง Reboot

[P00205 | 6267:6321 | NORMAL_TEXT]
☐ ทดสอบ Flush/Restore โดยไม่ทำให้เข้าถึงเครื่องไม่ได้

[P00206 | 6321:6322 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00207 | 6322:6336 | HEADING_2]
ค่าที่ใช้จริง

[P00208 | 6336:6362 | NORMAL_TEXT]
Defender SSH Port: [กรอก]

[P00209 | 6362:6385 | NORMAL_TEXT]
Cowrie IP:Port: [กรอก]

[P00210 | 6385:6402 | NORMAL_TEXT]
Set Name: [กรอก]

[P00211 | 6402:6418 | NORMAL_TEXT]
Timeout: [กรอก]

[P00212 | 6418:6439 | NORMAL_TEXT]
Ruleset Path: [กรอก]

[P00213 | 6439:6440 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00214 | 6440:6451 | HEADING_2]
ผลการทดสอบ

[P00215 | 6451:6476 | NORMAL_TEXT]
IP ใน Set → Cowrie: [ผล]

[P00216 | 6476:6515 | NORMAL_TEXT]
IP นอก Set → ไม่ Redirect ผิดทาง: [ผล]

[P00217 | 6515:6536 | NORMAL_TEXT]
Return Traffic: [ผล]

[P00218 | 6536:6561 | NORMAL_TEXT]
Reboot/Persistence: [ผล]

[P00219 | 6561:6580 | NORMAL_TEXT]
Restore Test: [ผล]

[P00220 | 6580:6634 | NORMAL_TEXT]
สถานะ D5: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00221 | 6634:6688 | NORMAL_TEXT]
หลักฐาน: [Ruleset, tcpdump, conntrack และ Cowrie Log]

[P00222 | 6688:6708 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00223 | 6708:6782 | NORMAL_TEXT]
ข้อมูลที่ต้องรับจากคนที่ 2: Cowrie Port, Health/Log Path และ Return Route

[P00224 | 6782:6783 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00225 | 6783:6802 | HEADING_1]
D6 Decision Engine

[P00226 | 6802:6803 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00227 | 6803:6816 | HEADING_2]
วัตถุประสงค์

[P00228 | 6816:6915 | NORMAL_TEXT]
อ่าน Alert จาก Suricata คำนวณ Risk และเปลี่ยน Nginx/nftables อย่างปลอดภัย พร้อม Audit และ Rollback

[P00229 | 6915:6916 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00230 | 6916:6927 | HEADING_2]
องค์ประกอบ

[P00231 | 6927:6958 | NORMAL_TEXT]
☐ eve.json Reader แบบต่อเนื่อง

[P00232 | 6958:6983 | NORMAL_TEXT]
☐ File Offset/Checkpoint

[P00233 | 6983:7007 | NORMAL_TEXT]
☐ Log Rotation Handling

[P00234 | 7007:7029 | NORMAL_TEXT]
☐ Event Normalization

[P00235 | 7029:7051 | NORMAL_TEXT]
☐ Event Deduplication

[P00236 | 7051:7071 | NORMAL_TEXT]
☐ Risk Score Engine

[P00237 | 7071:7102 | NORMAL_TEXT]
☐ Threshold และ Action Mapping

[P00238 | 7102:7122 | NORMAL_TEXT]
☐ Nginx Map Adapter

[P00239 | 7122:7145 | NORMAL_TEXT]
☐ nftables Set Adapter

[P00240 | 7145:7166 | NORMAL_TEXT]
☐ Expiration/Timeout

[P00241 | 7166:7181 | NORMAL_TEXT]
☐ Dry-run Mode

[P00242 | 7181:7202 | NORMAL_TEXT]
☐ Audit/Decision Log

[P00243 | 7202:7225 | NORMAL_TEXT]
☐ Retry/Error Handling

[P00244 | 7225:7252 | NORMAL_TEXT]
☐ Configuration Validation

[P00245 | 7252:7270 | NORMAL_TEXT]
☐ systemd Service

[P00246 | 7270:7295 | NORMAL_TEXT]
☐ Unit/Integration Tests

[P00247 | 7295:7296 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00248 | 7296:7319 | HEADING_2]
Risk Policy ที่ใช้จริง

[P00249 | 7319:7345 | NORMAL_TEXT]
คะแนนจาก Severity: [กรอก]

[P00250 | 7345:7372 | NORMAL_TEXT]
คะแนนจาก Frequency: [กรอก]

[P00251 | 7372:7402 | NORMAL_TEXT]
คะแนนจาก Scan History: [กรอก]

[P00252 | 7402:7428 | NORMAL_TEXT]
Threshold Monitor: [กรอก]

[P00253 | 7428:7459 | NORMAL_TEXT]
Threshold Web Redirect: [กรอก]

[P00254 | 7459:7490 | NORMAL_TEXT]
Threshold SSH Redirect: [กรอก]

[P00255 | 7490:7524 | NORMAL_TEXT]
Threshold Temporary Block: [กรอก]

[P00256 | 7524:7548 | NORMAL_TEXT]
ระยะเวลาหมดอายุ: [กรอก]

[P00257 | 7548:7549 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00258 | 7549:7566 | HEADING_2]
Action ที่รองรับ

[P00259 | 7566:7587 | NORMAL_TEXT]
• allow — [เงื่อนไข]

[P00260 | 7587:7610 | NORMAL_TEXT]
• monitor — [เงื่อนไข]

[P00261 | 7610:7646 | NORMAL_TEXT]
• redirect_web — [เงื่อนไข/Profile]

[P00262 | 7646:7674 | NORMAL_TEXT]
• redirect_ssh — [เงื่อนไข]

[P00263 | 7674:7714 | NORMAL_TEXT]
• temporary_block — [เงื่อนไข/ระยะเวลา]

[P00264 | 7714:7715 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00265 | 7715:7726 | HEADING_2]
ผลการทดสอบ

[P00266 | 7726:7758 | NORMAL_TEXT]
Event จำลองแต่ละ Protocol: [ผล]

[P00267 | 7758:7780 | NORMAL_TEXT]
Duplicate Event: [ผล]

[P00268 | 7780:7805 | NORMAL_TEXT]
Restart/Checkpoint: [ผล]

[P00269 | 7805:7824 | NORMAL_TEXT]
Log Rotation: [ผล]

[P00270 | 7824:7859 | NORMAL_TEXT]
Nginx Config ผิด: [ผลและ Rollback]

[P00271 | 7859:7899 | NORMAL_TEXT]
nftables Command ล้มเหลว: [ผลและ Retry]

[P00272 | 7899:7953 | NORMAL_TEXT]
สถานะ D6: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00273 | 7953:7980 | NORMAL_TEXT]
ไฟล์/โมดูลที่สร้าง: [กรอก]

[P00274 | 7980:8035 | NORMAL_TEXT]
หลักฐาน: [Unit Test, Decision Log และ Integration Log]

[P00275 | 8035:8055 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00276 | 8055:8141 | NORMAL_TEXT]
ข้อมูลที่ต้องรับจากคนที่ 2: Correlated Intelligence และ Profile Recommendation Schema

[P00277 | 8141:8142 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00278 | 8142:8168 | HEADING_1]
D7 Dashboard และ Baseline

[P00279 | 8168:8169 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00280 | 8169:8182 | HEADING_2]
วัตถุประสงค์

[P00281 | 8182:8259 | NORMAL_TEXT]
แสดงสถานะและผลการตัดสินใจของระบบ พร้อมเก็บ Baseline ที่ใช้ตรวจคุณภาพในเทอม 2

[P00282 | 8259:8260 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00283 | 8260:8270 | HEADING_2]
Dashboard

[P00284 | 8270:8285 | NORMAL_TEXT]
☐ Alert ล่าสุด

[P00285 | 8285:8310 | NORMAL_TEXT]
☐ Source IP และ Protocol

[P00286 | 8310:8341 | NORMAL_TEXT]
☐ SID, Severity และ Risk Score

[P00287 | 8341:8362 | NORMAL_TEXT]
☐ Action และ Profile

[P00288 | 8362:8379 | NORMAL_TEXT]
☐ Backend Status

[P00289 | 8379:8419 | NORMAL_TEXT]
☐ Suricata/Nginx/Decision Engine Status

[P00290 | 8419:8437 | NORMAL_TEXT]
☐ สรุปตามช่วงเวลา

[P00291 | 8437:8455 | NORMAL_TEXT]
☐ Export CSV/JSON

[P00292 | 8455:8475 | NORMAL_TEXT]
☐ Error/Empty State

[P00293 | 8475:8513 | NORMAL_TEXT]
☐ จำกัดการเข้าถึง Dashboard เฉพาะ Lab

[P00294 | 8513:8514 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00295 | 8514:8541 | HEADING_2]
Baseline อย่างน้อย 5 กลุ่ม

[P00296 | 8541:8583 | NORMAL_TEXT]
1. Benign Traffic: [จำนวน/แหล่งข้อมูล/ผล]

[P00297 | 8583:8622 | NORMAL_TEXT]
2. Known HTTP/HTTPS Attack: [จำนวน/ผล]

[P00298 | 8622:8658 | NORMAL_TEXT]
3. Known SSH/Scan Event: [จำนวน/ผล]

[P00299 | 8658:8702 | NORMAL_TEXT]
4. False-positive/Negative Case: [จำนวน/ผล]

[P00300 | 8702:8744 | NORMAL_TEXT]
5. Latency และ Resource Usage: [จำนวน/ผล]

[P00301 | 8744:8745 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00302 | 8745:8752 | HEADING_2]
Metric

[P00303 | 8752:8783 | NORMAL_TEXT]
Detection Accuracy: [สูตร/ค่า]

[P00304 | 8783:8815 | NORMAL_TEXT]
False Positive Rate: [สูตร/ค่า]

[P00305 | 8815:8847 | NORMAL_TEXT]
Decision Latency: [วิธีวัด/ค่า]

[P00306 | 8847:8879 | NORMAL_TEXT]
Redirect Latency: [วิธีวัด/ค่า]

[P00307 | 8879:8907 | NORMAL_TEXT]
CPU/RAM/Disk: [วิธีวัด/ค่า]

[P00308 | 8907:8908 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00309 | 8908:8962 | NORMAL_TEXT]
สถานะ D7: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00310 | 8962:8986 | NORMAL_TEXT]
ไฟล์และ Dataset: [กรอก]

[P00311 | 8986:9035 | NORMAL_TEXT]
หลักฐาน: [Screenshot, CSV/JSON และ Script คำนวณ]

[P00312 | 9035:9055 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00313 | 9055:9127 | NORMAL_TEXT]
ข้อมูลส่งต่อคนที่ 2: Baseline Version, Dataset และ Acceptance Threshold

[P00314 | 9127:9128 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00315 | 9128:9183 | HEADING_1]
D8 Validation, Deploy Rule และ Cross-protocol Feedback

[P00316 | 9183:9184 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00317 | 9184:9197 | HEADING_2]
วัตถุประสงค์

[P00318 | 9197:9299 | NORMAL_TEXT]
ตรวจ Candidate Rule ก่อน Deploy อัตโนมัติ มี Audit/Rollback และใช้ประวัติหลาย Protocol เพื่อปรับ Risk

[P00319 | 9299:9300 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00320 | 9300:9318 | HEADING_2]
Validation 5 ด่าน

[P00321 | 9318:9346 | NORMAL_TEXT]
1. Syntax Test — ผล: [กรอก]

[P00322 | 9346:9385 | NORMAL_TEXT]
2. Duplicate/Overlap Test — ผล: [กรอก]

[P00323 | 9385:9421 | NORMAL_TEXT]
3. Baseline Regression — ผล: [กรอก]

[P00324 | 9421:9454 | NORMAL_TEXT]
4. Malicious Replay — ผล: [กรอก]

[P00325 | 9454:9502 | NORMAL_TEXT]
5. Performance/False-positive Gate — ผล: [กรอก]

[P00326 | 9502:9503 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00327 | 9503:9511 | HEADING_2]
สถานะกฎ

[P00328 | 9511:9523 | NORMAL_TEXT]
☐ candidate

[P00329 | 9523:9534 | NORMAL_TEXT]
☐ approved

[P00330 | 9534:9545 | NORMAL_TEXT]
☐ rejected

[P00331 | 9545:9556 | NORMAL_TEXT]
☐ deployed

[P00332 | 9556:9570 | NORMAL_TEXT]
☐ rolled_back

[P00333 | 9570:9678 | NORMAL_TEXT]
Metadata ที่เก็บ: Rule ID, Version, Evidence, Confidence, Reviewer, Metric ก่อน/หลัง, เวลา Deploy และเหตุผล

[P00334 | 9678:9679 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00335 | 9679:9695 | HEADING_2]
Deploy Workflow

[P00336 | 9695:9730 | NORMAL_TEXT]
☐ รับ Candidate Package จากคนที่ 2

[P00337 | 9730:9753 | NORMAL_TEXT]
☐ ตรวจ Schema/Metadata

[P00338 | 9753:9770 | NORMAL_TEXT]
☐ รัน Validation

[P00339 | 9770:9792 | NORMAL_TEXT]
☐ สำรอง Rule ปัจจุบัน

[P00340 | 9792:9810 | NORMAL_TEXT]
☐ รัน suricata -T

[P00341 | 9810:9832 | NORMAL_TEXT]
☐ Activate และ Reload

[P00342 | 9832:9847 | NORMAL_TEXT]
☐ Health Check

[P00343 | 9847:9877 | NORMAL_TEXT]
☐ ตรวจ Alert Rate/Performance

[P00344 | 9877:9911 | NORMAL_TEXT]
☐ Rollback อัตโนมัติเมื่อผิดเกณฑ์

[P00345 | 9911:9930 | NORMAL_TEXT]
☐ บันทึก Audit Log

[P00346 | 9930:9931 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00347 | 9931:9951 | HEADING_2]
Cross-protocol Test

[P00348 | 9951:9995 | NORMAL_TEXT]
Scan → เพิ่ม Risk ของ HTTP ครั้งถัดไป: [ผล]

[P00349 | 9995:10039 | NORMAL_TEXT]
SSH → เปลี่ยน Profile/Action ของ HTTP: [ผล]

[P00350 | 10039:10080 | NORMAL_TEXT]
TLS/TCP Metadata → ปรับ Confidence: [ผล]

[P00351 | 10080:10112 | NORMAL_TEXT]
Expiration/Decay ของ Risk: [ผล]

[P00352 | 10112:10113 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00353 | 10113:10140 | HEADING_2]
HTTP Feedback Loop ขั้นต่ำ

[P00354 | 10140:10217 | NORMAL_TEXT]
Honeypot Evidence → Candidate Rule → Validation → Deploy → ตรวจจับครั้งถัดไป

[P00355 | 10217:10239 | NORMAL_TEXT]
ผล End-to-End: [กรอก]

[P00356 | 10239:10260 | NORMAL_TEXT]
Rule Version: [กรอก]

[P00357 | 10260:10277 | NORMAL_TEXT]
Evidence: [กรอก]

[P00358 | 10277:10278 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00359 | 10278:10332 | NORMAL_TEXT]
สถานะ D8: ☐ ยังไม่เริ่ม  ☐ กำลังทำ  ☐ ผ่าน  ☐ ไม่ผ่าน

[P00360 | 10332:10355 | NORMAL_TEXT]
ไฟล์และ Script: [กรอก]

[P00361 | 10355:10404 | NORMAL_TEXT]
หลักฐาน: [Validation Report, Audit Log และ PCAP]

[P00362 | 10404:10424 | NORMAL_TEXT]
ปัญหาคงค้าง: [กรอก]

[P00363 | 10424:10507 | NORMAL_TEXT]
ข้อมูลที่ต้องรับจากคนที่ 2: Candidate Rule, Metadata, Test PCAP และ Quality Report

[P00364 | 10507:10508 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00365 | 10508:10540 | HEADING_1]
Integration Test ร่วมกับคนที่ 2

[P00366 | 10540:10541 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00367 | 10541:10587 | HEADING_2]
Test Case 1 — Benign HTTP/HTTPS → Real Server

[P00368 | 10587:10626 | NORMAL_TEXT]
ผลที่คาดหวัง: ไม่ Redirect ไป Honeypot

[P00369 | 10626:10641 | NORMAL_TEXT]
ผลจริง: [กรอก]

[P00370 | 10641:10657 | NORMAL_TEXT]
หลักฐาน: [กรอก]

[P00371 | 10657:10658 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00372 | 10658:10699 | HEADING_2]
Test Case 2 — HTTP Attack → Web Honeypot

[P00373 | 10699:10747 | NORMAL_TEXT]
ผลที่คาดหวัง: Alert → Risk → Redirect → Web Log

[P00374 | 10747:10762 | NORMAL_TEXT]
ผลจริง: [กรอก]

[P00375 | 10762:10778 | NORMAL_TEXT]
หลักฐาน: [กรอก]

[P00376 | 10778:10779 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00377 | 10779:10813 | HEADING_2]
Test Case 3 — SSH Attack → Cowrie

[P00378 | 10813:10868 | NORMAL_TEXT]
ผลที่คาดหวัง: Alert/Policy → nftables → Cowrie Session

[P00379 | 10868:10883 | NORMAL_TEXT]
ผลจริง: [กรอก]

[P00380 | 10883:10899 | NORMAL_TEXT]
หลักฐาน: [กรอก]

[P00381 | 10899:10900 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00382 | 10900:10947 | HEADING_2]
Test Case 4 — Scan → Risk ของ Connection ถัดไป

[P00383 | 10947:11009 | NORMAL_TEXT]
ผลที่คาดหวัง: Scan Alert ไม่ Redirect กลาง Scan แต่เพิ่ม Risk

[P00384 | 11009:11024 | NORMAL_TEXT]
ผลจริง: [กรอก]

[P00385 | 11024:11040 | NORMAL_TEXT]
หลักฐาน: [กรอก]

[P00386 | 11040:11041 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00387 | 11041:11076 | HEADING_2]
Test Case 5 — Failure และ Recovery

[P00388 | 11076:11104 | NORMAL_TEXT]
กรณี Nginx Config ผิด: [ผล]

[P00389 | 11104:11127 | NORMAL_TEXT]
กรณี Backend ล่ม: [ผล]

[P00390 | 11127:11155 | NORMAL_TEXT]
กรณี Log ขาด/หมุนไฟล์: [ผล]

[P00391 | 11155:11190 | NORMAL_TEXT]
กรณี Decision Engine Restart: [ผล]

[P00392 | 11190:11221 | NORMAL_TEXT]
กรณี Rule Deploy ผิดพลาด: [ผล]

[P00393 | 11221:11222 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00394 | 11222:11246 | HEADING_1]
สรุปไฟล์ที่สร้างหรือแก้

[P00395 | 11246:11247 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00396 | 11247:11278 | NORMAL_TEXT]
• Network Config: [พาธ/Commit]

[P00397 | 11278:11310 | NORMAL_TEXT]
• Suricata Config: [พาธ/Commit]

[P00398 | 11310:11341 | NORMAL_TEXT]
• Suricata Rules: [พาธ/Commit]

[P00399 | 11341:11374 | NORMAL_TEXT]
• Nginx Config/Map: [พาธ/Commit]

[P00400 | 11374:11405 | NORMAL_TEXT]
• nftables Rules: [พาธ/Commit]

[P00401 | 11405:11437 | NORMAL_TEXT]
• Decision Engine: [พาธ/Commit]

[P00402 | 11437:11467 | NORMAL_TEXT]
• systemd Units: [พาธ/Commit]

[P00403 | 11467:11493 | NORMAL_TEXT]
• Dashboard: [พาธ/Commit]

[P00404 | 11493:11536 | NORMAL_TEXT]
• Validation/Deploy Pipeline: [พาธ/Commit]

[P00405 | 11536:11558 | NORMAL_TEXT]
• Tests: [พาธ/Commit]

[P00406 | 11558:11595 | NORMAL_TEXT]
• Experiments/Evidence: [พาธ/Commit]

[P00407 | 11595:11626 | NORMAL_TEXT]
• README/Runbook: [พาธ/Commit]

[P00408 | 11626:11627 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00409 | 11627:11644 | HEADING_1]
ปัญหาและการแก้ไข

[P00410 | 11644:11645 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00411 | 11645:11665 | HEADING_2]
ปัญหาที่ 1: [อาการ]

[P00412 | 11665:11680 | NORMAL_TEXT]
สาเหตุ: [กรอก]

[P00413 | 11680:11700 | NORMAL_TEXT]
วิธีตรวจสอบ: [กรอก]

[P00414 | 11700:11716 | NORMAL_TEXT]
วิธีแก้: [กรอก]

[P00415 | 11716:11734 | NORMAL_TEXT]
ผลหลังแก้: [กรอก]

[P00416 | 11734:11750 | NORMAL_TEXT]
หลักฐาน: [กรอก]

[P00417 | 11750:11751 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00418 | 11751:11771 | HEADING_2]
ปัญหาที่ 2: [อาการ]

[P00419 | 11771:11786 | NORMAL_TEXT]
สาเหตุ: [กรอก]

[P00420 | 11786:11806 | NORMAL_TEXT]
วิธีตรวจสอบ: [กรอก]

[P00421 | 11806:11822 | NORMAL_TEXT]
วิธีแก้: [กรอก]

[P00422 | 11822:11840 | NORMAL_TEXT]
ผลหลังแก้: [กรอก]

[P00423 | 11840:11856 | NORMAL_TEXT]
หลักฐาน: [กรอก]

[P00424 | 11856:11857 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00425 | 11857:11872 | HEADING_1]
สรุปผลปัจจุบัน

[P00426 | 11872:11873 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

[P00427 | 11873:11906 | NORMAL_TEXT]
ส่วนที่ทำเสร็จแล้ว: [กรอก D1–D8]

[P00428 | 11906:11936 | NORMAL_TEXT]
ส่วนที่กำลังดำเนินการ: [กรอก]

[P00429 | 11936:11963 | NORMAL_TEXT]
ส่วนที่ยังไม่เริ่ม: [กรอก]

[P00430 | 11963:11998 | NORMAL_TEXT]
ส่วนที่ติดข้อมูลจากคนที่ 2: [กรอก]

[P00431 | 11998:12031 | NORMAL_TEXT]
ส่วนที่ต้องปรึกษาอาจารย์: [กรอก]

[P00432 | 12031:12055 | NORMAL_TEXT]
Milestone ถัดไป: [กรอก]

[P00433 | 12055:12082 | NORMAL_TEXT]
วันที่อัปเดตล่าสุด: [กรอก]

[P00434 | 12082:12101 | NORMAL_TEXT]
ผู้ตรวจสอบ: [กรอก]

[P00435 | 12101:12102 | NORMAL_TEXT]
⟦EMPTY PARAGRAPH⟧

