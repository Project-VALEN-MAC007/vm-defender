# รายการกฎ Default: ET Open

ชุดเริ่มต้นประกอบด้วยกฎสำเร็จรูป 13 กฎ รวมใน `rules/et-open-selected.rules`
ไม่มีกฎเขียนเองเดิมในชุดนี้

| SID | ชื่อกฎ | เงื่อนไขสำคัญ |
|---|---|---|
| 2002677 | ET SCAN Nikto Web App Scan in Progress | User-Agent มี (Nikto และถึงเกณฑ์ 5 ครั้ง/60 วินาที |
| 2008538 | ET SCAN Sqlmap SQL Injection Scan | User-Agent เริ่มด้วย sqlmap |
| 2009359 | ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE) | User-Agent มี Nmap NSE |
| 2017616 | ET SCAN NETWORK Incoming Masscan detected | User-Agent เริ่มด้วย masscan/; ไม่ใช่กฎนับ SYN ทุกพอร์ต |
| 2031502 | ET INFO Request to Hidden Environment File - Inbound | URI ลงท้าย /.env |
| 2101071 | GPL WEB_SERVER .htpasswd access | URI มี .htpasswd |
| 2049400 | ET WEB_SERVER /etc/passwd Detected in URI | URI มี /etc/passwd; ไม่ยืนยันว่าอ่านไฟล์สำเร็จ |
| 2006446 | ET WEB_SERVER Possible SQL Injection Attempt UNION SELECT in HTTP URI | รูปแบบ UNION SELECT ใน URI |
| 2053468 | ET WEB_SERVER Possible SQL Injection UNION SELECT in HTTP Request Body | รูปแบบ UNION SELECT ใน request body |
| 2001219 | ET SCAN Potential SSH Scan | SYN ไปพอร์ต 22 ถึงเกณฑ์ 5 ครั้ง/120 วินาที |
| 2006546 | ET SCAN LibSSH Based Frequent SSH Connections Likely BruteForce Attack | ลักษณะ banner ของ libssh และถึงเกณฑ์ 5 ครั้ง/30 วินาที |
| 2101251 | GPL TELNET Bad Login | คำตอบ Login incorrect จากพอร์ต 23 |
| 2100492 | GPL TELNET TELNET login failed | คำตอบ Login failed จากพอร์ต 23 |

## ความต่างจากกฎเดิมที่ตัดออก

- มีตัวแทนสำหรับ sqlmap, Nikto, .env, .htpasswd และการเชื่อมต่อ SSH ถี่
  แต่เงื่อนไขและ threshold ต่างจากกฎที่เขียนเอง
- /etc/passwd ใน URI ครอบคลุมตัวอย่างอ่านไฟล์เดิมบางส่วน ไม่ใช่การตรวจ
  Path Traversal ทั่วไปทุกแบบ
- ยังไม่พบกฎตรงสำหรับ Nuclei User-Agent, /.git/config, /.svn/entries,
  TLS 1.0/1.1 ที่เจรจาสำเร็จ, Telnet SYN burst และ SYN burst ทุกพอร์ต
  ในกฎเปิดใช้ของ ET Open snapshot ที่ตรวจ ไม่อ้างว่าชุดนี้ทดแทนครบ 11 กฎ
- กฎ Telnet ตรวจข้อความ login ไม่สำเร็จ ไม่ใช่จำนวนครั้งที่พยายามเชื่อมต่อ
- กฎหลายรายการอาจตรงคำขอเดียวกัน ต้องตรวจผลต่อคะแนนสะสมของ engine

## ที่มา

คัดจาก [ET Open สำหรับ Suricata 7.0.3](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz)
เมื่อ 2 ตุลาคม 2026 โดยคงข้อความกฎ SID และ revision เดิม มีไฟล์ต้นทางและ
SHA-256 ของแต่ละกฎใน `et-open-manifest.json` และ license ใน `licenses/`
ไฟล์นี้เป็น snapshot; suricata-update ไม่อัปเดตไฟล์ใน repository โดยอัตโนมัติ
เมื่ออัปเดตต้องตรวจ SID, revision, dependency และทดสอบอีกครั้ง

## ข้อความสำหรับรายงาน

ระบบใช้ชุดกฎสำเร็จรูป Emerging Threats Open เป็นกฎเริ่มต้น โดยเลือกกฎตรวจจับ
การสแกนเว็บ การโจมตี SQL Injection การเข้าถึงไฟล์สำคัญ การเชื่อมต่อ SSH
ที่ผิดปกติ และการเข้าสู่ระบบ Telnet ที่ไม่สำเร็จ เพื่อส่งข้อมูลให้ Decision Engine
ประเมินความเสี่ยงและเลือกเส้นทางตามเกณฑ์ที่กำหนด

## การปรับกฎ 2006546 (TRAP)

กฎต้นฉบับ rev 9 ใช้ `content:"SSH-"; content:"libssh"; within:20;` บน stream ดิบ
ซึ่งไม่เกิด alert บน Suricata 7.0.3 แม้ pcap (`ssh-retest.pcap`) จะมี banner
`SSH-2.0-libssh_0.10.6` ครบ 6 ครั้ง TRAP จึงเปลี่ยนเป็น `ssh.software; content:"libssh"; nocase;`
ซึ่งตรวจชื่อซอฟต์แวร์ client ที่ parser SSH แยกไว้แล้ว คง SID, msg, threshold
(5 ครั้ง/30 วินาที by_src) และ classtype เดิม เปลี่ยนเป็น rev 10 และติด metadata
`trap_adapted ssh_software_buffer` รายละเอียดใน `et-open-manifest.json`
