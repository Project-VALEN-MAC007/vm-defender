# TRAP — รายงานทดสอบระบบ 3 เครื่อง รอบ 4

```text
ผู้ใช้ปกติ / attacker (trap-attacker; ไม่มี default route)
  -> 192.168.56.10 [Project-Defender]
       Suricata -> Decision Engine -> Nginx / nftables
       inner 10.10.10.1 / Project-Lab
       ├─ ความเสี่ยงต่ำ -> Project-Web 10.10.10.3
       │                    WordPress 8080 / OpenSSH 22 / Telnet 23
       └─ redirect -> Project-Honeypot 10.10.10.2
                            Web/Rabbit Hole 8084 / Cowrie SSH 2222 / Telnet 2223
```

| VM | IP lab | NAT SSH บน Windows | บริการที่ตรวจจากเครื่องจริง |
|---|---|---|---|
| Project-Defender | 192.168.56.10 (trap-out), 10.10.10.1 (enp0s8) | 127.0.0.1:2221 | Suricata, adaptive-defender, Nginx 80/443, Dashboard 9090, rule helper, log sync timer |
| Project-Honeypot | 10.10.10.2 | 127.0.0.1:2222 | Cowrie 2222/2223, Web/Rabbit Hole 8084 |
| Project-Web | 10.10.10.3 | 127.0.0.1:2223 | Ubuntu 24.04, 2 GB RAM / 2 vCPU, WordPress/MariaDB Compose 8080, OpenSSH 22, inetutils-telnetd 23 /bin/login |

Test-start UTC: `2026-10-10T09:13:13Z`. Evidence: `round4-20261010T091313Z`. ผลใน matrix ใช้ start_time ตั้งแต่ test-start; การยิงทั้งหมดไป 192.168.56.10 ใน namespace ที่ไม่มี default route เท่านั้น. Source IP ใหม่ตรวจจาก log ก่อนใช้ และบันทึกใน source-ips.json.

ผลรวมรายการตรวจ: FAIL 1, PASS 49, SUPERSEDED 5. SUPERSEDED คือผลตัวตรวจครั้งแรกที่เก็บไว้ แล้วมีผลตรวจซ้ำแยกต่างหาก ไม่ได้นับซ้ำเป็นการผ่าน.

## การติดตั้งและ routing

ใช้ VM เว็บที่ติดตั้งไว้ต่อ เปลี่ยนชื่อ Project-Web เพิ่ม RAM/CPU ตามงาน และใช้ production/docker-compose.yml จาก repo. สร้าง .env รหัสสุ่มบน VM สิทธิ์ 600; ไม่ commit และไม่รวมในรายงาน/zip. WordPress ติดตั้งแล้ว มีหน้า Welcome/About/Contact, ข่าว, static file, ฟอร์ม และบัญชี normaluser กับ trapwpadmin. SSH/Telnet ใช้บัญชี webadmin. ข้อมูลลับอยู่บน VM เท่านั้น.

Nginx render จาก template ให้ real/default เป็น 10.10.10.3:8080; HTTP listener ใน lab proxy โดยตรงเพื่อแยกทดสอบ HTTP/HTTPS. TLS จบที่ Defender. nftables render จาก template โดยกฎ Cowrie อยู่ก่อน production DNAT 22/23. ผ่าน nginx -t และ nft -c -f ก่อน apply; ตั้ง rollback timer ระหว่าง apply แล้วหยุดหลังตรวจสำเร็จ. ไม่มี source NAT บน Defender. Route กลับ 192.168.56.0/24 ผ่าน 10.10.10.1 อยู่ใน Netplan ของ Web/Honeypot.

เว็บ local trap-real-web บน Defender ถูก disable/stop; ไม่ลบ fixture. หลัง apply ไม่พบ listener local 8080/23. Management NAT SSH 2221 ยังเข้าถึงได้. Web VM ปิด Nginx หน้า placeholder เดิม ใช้ WordPress Compose แทน. มี Compose override เฉพาะ VM สำหรับ URL HTTP/HTTPS ตาม Host ที่อนุญาต และ access log ที่เก็บ X-Forwarded-For. หน้า form ทดสอบเป็น endpoint POST บนเว็บจริง.

ไม่ได้แก้ Decision Engine ในงานรอบ 4; SHA256 ก่อน/หลังอยู่ใน engine-before.sha256 และ Defender-health.json. ไม่ได้ commit. แก้เอกสาร repo 3 ไฟล์: defender/network/topology.md, defender/nginx/README.md, defender/nftables/README.md. รายการ git ที่มีอยู่ก่อนเริ่มงานเก็บแยกจากการแก้รอบนี้.

## Traffic ปกติ

HTTP และ HTTPS ทดสอบหน้าแรก/หน้าอื่น/static/search, WordPress login ด้วยรหัสถูก และส่งฟอร์ม. Nginx profile real/upstream 10.10.10.3:8080; Web access log ยืนยัน request/X-Forwarded-For. SSH webadmin รัน hostname/whoami/pwd/id และ auth log ของ Web ยืนยัน source IP. Telnet login แล้วรัน hostname/whoami/pwd; การตรวจซ้ำยืนยัน /bin/login session บน Web และ packet summary source -> 10.10.10.3:23 โดยไม่เก็บ payload รหัสผ่าน.

ตัวตรวจ Telnet ครั้งแรกอ่าน journal เฉพาะ ssh/inetd จึงไม่พบ login process ที่อยู่ใน session scope และ last ไม่มีรายการ. เก็บ FAIL เดิมไว้ แล้วตรวจซ้ำจาก IP ใหม่ด้วย journal ของ login และ packet summary ผ่าน. ไม่แก้กฎ IDS เพื่อทำให้ traffic ปกติผ่าน.

## False positive

พบ alert จาก IP traffic ปกติ 0 รายการ (ตรวจทั้ง src_ip และ dest_ip). ไม่มี decision redirect หรือ Honeypot event จาก IP ปกติในเคสที่ผ่าน.

## Regression และกฎ ET Open

ตรวจพบ/ได้ decision ที่คาด 12/13 กฎ. SID 2101251 เกิดจาก Login incorrect ของ telnetd จริง. เคส SID 2100492 ไม่พบ alert/decision และ reply ที่ตัวตรวจอ่านหลังรอ 4 วินาทีมีเพียง CRLF จึงไม่มีหลักฐาน Login failed ใน capture นี้. ไม่สรุปว่า telnetd ไม่มีทางตอบข้อความนี้ หรือระบุสาเหตุของการไม่เห็นข้อความเกินหลักฐาน. รายงานเป็น FAIL ของกรณีตรวจ SID นี้บนบริการจริง ไม่ใช้ fixture เพื่ออ้าง PASS. หลักฐาน 2100492-real-telnet.json และ auth log. Masscan SID 2017616 ได้ monitor ตาม scan-only policy.

แสดงทั้งก่อนและหลัง threshold ด้วย source เดิมใน HTTP/SSH: ก่อนถึงเกณฑ์ถึง Web จริง หลังถึงเกณฑ์ถึง Web Honeypot/Cowrie. HTTP/HTTPS/SSH/Telnet redirect ข้าม VM และ Rabbit Hole Web/SSH อยู่ใน matrix พร้อม origin log. ค่าทดสอบ threshold ชั่วคราวคืนเป็น monitor 15 / redirect 40.

Immediate redirect HTTP 5 + HTTPS 5: 10/10 ผ่านจาก request เดิม. ไม่มี sleep หลังอ่าน redirect_web decision ก่อนส่ง request. nginx_ready=true ทุก decision; nginx_ready_seconds min=0.156, median=0.161, max=0.178 วินาที.

บางเคสตัวตรวจไม่พบ event ในสำเนา Honeypot ที่ Defender อ่านทันที จึงเก็บ FAIL ไว้. final-verification.json เทียบ request เดิมกับ log ต้นทาง Honeypot + Nginx source/query/upstream/status200 และ Cowrie command โดยไม่ยิงซ้ำแทน request นั้น. เฉพาะเคสที่มีหลักฐานครบจึงเป็น final PASS.

## Dashboard

ตรวจ notification read/unread/delete/filter/latest/oldest; Master สร้างบัญชี ทดสอบ weak password, แก้ชื่อ เปลี่ยน role ลบ; User ถูกปฏิเสธการสร้างบัญชี. เปลี่ยนรหัสของ User/Master แล้ว session เดิมเข้าถึง API ที่ต้อง login ได้ 401 และ login ด้วยรหัสใหม่ผ่าน ก่อนคืนรหัสเดิม. ค่าเฉลี่ย dwell แยก profile และ CSV ตรงกับ analytics; snapshot อยู่ใน dashboard-report.json/csv.

ตัวตรวจรหัสผ่านครั้งแรกคาด /api/session.json ต้องตอบ 401 แต่ API นี้ตอบ 200 พร้อม session=null ตามโค้ด จึงเกิด FAIL ของตัวตรวจ. คืนบัญชีทดสอบแล้วใช้ /api/alerts.json ที่ต้อง login ตรวจซ้ำผ่าน. ผลและการกู้คืนบัญชีทดสอบยังเก็บไว้; ไม่แก้ implementation Dashboard เพื่อให้ผ่าน.

## Reboot / Flush

ผล boot IDs, service/containers กลับมาเอง, threshold persistence และ traffic ใหม่หลังบูตอยู่ใน matrix/boot-before.json. ไม่สั่ง start service เพื่อกลบผลหลัง reboot. Flush ทดสอบหลังเก็บหลักฐานทั้งหมด และสำรอง raw logs เป็นไฟล์ private บน Defender ก่อน; รายงาน/zipมีเฉพาะข้อมูลที่ตัดรหัสผ่าน/secretออก. ผลการยืนยัน FLUSH+TOTP อยู่ในเคสสุดท้ายและ preflush-backup-manifest.json.

## ข้อจำกัดและหลักฐาน FAIL

Web VM มี kernel soft lockup ระหว่างรอบ และ host มี RAM ว่างต่ำใน snapshot ที่ตรวจ. เก็บ Web-console.txt และ health/log ไว้; ไม่สรุปว่า RAM เป็นสาเหตุของ soft lockup เพราะยังไม่ได้พิสูจน์ causal link. สั่ง memory balloon 384 MB ชั่วคราวต่อ VM ระหว่างการทดสอบ แล้วคืนเป็น 0 หลังจบ; RAM ที่ตั้งใน VM Web เป็น 2 GB.

มีชุดทดสอบเริ่มก่อน apply routing ใหม่เพราะ placeholder ในคอมเมนต์ทำให้ render assertion หยุด. หยุดชุดแรก เก็บ pre-routing-audit/ แล้ว apply สำเร็จและใช้ source IP ใหม่ทั้งหมดในการทดสอบชุดหลัก. ชุดแรกไม่ได้ใช้แทนผลสถาปัตยกรรม 3 เครื่อง.

รายงานรอบ 3 ย้ายไป Previous-Reports/round3-20261010T083043Z-before-round4 และตรวจ SHA256/การมีอยู่หลังย้าย. หลักฐาน raw ที่มีข้อมูลรับรองการเข้าใช้งานเก็บแบบ private บน VM; ไม่ใส่ password, TOTP secret, .env, auth cookies ในรายงานหรือ zip. ดู manifest.json สำหรับ SHA256 ของไฟล์หลักฐานที่ส่งมอบ.

## รายการทดสอบ

| Case | Final | Initial | IP |
|---|---|---|
| Normal-Web-HTTP | PASS | PASS | 192.168.56.71 |
| Normal-Web-HTTPS | PASS | PASS | 192.168.56.72 |
| Normal-SSH | PASS | PASS | 192.168.56.73 |
| Normal-Telnet | PASS | FAIL | 192.168.56.74 |
| Transition-HTTP-production-to-Honeypot | PASS | PASS | 192.168.56.75 |
| Transition-SSH-production-to-Cowrie | PASS | PASS | 192.168.56.76 |
| ET-sqlmap | PASS | PASS | 192.168.56.77 |
| ET-Nikto | PASS | PASS | 192.168.56.78 |
| ET-Nmap | PASS | PASS | 192.168.56.79 |
| ET-Masscan | PASS | PASS | 192.168.56.80 |
| ET-UNION-URI | PASS | PASS | 192.168.56.81 |
| ET-UNION-body | PASS | PASS | 192.168.56.82 |
| ET-passwd | PASS | PASS | 192.168.56.83 |
| ET-env | PASS | PASS | 192.168.56.84 |
| ET-htpasswd | PASS | PASS | 192.168.56.85 |
| ET-SSH-scan | PASS | PASS | 192.168.56.86 |
| ET-LibSSH | PASS | PASS | 192.168.56.87 |
| ET-Telnet-real-Login-incorrect | PASS | PASS | 192.168.56.88 |
| ET-Telnet-real-Login-failed | FAIL | FAIL | 192.168.56.89 |
| Immediate-HTTP-1 | PASS | PASS | 192.168.56.90 |
| Immediate-HTTP-2 | PASS | FAIL | 192.168.56.91 |
| Immediate-HTTP-3 | PASS | FAIL | 192.168.56.92 |
| Immediate-HTTP-4 | PASS | FAIL | 192.168.56.93 |
| Immediate-HTTP-5 | PASS | FAIL | 192.168.56.94 |
| Immediate-HTTPS-1 | PASS | FAIL | 192.168.56.95 |
| Immediate-HTTPS-2 | PASS | FAIL | 192.168.56.96 |
| Immediate-HTTPS-3 | PASS | FAIL | 192.168.56.97 |
| Immediate-HTTPS-4 | PASS | PASS | 192.168.56.98 |
| Immediate-HTTPS-5 | PASS | PASS | 192.168.56.99 |
| Redirect-HTTP | PASS | FAIL | 192.168.56.100 |
| Redirect-HTTPS | PASS | FAIL | 192.168.56.112 |
| Redirect-SSH | PASS | FAIL | 192.168.56.113 |
| Redirect-Telnet | PASS | PASS | 192.168.56.114 |
| Rabbit-Hole-Web | PASS | PASS | 192.168.56.115 |
| Rabbit-Hole-SSH | PASS | PASS | 192.168.56.116 |
| Dashboard-Rule-apply-restore | PASS | PASS | 192.168.56.117,192.168.56.118 |
| Dashboard-Invalid-rule-safe-reject | PASS | PASS |  |
| Dashboard-Threshold-TOTP-roles | PASS | PASS | 192.168.56.119 |
| Normal-Telnet-auth-and-source-proof-retest | PASS | PASS | 192.168.56.120 |
| Dashboard-Notifications-read-unread-delete-filter-order | SUPERSEDED | PASS |  |
| Dashboard-Master-user-lifecycle-policy | SUPERSEDED | PASS |  |
| Dashboard-Self-password-change-trapuser | SUPERSEDED | FAIL |  |
| Dashboard-Self-password-change-trapadmin | SUPERSEDED | FAIL |  |
| Dashboard-Report-dwell-by-profile-CSV | SUPERSEDED | FAIL |  |
| Dashboard-Notifications-read-unread-delete-filter-order | PASS | PASS |  |
| Dashboard-Master-user-lifecycle-policy | PASS | PASS |  |
| Dashboard-Self-password-change-trapuser | PASS | PASS |  |
| Dashboard-Self-password-change-trapadmin | PASS | PASS |  |
| Dashboard-Report-dwell-by-profile-CSV | PASS | PASS |  |
| Reboot-all-three-services-containers-thresholds | PASS | PASS |  |
| Postboot-Normal-Web-HTTPS | PASS | PASS | 192.168.56.121 |
| Postboot-Normal-SSH | PASS | PASS | 192.168.56.122 |
| Postboot-Redirect-HTTP | PASS | PASS | 192.168.56.123 |
| Postboot-Redirect-SSH | PASS | PASS | 192.168.56.124 |
| Dashboard-Flush-final-step-backup-confirmation-TOTP | PASS | PASS |  |

FAIL `ET-Telnet-real-Login-failed`: AssertionError: Real telnetd response did not trigger SID 2100492; see captured reply and production auth log. หลักฐาน `cases.json`.
