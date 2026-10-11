# TRAP Deployment and VM Retest Report

วันที่ 10 ตุลาคม 2026 — test-start **2026-10-10T08:01:23Z** (15:01:23 เวลาไทย). รายงานนี้ครอบคลุมเฉพาะ 4 จุดที่เคย FAIL และ regression HTTP/HTTPS/SSH/Telnet ตามคำขอรอบนี้.

ผลสุดท้าย: **4 จุดที่แก้ผ่านทั้งหมด และ regression ทั้ง 4 แบบผ่าน**. Unit tests รันใน Defender VM ผ่าน **109/109**. มี11บันทึกการทดลอง: 10PASS และ1FAILของ HTTPS ครั้งแรก; ผลทดสอบซ้ำ HTTPS เป็นPASSด้วยIPใหม่. ไม่ลบหรือเปลี่ยนสถานะหลักฐานครั้งแรก.

## Source และ deployment

Source C:\Users\Yakult\Documents\GitHub\vm-defender, commit `79ce4a18b25ccdb6f3da65d8eb4398dc76e7c572`. Sync tracked source ไป `/opt/trap` เฉพาะ Defender. ตรวจ unit tests ใน VM แล้วรัน `sudo sh /opt/trap/deploy/install-dashboard-helpers.sh --update-rules`. ใช้ Suricata7.0.3 และ active rules `/etc/suricata/rules/et-open-selected.rules`.

Installer ตั้ง `rules.apply_dir=/var/lib/trap/rules`, ติดตั้ง trap-apply-rules.path/.service, เพิ่ม `thresholds_path=/var/lib/trap/engine/thresholds.json` และ `scan_only_signatures=[2017616]`. Initial helper result `state=applied`; trap-apply-rules.path active. Active SID2006546 มี ssh.software/content libssh/nocase/rev10. Installer แก้ /etc config เพื่อกำหนด override path; การเทียบ “/etcไม่เปลี่ยน” เริ่มหลัง installer เสร็จ.

Unit tests มี ResourceWarning ของ socket และ log threshold_reload_failed จาก negative testcase แต่จบ OK109 tests. ดู unit-tests.txt.

## ขอบเขตเครือข่ายและการแยกรอบ

ทดสอบจาก `sudo ip netns exec trap-attacker ...` เข้า **192.168.56.10 เท่านั้น**. Namespace มี routeเฉพาะ192.168.56.0/24 ไม่มีdefault route. ใช้ IPใหม่ .101–.110; HTTPSซ้ำใช้ .111. ก่อนเพิ่ม IP ตรวจว่าไม่มีใน EVE, decision, Cowrie และ Web log เดิม. HTTP→10.10.10.2:8084; SSH/Telnet→10.10.10.2:2222/2223 ผ่าน internal network. NATของVMยังใช้บริหารเครื่อง ไม่ใช่ air-gap ทั้งVM.

Raw logs ในชุดหลักฐานคัดด้วย timestamp/start_time >= test-start โดยแปลง timezoneเป็นinstantเดียวกัน. Suricata/Nginxเขียน+0700, Decision/Cowrie/Webใช้UTC. Telnet response alert ใช้dest_ipเพื่อเชื่อมกลับattacker; จึงไม่กรองเฉพาะsrc_ip.

## ตารางผล

| Test | Source IP | Actual | Result |
|---|---|---|---|
| FAIL1-LibSSH-handshakes | 192.168.56.101 | SID2006546 rev10 มี alert; risk80 redirect_ssh (ก่อนหน้า2001219 risk35 monitor) | PASS |
| FAIL1-Hydra | 192.168.56.102 | SID2006546 มี alert; risk80 redirect_ssh | PASS |
| FAIL2-Masscan-scan-only-and-followup | 192.168.56.103 | Masscan monitor ทั้ง3: risk37,73.99,100 พร้อม reason; SID2101071 จาก IP เดิม risk100 redirect_web | PASS |
| FAIL3-Rule-approve-activate-alert-restore | 192.168.56.104,192.168.56.110 | API save/approve200; helper applied; probe SID9900001 alert; restore applied; IP ใหม่ยิงซ้ำไม่เกิด alert | PASS |
| FAIL3-Invalid-rule-rejected-active-unchanged |  | POST rules/change200 staging; helper failed ที่ syntax_test; SHA256 active ก่อน/หลังเท่ากัน; restore applied | PASS |
| FAIL4-Threshold-API-reload-and-User-denied | 192.168.56.105 | POST200 high5/90 → .env monitor17; low5/10 → .htpasswd redirect_web56.99; thresholds.json={5,10}; /etc hashเดิม; User403; คืน15/40 | PASS |
| Regression-HTTP | 192.168.56.106 | HTTP200; Web log source .106; redirect_web risk50 | PASS |
| Regression-HTTPS | 192.168.56.107 | HTTP200 แต่ Nginx upstream127.0.0.1:8080 profile real; ไม่พบ requestในHoneypot log (ครั้งแรก) | FAIL (initial; retest PASS) |
| Regression-SSH | 192.168.56.108 | source .108; SSH scan risk35 redirect_ssh; Cowrie บันทึก whoami,ls,uname -a; shell exit0 | PASS |
| Regression-Telnet | 192.168.56.109 | source .109; SID2101251 risk35/69.97 redirect_telnet; Cowrie มีlogin.failed; nft counterDNAT | PASS |
| Regression-HTTPS-retest | 192.168.56.111 | source .111; TLS200; Nginx profile rabbithole upstream10.10.10.2:8084; Honeypot protocolhttps/queryตรงกัน | PASS |

คำสั่งและpayload APIครบอยู่ใน TRAP-Test-Matrix.csv และ commands.json/api.json. การLogin/TOTPใช้บัญชีจริง trapadmin/trapuser; ตัดpassword/challenge/TOTP/secretออกจากหลักฐาน.

## หลักฐานการแก้แต่ละจุด

1. **LibSSH:** source.101 ทำ6 Paramiko handshakesด้วยbanner SSH-2.0-libssh_0.10.6; source.102ยิงHydra. ทั้งสองได้ SID2001219 monitor35 แล้ว SID2006546 redirect_ssh80. มี pcapและ SSH telemetryของParamiko. ไม่ต้องใช้offline replayเพราะliveSID2006546ผ่านแล้ว. Hydraนี้ตรวจalert/decision; การพิสูจน์DNAT+CowrieทำในSSH regressionแยกต่างหาก.

2. **Scan-only:** Dashboardตั้งmonitor5/redirect10 (ต้องmonitorต่ำกว่าredirect). Masscan source.103 เกิด3decisions monitorทั้งหมด รวมscore100; reasonมีscan_only_policy:monitor. จากIPเดิม .htpasswdให้redirect_web100. SID2001219ยังredirectSSHได้ตามข้อกำหนด ไม่จัดเป็นscan-only.

3. **Rule activation:** เพิ่มcandidateSID9900001ผ่านDashboardและapprove. pathunitเรียกhelper, resultapplied, activeมีSID, URI /trap-retest-probeเกิดalertจริง. restoreจากDashboardแล้วresultapplied, SIDหายจากactive; ยิงURIด้วยIPใหม่.110ไม่เกิดSID. สำหรับกฎผิดใช้unknownkeywordที่ผ่านstructuralcheckของDashboardแต่Suricataปฏิเสธ: helper resultfailed/step syntax_test; activeSHA256ไม่เปลี่ยน. จากนั้นrestoreกลับapplied. การPOST200หมายถึงรับstaging; ต้องดูresulthelperเพื่อรู้ผลdeploy.

Hash activeก่อน/หลังinvalid rule: `049a99cf7e216ef541d33159708c0108816c4c71d46e14555889bb8effbd5b8a` (เท่ากัน).

4. **Threshold:** MasterAdmin+TOTP POST200: threshold5/90ให้.env monitor17; เปลี่ยน5/10แล้วdecisionถัดไป .htpasswd redirect_web56.99. อ่านoverridefileยืนยัน5/10. UserPOSTถูก403. คืนthreshold15/40ตอนจบ.

Hash `/etc/adaptive-defender/live.json` ก่อน/หลังAPI: `55e3ceae361ff15685af249e2c38b23e841deab020f26e7f51d2a3d58f655f9b` (เท่ากัน). เก็บไฟล์หลังคืนค่าในraw/thresholds.json.

## HTTPS ครั้งแรกและการทดสอบซ้ำ

source.107 มี redirect_webdecisionแล้ว แต่ request HTTPSครั้งแรกได้HTTP200จากReal: Nginx profile=real, upstream127.0.0.1:8080 และไม่มีrequestนี้ในHoneypot. จึงบันทึกFAILตามข้อเท็จจริง. Adapterใช้systemctl reload nginx ซึ่งสั่งreloadโดยไม่ตรวจว่าworkerใหม่รับrequestแล้ว; หลักฐานแสดงช่วงเวลานี้ยังไปReal. รายงานไม่สรุปว่าHTTPSเสียถาวรหรือlogsyncเสีย.

ใช้sourceใหม่.111 ยืนยันredirectdecisionแล้วรอ2วินาทีก่อนTLSrequest. ผลNginxprofile=rabbithole/upstream10.10.10.2:8084, HTTP200 และHoneypotlog protocol=https/source/queryตรงกัน. จึงให้finalregressionHTTPSเป็นPASS. ระบบยังไม่มีreadinessbarrierยืนยันworkerใหม่; ถ้าข้อกำหนดต้องredirectทันทีหลังdecision ควรเพิ่มการตรวจความพร้อมและทดสอบความหน่วงแยกต่างหาก.

## พิสูจน์ข้าม VM และสถานะส่งมอบ

HTTPsource.106และHTTPSsource.111มีNginxaccessและWebHoneypotlogตรงกัน. SSHsource.108ใช้SID2001219redirectแล้วCowrieบันทึกlogin+whoami/ls/uname -a. Telnetsource.109ใช้fixtureตอบLoginincorrectครั้งแรกเพื่อtriggerก่อนDNAT; ครั้งถัดไปCowrieบันทึกbadlogin. nftcountersสำหรับSSH/Telnetเพิ่มจริง. ดูraw/nft.txtและcases.json.

Cowrie/WebบนHoneypotactive. SHA256ของlogต้นทางตรงกับสำเนาที่syncมายังDefenderก่อนคัดเฉพาะรอบ; ดูdefender-sync-hashes.jsonและoperation honeypot-final. Suricata/Nginx/DecisionEngine/Dashboard/pathunit/logsynctimeractive; nginx-tผ่าน. Finalrulehelperappliedและไม่มีSID9900001/9900002ในactive. threshold15/40; expiry120วินาทีตามlabเดิม. ฟังก์ชันblockยังไม่มี.

## ไฟล์หลักฐาน

- `TRAP-Retest-Evidence/20261010T080123Z/cases.json`: ผลทุกการทดลอง รวมHTTPSครั้งแรกและครั้งซ้ำ
- `api.json`, `commands.json`: คำสั่ง/API/status/ผลจริง; `raw/`: logหลังtest-startทั้งสองฝั่ง
- `unit-tests.txt`, `install-helpers.txt`, `raw/helper-journal.txt`, `raw/result.json`: ผลunit/deploy/helper
- `libssh-retest.pcap`, `libssh-telemetry.json`: หลักฐานSSH; `source-manifest.json`: sourcehashและcommit
- `SHA256SUMS.txt`: hashไฟล์หลักฐาน; zipไม่มีDashboardcredentials/TOTPsecret
- รายงานรอบเดิมเก็บในPrevious-Reports; ไม่รวมเคสเดิมอื่นในคะแนนรอบนี้

การทดสอบนี้พิสูจน์พฤติกรรมในlabตามเคสที่ระบุ ไม่ได้ทดสอบreboot/load/productionreadinessหรือความหน่วงredirectทุกสถานการณ์.
