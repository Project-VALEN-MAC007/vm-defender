# TRAP Round 3 — System Deployment, Readiness and Reboot Tests

ทดสอบ10ตุลาคม2026; test-start **2026-10-10T08:30:43Z** (15:30:43เวลาไทย). ใช้เฉพาะtrafficเข้า192.168.56.10ในlabเดิม. รายงานนี้สรุปทั้งระบบตามขอบเขตรอบ3 ไม่รวมคะแนนจากรอบก่อน.

ผลสุดท้ายจากการเทียบหลักฐานจริง **47/47 รายการ PASS, 0 FAILคงเหลือ**. Unit testsในDefenderผ่าน **113/113**. Immediate HTTPS10และHTTP10ผ่าน **20/20**; ET Openผ่าน **13/13**; timeout, redirect4แบบ, Rabbit Hole2แบบ, Dashboardและrebootผ่าน.

ตัวตรวจครั้งแรกบันทึกFAIL 13 รายการเพราะยังหาrequestในสำเนาHoneypotlogบนDefenderไม่พบ. เก็บสถานะ/errorเดิมในcases.jsonและcases-initial-checks.json. หลังจบtrafficอ่านlogต้นทางและบังคับsyncใหม่ พบrequestเดิมครบโดยไม่ยิงซ้ำ; final-verification.jsonแสดงผลcorrelationแยกจากสถานะเดิม. ไม่มีImmediate requestใดไปRealในNginxlog. รายงานไม่ลบหลักฐานFAILหรืออ้างว่าตัวตรวจครั้งแรกผ่านทั้งหมด.

## Source และ deployment

Source `C:\Users\Yakult\Documents\GitHub\vm-defender` syncไป`/opt/trap`บนDefender. Basecommit `79ce4a18b25ccdb6f3da65d8eb4398dc76e7c572` มีการแก้working treeของNginxreadiness; source-manifest.jsonบันทึกSHA256เนื้อหาไฟล์ที่deployจริง จึงไม่อ้างว่าcommitอย่างเดียวแทนไฟล์ที่แก้. รันunitในVMแล้วrestartadaptive-defender.

`/run/nginx.pid`มีอยู่; engineรันrootและอ่าน/proc/workerได้. systemdProtectProc=default, ProcSubset=all. เพิ่มworker_pid=$pidและmsec=$msecในNginxaccesslogชั่วคราวระหว่างทดสอบ แล้วคืนconfigเดิมและผ่านnginx-tหลังจบ. NginxReloaderตรวจworkerใหม่และworkerเก่าหาย/กำลังshuttingdownก่อนเขียนauditdecision.

## Immediate redirect และสถิติ readiness

HTTPS10ครั้งsource.130–.139; HTTP10ครั้งsource.140–.149. ยิง/.htpasswdเพื่อtrigger แล้วอ่านdecisionแบบtailจากoffsetก่อนtrigger. ทันทีที่พบredirect_webของIPนั้นเรียกcurlrequestถัดไป ไม่มีsleepหรือรอเพิ่มหลังเห็นdecision. ทุกdecisionnginx_ready=true; ทุกrequestHTTP200, profilerabbithole, upstream10.10.10.2:8084 และมีWebHoneypotrequestจริง. บันทึกdecision_observed_utc, Nginxmsec, workerPIDและrequestID.

สถิติnginx_ready_secondsเฉพาะ20Immediate decisions: **min 0.162s / median 0.1765s / max 0.186s** (162/176.5/186ms). ไม่รวมtimeoutจำลองหรือunitfixtures.

| Protocol | IP | nginx_ready_seconds | Worker PID | Nginx upstream | Final |
|---|---|---:|---|---|---|
| https | 192.168.56.130 | 0.183 | 15028 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.131 | 0.169 | 15065 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.132 | 0.167 | 15102 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.133 | 0.162 | 15113 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.134 | 0.182 | 15124 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.135 | 0.174 | 15135 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.136 | 0.176 | 15173 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.137 | 0.18 | 15210 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.138 | 0.177 | 15232 | 10.10.10.2:8084 | PASS |
| https | 192.168.56.139 | 0.18 | 15244 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.140 | 0.178 | 15254 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.141 | 0.172 | 15266 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.142 | 0.18 | 15276 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.143 | 0.164 | 15288 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.144 | 0.186 | 15298 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.145 | 0.186 | 15309 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.146 | 0.166 | 15322 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.147 | 0.163 | 15332 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.148 | 0.171 | 15369 | 10.10.10.2:8084 | PASS |
| http | 192.168.56.149 | 0.18 | 15405 | 10.10.10.2:8084 | PASS |

## Timeout simulation

พักเฉพาะNginxmasterด้วยSIGSTOPในlab; workersเดิมยังทำงาน. ตั้งsystemdwatchdogSIGCONT15วินาทีก่อนพัก และresumeในfinally. ไม่มีการเปลี่ยนsourceให้จำลองผลหรือสร้างauditปลอม. เมื่อreloadsignalยังไม่มีworkerใหม่ engineรอจนtimeoutแต่เขียนdecisionreadyfalseสองรายการต่อกันจากIPใหม่ .150/.151. เวลา5.009sและ5.003s. หลังresume sourceใหม่.152ได้readytrue0.176s. แสดงว่าengineทำงานต่อและกลับมาreadyได้. Timeoutfalseไม่ได้ยืนยันว่าrequestระหว่างนั้นจะredirectแล้ว; callerต้องอ่านฟิลด์นี้.

## ตาราง regression ทั้งระบบ

| Test | Source IP | Actual | Initial | Final |
|---|---|---|---|---|
| Readiness-timeout-and-engine-continues | 192.168.56.150,192.168.56.151,192.168.56.152 | nginx_ready=false 5.009s และ5.003s; engineเขียนสองdecisionsต่อกัน; resumeแล้วready=true0.176s | PASS | PASS |
| ET-sqlmap-UA | 192.168.56.160 | SID2008538 redirect_web risk50.0 | PASS | PASS |
| ET-Nikto-UA-threshold | 192.168.56.161 | SID2002677 redirect_web risk60.0 | PASS | PASS |
| ET-Nmap-NSE-UA | 192.168.56.162 | SID2009359 redirect_web risk60.0 | PASS | PASS |
| ET-Masscan-UA | 192.168.56.163 | SID2017616 monitor risk37.0; SID2017616 monitor risk74.0; SID2017616 monitor risk100.0 | PASS | PASS |
| ET-UNION-URI | 192.168.56.164 | SID2006446 redirect_web risk40.0 | PASS | PASS |
| ET-UNION-body | 192.168.56.165 | SID2053468 redirect_web risk40.0 | PASS | PASS |
| ET-passwd-URI | 192.168.56.166 | SID2049400 monitor risk30.0 | PASS | PASS |
| ET-env | 192.168.56.167 | SID2031502 monitor risk17.0 | PASS | PASS |
| ET-htpasswd | 192.168.56.168 | SID2101071 redirect_web risk40.0 | PASS | PASS |
| ET-SSH-scan | 192.168.56.169 | SID2001219 monitor risk35.0 | PASS | PASS |
| ET-LibSSH-Hydra | 192.168.56.170 | SID2001219 monitor risk35.0; SID2006546 redirect_ssh risk80.0 | PASS | PASS |
| ET-Telnet-incorrect | 192.168.56.171 | SID2101251 monitor risk35.0 | PASS | PASS |
| ET-Telnet-failed | 192.168.56.172 | SID2100492 monitor risk35.0 | PASS | PASS |
| Regression-HTTP | 192.168.56.180 | HTTP200; redirect_web; WebHoneypot source/queryตรงกัน | PASS | PASS |
| Regression-HTTPS | 192.168.56.181 | HTTPS200; Nginx10.10.10.2:8084; WebHoneypot source/queryตรงกัน (ยืนยันจากfinalrawlog) | FAIL | PASS |
| Regression-SSH | 192.168.56.182 | redirect_ssh; nftDNAT; Cowrieบันทึกwhoami/ls/uname -a | PASS | PASS |
| Regression-Telnet | 192.168.56.183 | redirect_telnet; nftDNAT; Cowrielogin.failedจากsourceIPใหม่ | PASS | PASS |
| Rabbit-Hole-Web | 192.168.56.184 | /robots.txt→/backup/→config.json→API; ใช้keyเรียก/api/v1/users HTTPS200 | PASS | PASS |
| Rabbit-Hole-SSH | 192.168.56.185 | Cowrie notes.txtชี้/opt/backup/backup.conf; อ่านไฟล์ลวงDB_HOSTได้; command logsมีจริง | PASS | PASS |
| Dashboard-Threshold-TOTP-User-Master | 192.168.56.186 | POST200; monitor17เมื่อ5/90 → redirect_web56.99เมื่อ5/10; User403; /etcSHA256เดิม; คืน15/40 | PASS | PASS |
| Dashboard-Rule-approve-applied-restore | 192.168.56.187,192.168.56.188 | approve200→applied; SID9900001 activeและalert; restoreappliedแล้วSIDหาย; IPใหม่ยิงURIไม่เกิดSID | PASS | PASS |
| Dashboard-Invalid-rule-rejected |  | helperfailedที่syntax_test; activeSHA256ไม่เปลี่ยน; restoreapplied | PASS | PASS |
| Reboot-services-and-threshold-persistence |  | boot ID เปลี่ยน; 6 services activeเอง; thresholdsก่อน/หลังSHA256เท่ากัน | PASS | PASS |
| Post-reboot-HTTP | 192.168.56.189 | HTTP200; redirect_web; WebHoneypot source/queryตรงกัน | PASS | PASS |
| Post-reboot-SSH | 192.168.56.190 | redirect_ssh; nftDNAT; Cowrieบันทึกwhoami/ls/uname -a | PASS | PASS |
| Dashboard-TOTP-negative-and-role-enforcement |  | invalidTOTP401; Userrules403/threshold403; Masterrules200 | PASS | PASS |

คำสั่งเต็ม,payloadAPI,status,response,alerts,decisions,sessionและrequestอยู่ในCSV/cases/API/rawlogs. กฎNiktoทดสอบด้วยcurlUAที่ตรงsignatureและครบthreshold6requests; Nmapใช้ข้อความNmapNSEที่กฎรองรับ; UNIONURIมีsemicolonตามsignature. ไม่อ้างว่าpayloadทุกแบบที่คล้ายกันจะmatch.

ETSSHscanSID2001219ได้monitorที่threshold40/risk35; ใช้threshold30ในSSHregressionเพื่อยืนยันredirectตามpolicy. MasscanSID2017616เป็นmonitorทั้ง3decisionsแม้risk100. SID2006546ผ่านHydraจริงและredirect_ssh80. Telnetกฎฝั่งresponseใช้fixtureLoginincorrect/failedก่อนredirect; regressionครั้งถัดไปไปCowrieจริง. Fixtureไม่ใช่Cowrie.

WebRabbitHoleตามrobots→backup/config.json→APIkey→HTTPS/api/v1/users200. SSHRabbitHoleใช้notes.txt→/opt/backup/backup.confและพบไฟล์ลวง; Cowrieเก็บcommands. HTTP/HTTPS/CowrielogมาจากHoneypotจริง โดยSHA256ต้นทางตรงสำเนาDefenderก่อนคัดช่วงเวลา.

Dashboard: MasterAdmin+TOTPsave5/90→5/10ผ่าน200, enginedecisionใช้ค่าใหม่; User403; /etcconfigSHA256เดิม. ApproveSID9900001ผ่านappliedจริงและprobealert; restoreแล้วSIDหายและIPใหม่ไม่เกิดalert. กฎผิดsyntaxhelperfailedแต่activehashเดิมแล้วrestoreapplied. InvalidTOTP401; Userrules/threshold403; Masterrules200. คืนthreshold15/40และไม่มีblockfeature.

## Reboot และ persistence

Boot IDก่อน `590bc604-a35d-42b4-a07a-f7eba5da8479` → หลัง `c0a549fe-7014-4837-996b-04d55fe0a7cb`. ยืนยันrebootจริงจากIDเปลี่ยน. suricata,nginx,adaptive-defender,trap-dashboard,trap-apply-rules.path,trap-log-sync.timerกลับมาactiveเอง โดยไม่ได้สั่งstartเพื่อให้ผ่าน. ค่าthresholdfileตรงก่อนบูตแบบbyte-for-byte: SHA256 `18bf07a6c12ebf97060dca983195df4462eef554a11a2200d3bd97db13b2c4b1`; monitor15/redirect40.

หลังบูตIPใหม่.189redirectHTTPถึงWebHoneypot และ.190redirectSSHถึงCowrieพร้อมwhoami/ls/uname. ปรับthresholdชั่วคราวในSSHtestและคืน15/40. Nginxreadyfieldsยังทำงานหลังreboot. /tmpถูกล้างตามระบบ จึงuploadเฉพาะtestscriptsอีกครั้งก่อนยิงpostboot; ไม่มีการติดตั้งหรือเปิดserviceเพื่อกลบผลreboot.

## ผลตรวจครั้งแรกที่ FAIL และหลักฐานที่ใช้ปิดข้อสงสัย

InitialFAIL12รายการImmediateและ1รายการRegressionHTTPSเป็นerrorว่าไม่พบrequestในสำเนาHoneypotlogขณะตรวจ. แต่Nginxrecordของrequestเหล่านี้เป็นnon-real/upstreamHoneypotอยู่แล้ว. ตรวจต้นทางบนHoneypotพบ20Immediate requestsครบ และSHA256logต้นทางเท่ากับDefenderหลังsyncครั้งสุดท้าย. final-verificationยืนยันrequestเดิมด้วยsourceIP+query+upstream+status ไม่ได้ยิงrequestใหม่มาทดแทน.

ข้อเท็จจริงที่พิสูจน์ได้คือสำเนาที่ตัวตรวจอ่านครั้งแรกยังไม่แสดงrequest แต่ต้นทางและสำเนาครั้งสุดท้ายมีrequestครบ. ไม่สรุปสาเหตุภายในsyncอย่างเจาะจงเกินหลักฐาน. ตัวตรวจควรรอความพร้อมของlogหลังยิงtrafficหรือเทียบต้นทางโดยตรง; การรอนี้อยู่ขั้นอ่านหลักฐานหลังrequest ไม่เพิ่มการรอก่อนImmediate request.

## ขอบเขตและไฟล์หลักฐาน

Attackerเป็นnamespaceบนDefender ไม่ใช่VMที่สาม; มีrouteเฉพาะ192.168.56.0/24ไม่มีdefault. HTTP/HTTPSเข้าDefender192.168.56.10, backendHoneypot10.10.10.2:8084; SSH/TelnetDNAT2222/2223ผ่านProject-Labinternalnetwork. NATNICของVMยังใช้บริหารเครื่อง. ตรวจว่าIPแต่ละเคสไม่เคยอยู่ในEVE/decision/Nginx/Cowrie/Webก่อนเพิ่ม. Postbootใช้IPใหม่ที่ยังไม่เคยยิง.

Rawlogsคัดtimestamp/start_time>=test-startด้วยtimezone-awarecomparison. Telnetresponsealertเชื่อมattackerจากdest_ip. decisionstart_timeเป็นเวลาคำนวณriskก่อนreadinessbarrier; decision_observed_utcคือเวลาtestเห็นบรรทัดauditหลังbarrier จึงใช้ตัวนี้อธิบายImmediate request.

- `TRAP-Retest-Evidence/round3-20261010T083043Z/final-verification.json` — ผลสุดท้ายและrawcorrelation
- `cases.json`, `cases-initial-checks.json` — สถานะ/errorเดิม; `cases-with-final-alerts.json` — เพิ่มresponsealertsที่เชื่อมจากdest_ip
- `immediate.json`, `readiness-statistics.json` — timings/workerPID/decision/requestทั้ง20
- `raw/` — EVE/Decision/Nginx/Cowrie/Web, nftcounters, helperjournal/config/status
- `unit-tests.txt`, `proc-access.txt`, `nginx-workers.json`, `boot-wait.json` — unit/proc/bootหลักฐาน
- `api.json`, `commands.json`, scripts, source-manifest.json และSHA256SUMS.txt — ทำซ้ำ/ตรวจสอบได้
- DashboardreportsCSVและAPI snapshotเก็บในชุดหลักฐาน; สถิติทั้งหมดของDashboardอาจรวมประวัติก่อนรอบนี้ จึงไม่นำมาแทนคะแนนfilteredรอบ3
- รายงานรอบ2ย้ายไปPrevious-Reports; หลักฐานรอบก่อนยังอยู่. ZIPรอบ3ไม่มีDashboardpassword/TOTPsecret

ผลนี้ยืนยันเคสที่ระบุในlab: ไม่ใช่การรับประกันreadinessทุกโหลด/ทุกkeepaliveสถานการณ์หรือproductionreadiness. ไม่พบFAILระบบคงเหลือในเคสที่ทดสอบรอบนี้.
