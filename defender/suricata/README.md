# กฎ Suricata ของ MIMIC Defender

ไฟล์ `rules/local.rules` เป็นกฎ alert ของโปรเจกต์สำหรับทราฟฟิกขาเข้า
SID `2200001` ถึง `2200999` สงวนให้ MIMIC และต้องไม่ซ้ำกับชุดกฎอื่น
ชื่อกฎใน `msg` ใช้คำสั้นแบบ `snake_case` ให้ตรงกับรายการในเอกสาร
ทุกกฎเป็น `alert` ไม่ใช่ `drop`

## กฎพื้นฐานใน repository

| SID | ชื่อ | เหตุผล |
|---|---|---|
| 2200003 | scanner_user_agent | พบชื่อเครื่องมือสแกนใน User-Agent |
| 2200004 | env_file_access | ขอไฟล์ `/.env` |
| 2200005 | git_config_access | ขอไฟล์ `/.git/config` |
| 2200007 | path_traversal | ขอไฟล์ `etc/passwd` ผ่าน `../` |
| 2200008 | password_file_access | ขอไฟล์ `/.htpasswd` |
| 2200009 | svn_metadata_access | ขอไฟล์ `/.svn/entries` |
| 2200102 | tls_1_0_negotiated | HTTPS เจรจาใช้ TLS 1.0 |
| 2200103 | tls_1_1_negotiated | HTTPS เจรจาใช้ TLS 1.1 |
| 2200202 | ssh_connection_burst | SYN เข้า SSH ถึงเกณฑ์ |
| 2200203 | telnet_connection_burst | SYN เข้า Telnet ถึงเกณฑ์ |
| 2200301 | syn_burst | SYN จำนวนมากในช่วงสั้น; ใช้เป็นประวัติความเสี่ยง |

เลิกใช้ SID `2200001`, `2200002` และ `2200006` ที่ผูกกับ WordPress/
phpMyAdmin รวมถึง `2200101` (SNI `.lab`) และ `2200201` (client SSH ที่
ไม่ใช่ OpenSSH) อย่านำ SID เหล่านี้ไปใช้ซ้ำ

Decision Engine และ Nginx ใน checkout นี้ยังอ้าง profile เว็บเดิมอยู่
จึงยังไม่ควรนำกฎเว็บชุดใหม่นี้ไปใช้กับการ redirect จริงจนกว่าจะกำหนดชื่อ
profile และ endpoint ของฮันนีพอตเว็บใหม่ แล้วปรับการเลือก profile ให้ตรงกัน
TLS SNI/JA3 ควรเก็บเป็น EVE telemetry แล้ววิเคราะห์ร่วมกับบริบท
metadata `severity` เป็นป้ายข้อมูลของ MIMIC; ค่า `alert.severity` ที่
Decision Engine ใช้จริงมาจาก `classtype`/priority ของ Suricata
กฎ TLS สองรายการใช้ `misc-activity` (priority 3) เพราะเป็นการแจ้งเตือน
ด้านการตั้งค่า ไม่ใช่หลักฐานว่า client โจมตี หาก Nginx ปฏิเสธ TLS 1.0/1.1
ตามที่ควร กฎนี้จะไม่ alert เพราะไม่มีเวอร์ชันเก่าที่เจรจาสำเร็จ

## ที่มาของกฎ

| กลุ่ม | แหล่งที่ใช้ | สิ่งที่นำมาใช้ |
|---|---|---|
| HTTP | [Suricata HTTP keywords](https://docs.suricata.io/en/suricata-7.0.12/rules/http-keywords.html), [OWASP WSTG: sensitive files](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/), [OWASP: path traversal](https://community.owasp.org/attacks/Path_Traversal), [ET Open web server rules](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-web_server.rules) | HTTP buffer และรูปแบบการขอไฟล์สำคัญ/เดินข้าม path; regex, path และ threshold เป็นกฎที่ปรับเอง |
| HTTPS | [Suricata TLS keywords](https://docs.suricata.io/en/suricata-7.0.11/rules/tls-keywords.html), [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html), [ET Open web server rules](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-web_server.rules) | ตรวจเวอร์ชัน TLS ที่เจรจาสำเร็จ; ET Open ระบุ `SSLDecrypt` สำหรับการตรวจ HTTP ภายใน HTTPS |
| SSH | [Suricata rule format](https://docs.suricata.io/en/suricata-7.0.12/rules/intro.html), [Suricata thresholding](https://docs.suricata.io/en/suricata-7.0.11/rules/thresholding.html), [ET Open scan rules](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-scan.rules) | ET Open มีตัวอย่างแจ้งเตือนการเชื่อมต่อ SSH ถี่; เกณฑ์ 5 SYN/30 วินาทีเป็นค่าทดลองของโปรเจกต์ |
| Telnet | [Suricata rule format](https://docs.suricata.io/en/suricata-7.0.12/rules/intro.html), [Suricata thresholding](https://docs.suricata.io/en/suricata-7.0.11/rules/thresholding.html), [ET Open scan rules](https://rules.emergingthreats.net/open/suricata-7.0.3/rules/emerging-scan.rules) | ใช้รูปแบบกฎนับ SYN; เกณฑ์ 5 SYN/30 วินาทีเป็นค่าทดลองของโปรเจกต์ ไม่ใช่เกณฑ์มาตรฐานของ ET Open |

กฎ `svn_metadata_access` และ `syn_burst` เป็นกฎที่ออกแบบสำหรับโปรเจกต์
ตามหลักการเดียวกัน ไม่ได้คัดลอก SID หรืออ้างว่า OWASP/ET Open รับรอง
ค่า threshold เหล่านี้

## ก่อนโหลดกฎ

1. ตั้ง `HOME_NET` ใน `/etc/suricata/suricata.yaml` ให้เป็น outer IP ของ
   Defender ที่ถูกป้องกันจริง เช่น `HOME_NET: "[192.168.56.10/32]"`
   สำหรับ topology ตัวอย่าง หลีกเลี่ยงค่าเริ่มต้นที่ครอบ RFC1918 ทั้งหมด
   เพราะ attacker ในวง lab อาจถูกจัดเป็น HOME_NET ด้วย กฎ local ใช้
   `any -> $HOME_NET` เพื่อรับ source ทั้งภายใน lab และภายนอก
2. ตรวจว่า Suricata เห็น packet ขาเข้าบน outer interface และ destination
   เป็น IP ใน HOME_NET หาก capture หลัง DNAT หรือเฉพาะ inner interface
   ให้ปรับจุด capture และ HOME_NET จาก packet จริงก่อน
3. โหลด local file **ครั้งเดียว** ผ่าน `rule-files` ของ Suricata
   แล้วตรวจ `suricata -T` เพื่อไม่ให้ SID ซ้ำกับกฎที่ `suricata-update`
   รวมไว้ใน `suricata.rules`
4. คัดลอกกฎหลัง review ไปยัง path ที่ Dashboard ระบุใน
   `rules.active_rules` (`/etc/suricata/rules/mimic.rules` ในตัวอย่าง)
   การแก้ repository อย่างเดียวไม่เปลี่ยนกฎที่กำลังรัน

ตัวอย่างเมื่อใช้ `rule-files` กับกฎ ET Open ที่ `suricata-update` จัดการ:

```yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - /etc/suricata/rules/mimic.rules
```

```bash
sudo install -m 0644 /opt/mimic/defender/suricata/rules/local.rules \
  /etc/suricata/rules/mimic.rules
sudo suricata -T -c /etc/suricata/suricata.yaml \
  -S /etc/suricata/rules/mimic.rules
```

คำสั่ง `-S` ใช้ทดสอบไฟล์ local แยกจาก ruleset อื่น การใช้งานจริงต้องตรวจ
`rule-files` ใน config ด้วย แล้วจึง reload ตามขั้นตอนสำรองและ rollback ใน
`docs/root-operations.md` และทดสอบ replay ตาม `rule-tests.md`

## ขอบเขตการตรวจจับ

HTTP rules อ่านเนื้อหา HTTPS ได้ต่อเมื่อ Suricata capture HTTP หลัง Nginx
ถอด TLS แล้ว แต่ connection ฝั่ง backend อาจมี source เป็น IP ของ Nginx
จึง **ห้าม** นำ alert จากจุดนั้นไปบล็อกหรือ redirect โดยอ้างว่า `src_ip`
เป็น IP ผู้ใช้จริง หากต้องการตอบสนองตาม IP ผู้ใช้ ให้พิสูจน์การเชื่อม
EVE กับ access log ของ Nginx ที่เชื่อถือได้ก่อน กฎ TLS อย่างเดียวมองไม่เห็น
URI ภายใน HTTPS; SNI/JA3 เป็น telemetry ไม่ใช่หลักฐานโจมตีลำพัง

กฎ SYN burst นับ packet ที่ตรงเงื่อนไข ไม่พิสูจน์ว่าเป็นคนละปลายทางหรือ
คนละ connection และอาจรวม retransmission ควรปรับเกณฑ์จาก baseline ของ
เครือข่ายจริงก่อนเปิดการตอบสนองอัตโนมัติ

สำหรับ coverage ภัยคุกคามทั่วไป ให้ใช้ `suricata-update` จัดการ
Emerging Threats Open แยกจากกฎ MIMIC และทบทวน policy/SID ที่เปิดใช้
ก่อนส่ง alert เข้าสู่ Decision Engine ปัจจุบัน engine ประเมินทุก alert ใน
EVE เดียวกัน จึงไม่ควรเปิด ruleset กว้างทั้งชุดเข้ากระบวนการบล็อกอัตโนมัติ

อ้างอิงหลัก: [Suricata rule format](https://docs.suricata.io/en/suricata-7.0.12/rules/intro.html),
[HTTP sticky buffers](https://docs.suricata.io/en/suricata-7.0.12/rules/http-keywords.html),
[thresholding](https://docs.suricata.io/en/suricata-7.0.11/rules/thresholding.html),
[suricata-update](https://docs.suricata.io/en/suricata-7.0.12/rule-management/suricata-update.html)
