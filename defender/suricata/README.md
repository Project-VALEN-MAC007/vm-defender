# กฎ Suricata เริ่มต้นของ TRAP

ใช้กฎสำเร็จรูป ET Open 13 กฎรวมใน `rules/et-open-selected.rules` เพียงไฟล์เดียว
ตัดกฎเขียนเองเดิมและไฟล์ `local.rules` ออกจากชุดเริ่มต้นแล้ว
ชื่อกฎ SID revision และเนื้อหากฎคงตามต้นฉบับ รวมกฎชื่อ GPL ที่อยู่ใน ET Open
ดูรายการและข้อจำกัดใน [รายการกฎ](et-open-selection.md)
และแผนทดสอบใน [การทดสอบกฎ](rule-tests.md)

## การติดตั้งบน Defender

ตั้ง HOME_NET ให้ตรงกับ IP ที่ Suricata มองเห็นจริง และตั้ง HTTP_SERVERS
กับ TELNET_SERVERS ให้ตรงกับบริการ อย่ากำหนด HOME_NET ครอบคลุมเครื่อง
ทดสอบจน EXTERNAL_NET ไม่รวมต้นทางของเครื่องนั้น

```bash
sudo install -d /etc/suricata/rules
sudo install -m 0644 /opt/trap/defender/suricata/rules/et-open-selected.rules /etc/suricata/rules/et-open-selected.rules
```

รวมส่วนนี้ใน `/etc/suricata/suricata.yaml` แทนรายการกฎเก่า:

```yaml
rule-files:
  - /etc/suricata/rules/et-open-selected.rules
```

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

นำ `trap.rules`, `local.rules` และ `suricata.rules` ที่โหลด ET Open ทั้งชุด
ออกจาก rule-files สำหรับโหมดคัดเลือกนี้ เพื่อไม่ให้กฎเดิมยังทำงานหรือ SID ซ้ำ
จากนั้นทดสอบ replay และ reload ตาม `docs/root-operations.md`
การแก้ repository ไม่เปลี่ยนไฟล์บน VM โดยอัตโนมัติ

Dashboard ตั้งค่าเริ่มต้นให้ชี้ไฟล์คัดเลือกนี้แล้ว ส่วนกฎจาก Feedback Loop
ยังเป็นกฎที่เสนอและต้องผ่านการตรวจสอบก่อน deploy ไม่ใช่กฎ Default

## ขอบเขตการตอบสนอง

HTTPS: Nginx ถอด TLS ที่พอร์ต 443 แล้วส่งคำขอที่ถอดรหัสแล้วผ่านจุดตรวจบน loopback
(127.0.0.2 → 127.0.0.1:18443) ให้ Suricata ตรวจด้วยกฎชุดเดียวกับ HTTP
Nginx ขอบนอกเขียน IP ผู้ใช้จริงลง header `X-Trap-Client-IP` (เขียนทับค่าที่ผู้ใช้ส่งมา)
Suricata 7 รายงานเป็นฟิลด์ `alert.xff` และ Decision Engine/Dashboard เชื่อฟิลด์นี้
**เฉพาะ alert บน `lo` จาก 127.0.0.2 ไป 127.0.0.1:18443** เท่านั้น
ค่าต้องเป็น IP เดียวที่ไม่ใช่ loopback/unspecified/multicast; alert จาก interface ภายนอกไม่ใช้ header นี้
จึงปลอม header เพื่อให้ระบบ redirect IP อื่นไม่ได้ ตั้งค่า Suricata ตาม `https-inspection.yaml`

Service ต้องใช้ `--af-packet --runmode=workers` เพื่ออ่านทั้ง `trap-out` และ `lo`
จาก YAML. `--af-packet=trap-out` จะข้าม lo และ `single` ไม่รองรับหลาย interface.
ติดตั้ง `systemd/https-inspection.conf` เป็น drop-in หลังสำรอง unit/config เดิม.
ตั้งหนึ่ง thread ต่อ interface และ `block-size: 131072` ทั้งสอง entry: MTU 65536
ของ lo ทำให้ TPACKET_V3 block เดิม 32768 เล็กเกินไป. ตรวจ `suricata -T`,
`nginx -t`, `suricatasc -c iface-list` และ service health ก่อนยิงทดสอบ;
ถ้าเริ่ม service ไม่ได้ ให้คืน config/drop-in เดิมทันที.

HTTP พอร์ต 80 จับเฉพาะ `trap-out`; decrypted HTTPS จับเฉพาะ lo ด้วย BPF
`tcp port 18443`. ตรวจ `(flow_id, tx_id, signature_id)` ใน EVE ว่าไม่ซ้ำ
เพื่อแยก alert ซ้ำจาก request เดียวออกจากหลาย signature ที่ตรง request เดียวกัน.

Decision Engine รองรับ SID Telnet 2100492/2101251 ซึ่งเป็นคำตอบฝั่งเซิร์ฟเวอร์
โดยใช้ dest_ip เป็น IP ผู้ใช้ และตรวจ src_port ว่าเป็น 23 ก่อนรับเหตุการณ์
การ login ผิดหนึ่งครั้งไม่ยืนยัน brute force ระบบยังใช้คะแนนสะสมและ threshold

SID ของเครื่องมือสแกนและ SSH scan ใช้สร้างประวัติความเสี่ยงใน engine
ไม่มีการอ้างกฎ SID 2200xxx เดิมในการประเมินกฎ Default อีกต่อไป
ยังต้องทดสอบการเปลี่ยนเส้นทางจริงและปรับ threshold จาก Baseline
