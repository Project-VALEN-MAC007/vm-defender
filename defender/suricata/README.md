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

HTTP ใน HTTPS ตรวจได้เมื่อ capture หลัง Nginx ถอด TLS แล้ว ต้องเชื่อมโยง
IP ผู้ใช้จริงจากข้อมูลที่เชื่อถือได้ก่อนป้อน alert ฝั่ง backend เข้า Decision Engine
มิฉะนั้นอาจประเมิน IP ของ proxy แทนผู้ใช้

Decision Engine รองรับ SID Telnet 2100492/2101251 ซึ่งเป็นคำตอบฝั่งเซิร์ฟเวอร์
โดยใช้ dest_ip เป็น IP ผู้ใช้ และตรวจ src_port ว่าเป็น 23 ก่อนรับเหตุการณ์
การ login ผิดหนึ่งครั้งไม่ยืนยัน brute force ระบบยังใช้คะแนนสะสมและ threshold

SID ของเครื่องมือสแกนและ SSH scan ใช้สร้างประวัติความเสี่ยงใน engine
ไม่มีการอ้างกฎ SID 2200xxx เดิมในการประเมินกฎ Default อีกต่อไป
ยังต้องทดสอบการเปลี่ยนเส้นทางจริงและปรับ threshold จาก Baseline
