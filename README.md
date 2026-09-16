# Adaptive Honeypot — VM-Defender

โปรเจคนี้ประกอบด้วยส่วนประกอบของ VM-Defender สำหรับเฟส D1–D8 คำสั่งทั้งหมด
ที่เปลี่ยนแปลงระบบจะต้องได้รับการยืนยันก่อน โหมดเริ่มต้นของทุก helper คือ
validation หรือ dry-run เพื่อป้องกันไม่ให้ระบบทดสอบถูกเปิดเผยต่อเครือข่ายจริง
โดยไม่ตั้งใจ

## ข้อจำกัดของระบบปัจจุบัน

Defender ปัจจุบันมี interface ที่จัดการได้หนึ่งตัวคือ `enp0s3` (`10.0.2.15/24`,
VirtualBox NAT) interface ภายนอกและภายในที่จำเป็นสำหรับ lab ยังไม่มีอยู่
ห้าม assign `192.168.56.10` หรือ `10.10.10.1` ให้กับ `enp0s3` ต้องเพิ่ม
VirtualBox adapter แบบ isolated สองตัวก่อน และตรวจสอบการเข้าถึงผ่าน console
ก่อนที่จะ apply D1

Git, Nginx และ conntrack ยังไม่ได้ติดตั้ง Suricata 7.0.3 และ nftables
ได้ติดตั้งแล้ว คำสั่งที่ต้องใช้สิทธิ์ root รวบรวมไว้ใน
`docs/root-operations.md` คำสั่งเหล่านี้จะไม่ถูกรันโดยไม่มีหลักฐานและ
แผนการ rollback ที่ทดสอบแล้ว

## การตรวจสอบในเครื่องอย่างปลอดภัย

```bash
cd "/home/yakult/Documents/Default Project"
python3 -m unittest discover -s tests -v
python3 -m defender.decision_engine.adaptive_defender.cli \
  --config defender/decision_engine/config/lab.json --once --dry-run
python3 tests/generate_pcaps.py
python3 -m tests.run_feedback_loop
```


ตรวจสอบความพร้อมในการ deploy จริง (อ่านอย่างเดียว):

```bash
python3 -m defender.validation.readiness --pretty
```

Exit code `0` หมายความว่าผ่านการตรวจสอบทั้งหมด Exit code `2` หมายความว่า
พบปัญหาที่ขัดขวาง เช่น lab NICs ที่หายไป, แพ็กเกจที่ขาดหาย หรือบริการที่ไม่ทำงาน

ตรวจสอบ Dashboard (loopback เท่านั้น):

```bash
python3 -c 'from pathlib import Path; from defender.dashboard.app import serve; serve(Path("evidence/test-results/decisions.jsonl"), Path("evidence/test-results/status.json"))'
```

ห้าม bind dashboard ไปยังที่อยู่ที่ไม่ใช่ loopback ตัวโหลดการตั้งค่าและ
server จะปฏิเสธเงื่อนไขนั้น

## WordPress backend

Defender profile `wordpress` ควร redirect ผ่าน
`defender/nginx/adaptive-honeypot.conf.template` ไปยัง inner honeypot backend
ที่ `10.10.10.2:8081` โดยใช้ `__WORDPRESS_IP__=10.10.10.2` และ
`__WORDPRESS_PORT__=8081`

ดูผลลัพธ์จริงและสถานะของแต่ละเฟสได้ที่ `docs/person1-progress.md`
