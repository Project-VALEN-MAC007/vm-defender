# TRAP deploy agent

ตัวช่วยบนเครื่อง Honeypot ให้ Dashboard ส่งสำเนาเว็บมาให้ SNARE และสลับหน้าเว็บที่ SNARE เสิร์ฟได้
ทำได้แค่ 4 อย่างที่กำหนดตายตัว (รับสำเนา, เปิดใช้เวอร์ชัน, ดูสถานะ, ดูหน้าที่ได้มา) ไม่รับคำสั่ง shell

## ใครเป็นคน clone

**Defender** เป็นคน clone (`defender/deploy_agent/clone.py` ใน Dashboard) แล้วส่งสำเนาที่เสร็จแล้วมาที่
`POST /v1/versions` ของ agent ตัว Honeypot ไม่ต่อเว็บจริงเองเลย เพราะ `deploy/isolation/honeypot.nft`
ห้าม Honeypot และ container เปิดการเชื่อมต่อเข้าวง lab ทิศทางเดียวที่ใช้คือ Defender → Honeypot 8091
ซึ่งเปิดอยู่แล้ว

ไฟล์ที่ได้เป็นรูปแบบเดียวกับ cloner ของ SNARE (ไฟล์ชื่อ MD5 ของ path + `meta.json`) SNARE จึงเสิร์ฟได้เลย
agent ตรวจชื่อไฟล์ ขนาด และ `meta.json` ก่อนเก็บ แล้วสแกนหาความลับ/IP ภายในเหมือนเดิม

## ความปลอดภัย

- ฟังเฉพาะ IP ฝั่ง inner และรับเฉพาะ IP ใน `allowed_clients` (Defender) ที่ส่ง token ถูกต้อง
- clone ได้เฉพาะ host ใน `web_deploy.allowed_targets` ของ `trap.json` บน Defender รวมถึง redirect ก็ตามได้เฉพาะ host เดิม ป้องกันการเอาไปยิงเว็บอื่นหรือเครื่องภายใน
- คำสั่ง docker สร้างจาก argv ตายตัว ไม่ผ่าน shell
- ผู้ใช้ `trapdeploy` อยู่ในกลุ่ม docker ซึ่งเทียบเท่า root จึงต้องจำกัดเครือข่ายตามข้างบนเสมอ
- เปิดใช้เวอร์ชันใหม่แล้วตรวจ `health_url` ถ้าไม่ตอบ ระบบย้อนกลับเวอร์ชันเดิมเอง

## ติดตั้งบน Ubuntu (เครื่อง Honeypot)

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin trapdeploy
sudo usermod -aG docker trapdeploy
sudo chown -R trapdeploy:trapdeploy /opt/trap/honeypot/snare-tanner/data /opt/trap/honeypot/snare-tanner/settings.env
sudo install -d -m 750 -o root -g trapdeploy /etc/trap
python3 -c "import secrets;print(secrets.token_hex(32))" | sudo tee /etc/trap/deploy-agent.token >/dev/null
sudo chown root:trapdeploy /etc/trap/deploy-agent.token && sudo chmod 640 /etc/trap/deploy-agent.token
sudo cp honeypot/deploy-agent/deploy-agent.example.json /etc/trap/deploy-agent.json
sudo nano /etc/trap/deploy-agent.json # แก้ IP และ path ให้ตรงเครื่องจริง
sudo cp honeypot/deploy-agent/trap-deploy-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now trap-deploy-agent
```

คัดลอก token เดียวกันไปไว้บนเครื่อง Defender (เช่น `/etc/trap/deploy-agent.token`, chmod 600 เจ้าของคือผู้ใช้ที่รัน Dashboard)
แล้วเพิ่มใน `trap.json`:

```json
"web_deploy": {
  "agent_url": "http://10.10.10.2:8091",
  "token_file": "/etc/trap/deploy-agent.token",
  "allowed_targets": ["10.10.10.3:8080"]
}
```

ทดสอบจาก Defender: `curl -H "Authorization: Bearer $(cat /etc/trap/deploy-agent.token)" http://10.10.10.2:8091/v1/status`

## ลองบนเครื่องตัวเองโดยไม่มี Docker

`python generate_demo_data.py` สร้าง config เดโม่ให้แล้ว รันอีกหน้าต่างหนึ่ง:

```bash
python run_deploy_agent.py --config evidence/demo/deploy-agent.json
```

โหมดนี้ไม่เรียก Docker และ `web_deploy.dry_run: true` ใน `config/trap.demo.json` ทำให้ Dashboard ใช้หน้าเว็บตัวอย่างแทนการดึงเว็บจริง จึงลองกด Clone และ Deploy ได้
