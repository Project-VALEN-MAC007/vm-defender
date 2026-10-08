# TRAP deploy agent

ตัวช่วยบนเครื่อง Honeypot ให้ Dashboard สั่ง clone เว็บด้วย SNARE และสลับหน้าเว็บที่ SNARE เสิร์ฟได้
ทำได้แค่ 4 อย่างที่กำหนดตายตัว (clone, เปิดใช้เวอร์ชัน, ดูสถานะ, ดูหน้าที่ clone มา) ไม่รับคำสั่ง shell

## ความปลอดภัย

- ฟังเฉพาะ IP ฝั่ง inner และรับเฉพาะ IP ใน `allowed_clients` (Defender) ที่ส่ง token ถูกต้อง
- clone ได้เฉพาะ host ใน `allowed_targets` ป้องกันการเอาไปยิงเว็บอื่นหรือเครื่องภายใน
- คำสั่ง docker สร้างจาก argv ตายตัว ไม่ผ่าน shell
- ผู้ใช้ `trapdeploy` อยู่ในกลุ่ม docker ซึ่งเทียบเท่า root จึงต้องจำกัดเครือข่ายตามข้างบนเสมอ
- เปิดใช้เวอร์ชันใหม่แล้วตรวจ `health_url` ถ้าไม่ตอบ ระบบย้อนกลับเวอร์ชันเดิมเอง

## ติดตั้งบน Ubuntu (เครื่อง Honeypot)

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin trapdeploy
sudo usermod -aG docker trapdeploy
sudo chown -R trapdeploy:trapdeploy /opt/vm-defender/honeypot/snare-tanner/data /opt/vm-defender/honeypot/snare-tanner/settings.env
sudo install -d -m 750 -o root -g trapdeploy /etc/trap
python3 -c "import secrets;print(secrets.token_hex(32))" | sudo tee /etc/trap/deploy-agent.token >/dev/null
sudo chown root:trapdeploy /etc/trap/deploy-agent.token && sudo chmod 640 /etc/trap/deploy-agent.token
sudo cp honeypot/deploy-agent/deploy-agent.example.json /etc/trap/deploy-agent.json
id -u trapdeploy; id -g trapdeploy   # ใส่ค่าใน run_as เช่น "998:998"
sudo nano /etc/trap/deploy-agent.json # แก้ IP, allowed_targets, path ให้ตรงเครื่องจริง
sudo cp honeypot/deploy-agent/trap-deploy-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now trap-deploy-agent
sudo ufw allow from 10.10.10.1 to any port 8091 proto tcp
```

คัดลอก token เดียวกันไปไว้บนเครื่อง Defender (เช่น `/etc/trap/deploy-agent.token`, chmod 600 เจ้าของคือผู้ใช้ที่รัน Dashboard)
แล้วเพิ่มใน `trap.json`:

```json
"web_deploy": {
  "agent_url": "http://10.10.10.2:8091",
  "token_file": "/etc/trap/deploy-agent.token"
}
```

ทดสอบจาก Defender: `curl -H "Authorization: Bearer $(cat /etc/trap/deploy-agent.token)" http://10.10.10.2:8091/v1/status`

## ลองบนเครื่องตัวเองโดยไม่มี Docker

`python generate_demo_data.py` สร้าง config เดโม่ให้แล้ว รันอีกหน้าต่างหนึ่ง:

```bash
python run_deploy_agent.py --config evidence/demo/deploy-agent.json
```

โหมดนี้ (`dry_run: true`) ไม่เรียก Docker แต่สร้างหน้าเว็บตัวอย่างให้ลองกด Clone และ Deploy ใน Dashboard ได้
