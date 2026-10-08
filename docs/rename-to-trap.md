# ย้ายเครื่องที่ติดตั้งชื่อเดิม (MIMIC) มาใช้ชื่อ TRAP

โปรเจคเปลี่ยนชื่อจาก MIMIC เป็น TRAP ทั้งหมดแล้ว ทั้ง path, ชื่อ service, ผู้ใช้ระบบ และไฟล์ config
เครื่องที่ติดตั้งใหม่ทำตามหน้า **คู่มือติดตั้ง** ใน Dashboard ได้เลย ส่วนเครื่องที่ติดตั้งไว้แล้วให้ทำตามนี้

| ของเดิม | ของใหม่ |
|---|---|
| `/opt/mimic` | `/opt/trap` |
| `/etc/mimic/mimic.json` | `/etc/trap/trap.json` |
| `/var/lib/mimic` | `/var/lib/trap` |
| `/var/log/mimic` | `/var/log/trap` |
| `mimic-dashboard.service`, ผู้ใช้ `mimic-dashboard` | `trap-dashboard.service`, ผู้ใช้ `trap-dashboard` |
| `/etc/logrotate.d/mimic` | `/etc/logrotate.d/trap` |
| `/root/mimic-backup` | `/root/trap-backup` |
| cookie `mimic_session` | `trap_session` (ผู้ใช้ต้อง login ใหม่หนึ่งครั้ง) |
| `config/mimic.json` (เครื่องทดสอบ) | `config/trap.json` |

## Defender

```bash
sudo systemctl disable --now mimic-dashboard
sudo mv /opt/mimic /opt/trap
sudo mv /etc/mimic /etc/trap && sudo mv /etc/trap/mimic.json /etc/trap/trap.json
sudo sed -i 's#/mimic#/trap#g; s#mimic\.#trap.#g' /etc/trap/trap.json
# /var/lib/trap อาจมีอยู่แล้วจาก Rabbit Hole ให้รวมเข้าไป
sudo mkdir -p /var/lib/trap /var/log/trap
sudo cp -a /var/lib/mimic/. /var/lib/trap/ && sudo cp -a /var/log/mimic/. /var/log/trap/
sudo usermod -l trap-dashboard mimic-dashboard && sudo groupmod -n trap-dashboard mimic-dashboard
sudo chown -R trap-dashboard: /var/lib/trap /var/log/trap
sudo rm /etc/systemd/system/mimic-dashboard.service
sudo cp /opt/trap/defender/dashboard/systemd/trap-dashboard.service /etc/systemd/system/
sudo cp /opt/trap/defender/decision_engine/systemd/adaptive-defender.service /etc/systemd/system/
sudo rm -f /etc/logrotate.d/mimic && sudo cp /opt/trap/deploy/logrotate/trap /etc/logrotate.d/trap
sudo systemctl daemon-reload && sudo systemctl enable --now trap-dashboard
sudo systemctl restart adaptive-defender
```

ตรวจว่าไม่มีอะไรอ้างชื่อเดิมค้าง แล้วค่อยลบ `/var/lib/mimic` และ `/var/log/mimic`

```bash
sudo grep -rIl mimic /etc/systemd/system /etc/trap /etc/nginx /etc/nftables* /etc/logrotate.d 2>/dev/null
```

Nginx ใช้ตัวแปร `$trap_trusted_proxy_cidrs` แทน `$mimic_trusted_proxy_cidrs` ให้ generate config ใหม่จาก
`/opt/trap/defender/nginx` แล้ว `sudo nginx -t && sudo systemctl reload nginx`

## Honeypot

```bash
cd /opt/mimic/honeypot/snare-tanner && sudo docker compose down
sudo mv /opt/mimic /opt/trap
cd /opt/trap/honeypot/snare-tanner && sudo docker compose up -d
```

Compose project เปลี่ยนชื่อเป็น `trap-web-honeypot` container เดิมจึงถูกสร้างใหม่ ข้อมูลเว็บที่ clone ไว้อยู่ใน
โฟลเดอร์ของ repo จึงไม่หาย

## เครื่องทดสอบ Windows

เปลี่ยนชื่อ `config/mimic.json` เป็น `config/trap.json` แล้วดับเบิลคลิก `start-trap-demo.bat`
