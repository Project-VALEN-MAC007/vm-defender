# คู่มือติดตั้ง MIMIC Defender บนเครื่องใช้งานจริง

คู่มือนี้ครอบคลุมเฉพาะเครื่อง Defender ยังไม่รวมการติดตั้งเครื่อง Honeypot
หรือบริการภายใน

## เงื่อนไขก่อนเริ่ม

- Ubuntu 24.04 หรือระบบ Linux ที่ใช้ systemd
- Python 3.8 ขึ้นไป
- มี console ของเครื่องไว้กู้คืนหาก network ใช้งานไม่ได้
- มี interface บริหาร, outer และ inner แยกจากกัน
- ทราบชื่อ interface จาก `ip -br link` แล้ว ห้ามเดาชื่อ
- มีสิทธิ์ `sudo` สำหรับติดตั้ง package และ service
- ตรวจสอบ endpoint ภายในตาม `docs/person2-contract.md` แล้ว

## โครงสร้างพาธมาตรฐาน

| Path | ใช้เก็บ |
|---|---|
| `/opt/mimic` | source code ที่ผ่านการทบทวน |
| `/etc/mimic/mimic.json` | production config |
| `/etc/mimic/users.json` | บัญชี Dashboard แบบ hash |
| `/etc/adaptive-defender/live.json` | config ของ Decision Engine |
| `/var/lib/mimic` | registry, state และ backup ของระบบ |
| `/var/log/mimic` | security audit ของ Dashboard |
| `/var/log/adaptive-defender` | decision audit |

## 1. เตรียมแพ็กเกจ

```bash
sudo apt update
sudo apt install --no-install-recommends \
  python3 git nginx nftables conntrack suricata curl ripgrep
```

ตรวจสอบ:

```bash
python3 --version
suricata --build-info | head
nft --version
nginx -v
conntrack -V
```

## 2. ติดตั้งซอร์สโค้ดและสร้างไดเรกทอรี

นำ source ที่ผ่านการทดสอบไปไว้ที่ `/opt/mimic` แล้วกำหนด owner เป็น root
เพื่อไม่ให้ service แก้ source code ได้

```bash
sudo install -d -m 0755 /opt/mimic
sudo groupadd --system mimic-dashboard 2>/dev/null || true
sudo useradd --system --gid mimic-dashboard --home /nonexistent \
  --shell /usr/sbin/nologin mimic-dashboard 2>/dev/null || true
getent group suricata
sudo install -d -m 0750 \
  /etc/mimic \
  /etc/adaptive-defender \
  /var/lib/mimic \
  /var/log/mimic \
  /var/lib/adaptive-defender \
  /var/log/adaptive-defender
sudo chown -R root:root /opt/mimic
sudo chown mimic-dashboard:mimic-dashboard /var/lib/mimic /var/log/mimic
```

## 3. สร้างค่าตั้งสำหรับระบบจริง

```bash
sudo cp /opt/mimic/config/mimic.example.json /etc/mimic/mimic.json
sudo editor /etc/mimic/mimic.json
```

แทนค่า `CHANGE_ME` ทุกจุดด้วยชื่อ interface ที่ตรวจพบจริง จากนั้นสร้างบัญชี
Master Admin โดยให้คำสั่งถามรหัสผ่านผ่าน terminal:

```bash
cd /opt/mimic
sudo python3 -m defender.dashboard.manage_users \
  --file /etc/mimic/users.json \
  --username admin \
  --name "Master Admin" \
  --role master_admin
sudo chown root:mimic-dashboard /etc/mimic/users.json
sudo chmod 0640 /etc/mimic/users.json
```

ห้ามเก็บรหัสผ่าน plain text ใน repository หรือ service unit

## 4. รันด่านตรวจสอบ

```bash
cd /opt/mimic
python3 -m unittest discover -s tests -v
python3 -m defender.validation.production \
  --config /etc/mimic/mimic.json --pretty
python3 -m defender.validation.readiness --pretty
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo nginx -t
```

ผลที่ยอมรับได้:

- ชุดทดสอบทั้งหมดผ่าน
- `production` และ `readiness` ไม่มีรายการ `blocked`
- `suricata -T` และ `nginx -t` คืน exit code 0

หากข้อใดไม่ผ่าน ให้หยุดแก้ที่ต้นเหตุ ห้ามปิด gate หรือแก้ผลรายงาน

## 5. เตรียมเครือข่ายและไฟร์วอลล์

ทำตาม `defender/network/virtualbox-nic-checklist.md` และ
`docs/root-operations.md` ตามลำดับ ต้องสำรองค่าและเปิด timed rollback ก่อน
apply ทุกครั้ง

ไฟล์ nftables ที่ยังมี `__TOKEN__` หรือคำว่า `PARTIAL RENDER` ห้าม apply

## 6. ติดตั้ง systemd และการหมุนเวียนบันทึก

```bash
sudo cp /opt/mimic/defender/decision_engine/systemd/adaptive-defender.service \
  /etc/systemd/system/adaptive-defender.service
sudo cp /opt/mimic/defender/decision_engine/config/live.json \
  /etc/adaptive-defender/live.json
sudo cp /opt/mimic/defender/dashboard/systemd/mimic-dashboard.service \
  /etc/systemd/system/mimic-dashboard.service
sudo cp /opt/mimic/deploy/logrotate/mimic /etc/logrotate.d/mimic
sudo systemctl daemon-reload
```

ตรวจ unit ก่อนเปิด:

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/adaptive-defender.service \
  /etc/systemd/system/mimic-dashboard.service
```

## 7. เปิดบริการทีละตัว

```bash
sudo systemctl enable --now adaptive-defender
sudo systemctl --no-pager --full status adaptive-defender
sudo systemctl enable --now mimic-dashboard
sudo systemctl --no-pager --full status mimic-dashboard
```

ตรวจ Dashboard จากเครื่องเดียวกัน:

```bash
curl -I http://127.0.0.1:9090/
journalctl -u adaptive-defender -u mimic-dashboard --since today
```

Dashboard ต้องไม่ listen บน `0.0.0.0` หรือ IP ของ outer/inner interface

## 8. ตรวจหลังเริ่มระบบใหม่

```bash
sudo reboot
```

หลังเครื่องกลับมา:

```bash
systemctl is-active suricata nginx adaptive-defender mimic-dashboard
ss -lntp
sudo nft list table inet adaptive_defender
curl -I http://127.0.0.1:9090/
```

## การนำกฎขึ้นใช้

Dashboard อนุญาตให้ validate rule แต่ production template ตั้ง
`rules.allow_deploy: false` จึงยังไม่เปลี่ยน Suricata จริง การเปิด live deploy
ต้องมี root-owned helper ที่จำกัดคำสั่งไว้เฉพาะขั้นตอนต่อไปนี้:

1. รับ staging file ที่ผ่าน validation
2. สำรอง active rule
3. รัน `suricata -T`
4. activate แบบ atomic
5. reload Suricata
6. ตรวจ health และ alert output
7. restore backup ทันทีเมื่อข้อใดล้มเหลว

ห้ามแก้ปัญหาด้วยการรัน Dashboard เป็น root หรือให้ unrestricted sudo

## เกณฑ์ส่งมอบเครื่อง Defender

- preflight และ readiness ผ่าน
- service กลับมาทำงานหลัง reboot
- Dashboard login/RBAC ใช้งานได้
- audit log และ decision log เขียนได้
- Nginx, Suricata และ nftables ผ่าน syntax check
- มี backup และทดสอบ rollback แล้ว
- ไม่มี `CHANGE_ME`, `__TOKEN__` หรือ default credential ในไฟล์ที่ใช้งาน
