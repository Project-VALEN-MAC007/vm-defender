# คู่มือติดตั้ง TRAP Defender บนเครื่องใช้งานจริง

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
| `/opt/trap` | source code ที่ผ่านการทบทวน |
| `/etc/trap/trap.json` | production config |
| `/var/lib/trap/dashboard-users/users.json` | บัญชี Dashboard แบบ hash ที่ service จัดการได้ |
| `/etc/adaptive-defender/live.json` | config ของ Decision Engine |
| `/var/lib/trap` | registry, state และ backup ของระบบ |
| `/var/log/trap` | security audit ของ Dashboard |
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

นำ source ที่ผ่านการทดสอบไปไว้ที่ `/opt/trap` แล้วกำหนด owner เป็น root
เพื่อไม่ให้ service แก้ source code ได้

```bash
sudo install -d -m 0755 /opt/trap
sudo groupadd --system trap-dashboard 2>/dev/null || true
sudo useradd --system --gid trap-dashboard --home /nonexistent \
  --shell /usr/sbin/nologin trap-dashboard 2>/dev/null || true
getent group suricata
sudo install -d -m 0750 \
  /etc/trap \
  /etc/adaptive-defender \
  /var/lib/trap \
  /var/log/trap \
  /var/lib/adaptive-defender \
  /var/log/adaptive-defender
sudo chown -R root:root /opt/trap
sudo chown trap-dashboard:trap-dashboard /var/lib/trap /var/log/trap
sudo install -d -o trap-dashboard -g trap-dashboard -m 0700 /var/lib/trap/dashboard-users
```

## 3. สร้างค่าตั้งสำหรับระบบจริง

```bash
sudo cp /opt/trap/config/trap.example.json /etc/trap/trap.json
sudo editor /etc/trap/trap.json
```

แทนค่า `CHANGE_ME` ทุกจุดด้วยชื่อ interface ที่ตรวจพบจริง จากนั้นสร้างบัญชี
Master Admin โดยให้คำสั่งถามรหัสผ่านผ่าน terminal:

```bash
cd /opt/trap
sudo python3 -m defender.dashboard.manage_users \
  --file /var/lib/trap/dashboard-users/users.json \
  --username admin \
  --name "Master Admin" \
  --role master_admin
sudo chown trap-dashboard:trap-dashboard /var/lib/trap/dashboard-users/users.json
sudo chmod 0600 /var/lib/trap/dashboard-users/users.json
```

ห้ามเก็บรหัสผ่าน plain text ใน repository หรือ service unit

Master Admin จัดการบัญชี `User` ต่อได้จากเมนู **จัดการบัญชี** ใน Dashboard:
เลือกแท็บย่อย **ผู้ใช้งาน**, **สร้าง User** หรือ **บัญชีของฉัน**
เพื่อสร้างบัญชี, ระงับ/เปิดใช้ และรีเซ็ตรหัสผ่าน สามารถกำหนดรหัสผ่านเริ่มต้นเอง
หรือเว้นว่างให้ระบบสุ่มให้ (แสดงครั้งเดียว) ให้ส่งผ่านช่องทางส่วนตัว
ผู้ใช้เปลี่ยนรหัสผ่านของตนเองได้จากเมนูเดียวกัน
ไม่มีหน้าสมัครบัญชีสาธารณะ และสร้าง Master Admin เพิ่มผ่านหน้าเว็บไม่ได้

หากอัปเกรดจากการติดตั้งเดิมที่เก็บบัญชีไว้ที่ `/etc/trap/users.json`
ให้คัดลอกไฟล์ไปยังพาธใหม่ แล้วแก้ `security.users_file` ใน
`/etc/trap/trap.json` ก่อนรีสตาร์ตบริการ:

```bash
sudo install -o trap-dashboard -g trap-dashboard -m 0600 \
  /etc/trap/users.json /var/lib/trap/dashboard-users/users.json
sudo systemctl restart trap-dashboard
```

## 4. รันด่านตรวจสอบ

```bash
cd /opt/trap
python3 -m unittest discover -s tests -v
python3 -m defender.validation.production \
  --config /etc/trap/trap.json --pretty
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
sudo cp /opt/trap/defender/decision_engine/systemd/adaptive-defender.service \
  /etc/systemd/system/adaptive-defender.service
sudo cp /opt/trap/defender/decision_engine/config/live.json \
  /etc/adaptive-defender/live.json
sudo cp /opt/trap/defender/dashboard/systemd/trap-dashboard.service \
  /etc/systemd/system/trap-dashboard.service
sudo cp /opt/trap/deploy/logrotate/trap /etc/logrotate.d/trap
sudo systemctl daemon-reload
```

ตรวจ unit ก่อนเปิด:

```bash
sudo systemd-analyze verify \
  /etc/systemd/system/adaptive-defender.service \
  /etc/systemd/system/trap-dashboard.service
```

## 7. เปิดบริการทีละตัว

```bash
sudo systemctl enable --now adaptive-defender
sudo systemctl --no-pager --full status adaptive-defender
sudo systemctl enable --now trap-dashboard
sudo systemctl --no-pager --full status trap-dashboard
```

ตรวจ Dashboard จากเครื่องเดียวกัน:

```bash
curl -I http://127.0.0.1:9090/
journalctl -u adaptive-defender -u trap-dashboard --since today
```

Dashboard ต้องไม่ listen บน `0.0.0.0` หรือ IP ของ outer/inner interface

## 8. ตรวจหลังเริ่มระบบใหม่

```bash
sudo reboot
```

หลังเครื่องกลับมา:

```bash
systemctl is-active suricata nginx adaptive-defender trap-dashboard
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

## ติดตั้ง helper ให้ Dashboard มีผลจริง (กฎ + threshold)

หลัง sync source ไป `/opt/trap` แล้ว ให้รันบน Defender:

```bash
sudo sh /opt/trap/deploy/install-dashboard-helpers.sh --update-rules
```

สคริปต์จะ (1) ติดตั้งและเปิด `trap-apply-rules.path` เพื่อให้กฎที่อนุมัติใน Dashboard
ผ่าน `suricata -T` แล้วติดตั้ง/reload จริง (ถ้าไม่ผ่านจะคืนไฟล์เดิม) (2) ตั้ง
`rules.apply_dir` ใน `/etc/trap/trap.json` (3) ตั้ง `thresholds_path` และ
`scan_only_signatures` ใน engine config แล้วสร้าง `/var/lib/trap/engine/thresholds.json`
ที่ Dashboard เขียนได้ (4) `--update-rules` ติดตั้งไฟล์กฎของ repo ผ่าน helper เดียวกัน
ไฟล์ config เดิมถูกสำรองเป็น `*.bak.<เวลา>` ก่อนแก้ รันซ้ำได้
