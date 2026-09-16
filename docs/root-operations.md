# คู่มือคำสั่งที่ต้องใช้สิทธิ์ root

คำสั่งในเอกสารนี้เปลี่ยน network, firewall หรือ service ของเครื่องจริง
ให้ทำผ่าน local console และตรวจ target ทุกครั้ง ห้ามรันทั้งไฟล์แบบอัตโนมัติ

## 1. เก็บสถานะก่อนเปลี่ยน

```bash
sudo install -d -m 0700 /root/mimic-backup
sudo cp -a /etc/netplan /root/mimic-backup/netplan
sudo cp -a /etc/NetworkManager/system-connections \
  /root/mimic-backup/system-connections
sudo nft list ruleset | sudo tee /root/mimic-backup/nftables.before.nft
sudo sysctl net.ipv4.ip_forward | \
  sudo tee /root/mimic-backup/ip-forward.before.txt
ip -br link
ip -br addr
ip route
```

ตรวจว่าไฟล์สำรองมีข้อมูล:

```bash
sudo test -s /root/mimic-backup/nftables.before.nft
sudo ls -la /root/mimic-backup
```

## 2. ตั้ง timed rollback

เปิด console ค้างไว้ แล้วตั้งงานกู้คืนก่อน apply network/firewall:

```bash
sudo systemd-run \
  --unit mimic-network-rollback \
  --on-active=3m \
  /bin/sh -c 'cp -a /root/mimic-backup/netplan/. /etc/netplan/; netplan apply; nft -f /root/mimic-backup/nftables.before.nft'
```

ยกเลิก timer เฉพาะเมื่อ console, management route และ service สำคัญยังทำงาน:

```bash
sudo systemctl stop mimic-network-rollback.timer
```

## 3. เปิดใช้ Suricata config

สำรองไฟล์เดิมและตรวจ syntax ก่อน restart:

```bash
sudo cp -a /etc/suricata/suricata.yaml \
  /etc/suricata/suricata.yaml.bak.$(date -u +%Y%m%dT%H%M%SZ)
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
sudo systemctl --no-pager --full status suricata
sudo test -s /var/log/suricata/eve.json
```

หาก syntax test ไม่ผ่าน ห้าม restart

## 4. เปิดใช้ Nginx

```bash
sudo cp -a /etc/nginx /root/mimic-backup/nginx
sudo install -d -m 0750 /etc/adaptive-defender/tls
sudo install -d -m 0755 /etc/nginx/maps
sudo sh -c 'printf "%s\n" "# generated atomically; do not edit" "default real;" > /etc/nginx/maps/redirect_map.conf'
sudo nginx -t
sudo systemctl reload nginx
```

หาก reload แล้ว health check ล้มเหลว:

```bash
sudo cp -a /root/mimic-backup/nginx/. /etc/nginx/
sudo nginx -t
sudo systemctl reload nginx
```

## 5. ตรวจและนำ nftables ไปใช้

สร้าง staging file ที่แทน token ครบแล้ว จากนั้นตรวจโดยยังไม่เปลี่ยนระบบ:

```bash
rg '__[A-Z0-9_]+__|PARTIAL RENDER' /tmp/mimic.nft
sudo nft --check --file /tmp/mimic.nft
```

คำสั่ง `rg` ต้องไม่พบ token และ `nft --check` ต้องคืน exit code 0 จึง apply:

```bash
sudo nft --file /tmp/mimic.nft
sudo nft list table inet adaptive_defender
```

## 6. กู้คืนฉุกเฉิน

รันจาก local console:

```bash
sudo cp -a /root/mimic-backup/netplan/. /etc/netplan/
sudo netplan generate
sudo netplan apply
sudo nft flush table inet adaptive_defender 2>/dev/null || true
sudo nft -f /root/mimic-backup/nftables.before.nft
sudo sysctl -w net.ipv4.ip_forward=0
```

ตรวจหลังคืนค่า:

```bash
ip -br addr
ip route
sudo nft list ruleset
systemctl is-active suricata nginx
```

## ข้อห้าม

- ห้าม apply ไฟล์ที่ยังมี token
- ห้ามใช้ interface ที่มี default route เป็น outer หรือ inner
- ห้ามลบ ruleset ทั้งหมดเพื่อแก้ปัญหาเฉพาะ table
- ห้ามยกเลิก rollback timer ก่อนตรวจ management connectivity
- ห้ามใช้ค่า path หรือชื่อ interface จากเครื่องอื่นโดยไม่ตรวจซ้ำ
