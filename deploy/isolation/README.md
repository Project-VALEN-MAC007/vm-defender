# Isolation ของ lab (แก้ D1/D2 รอบ 8)

รอบ 8 พบว่า Honeypot VM, `cowrie` และ `web-honeypot` เปิดการเชื่อมต่อไป Web จริง
(10.10.10.3:22/23/8080) และ SSH ของ Defender (10.10.10.1:22) ได้ เพราะ Honeypot กับ Web อยู่ subnet
เดียวกัน traffic จึงไม่ผ่าน forward chain ของ Defender และทั้งสองเครื่องไม่มีกฎห้าม

ไฟล์ในโฟลเดอร์นี้ปิดทางนั้นทั้งสามเครื่อง แต่ละเครื่องใช้ table `inet trap_isolation` ของตัวเอง
แยกจากกฎของ Docker (iptables-nft) และ `adaptive_defender`: Docker ไม่เขียนทับ และ drop ใน table นี้
ชนะ accept ของ table อื่น จึงครอบคลุมพอร์ตที่ Docker publish ด้วย (ufw ทำไม่ได้)

| เครื่อง | ไฟล์ | สิ่งที่บังคับ |
|---|---|---|
| Honeypot 10.10.10.2 | `honeypot.nft` | ตัวเครื่องเปิดการเชื่อมต่อใหม่ไป 10.10.10.0/24 และ 192.168.56.0/24 ไม่ได้ · container ออกนอก bridge ของตัวเองไม่ได้ (lab, Defender, ตัวเครื่อง, อินเทอร์เน็ต) · รับการเชื่อมต่อใหม่จากวง lab เฉพาะ Defender |
| Web 10.10.10.3 | `web.nft` | รับการเชื่อมต่อใหม่จากวง lab เฉพาะ Defender ทั้งตัวเครื่องและ container `trap-web` |
| Defender 10.10.10.1 | `defender.nft` | ไม่รับการเชื่อมต่อใหม่จาก 10.10.10.2 ทุกพอร์ต |

ทางที่ระบบใช้ยังเปิดอยู่ทั้งหมด:

- Defender → Honeypot 22 (trap-sync), 8091 (deploy agent), 2222/2223 (DNAT), 8084 (Nginx)
- Defender → Web 8080 (Nginx) และ SSH/Telnet ที่ DNAT มา (ใช้ IP ผู้ใช้ 192.168.56.x จึงไม่โดนกฎ)
- `web-honeypot` → `web-app` บน network `decoy` (อยู่ bridge เดียวกัน)
- การตอบกลับทุกแบบ (established/related)
- NIC management (NAT, SSH 2221–2223 จาก host) ไม่ถูกแตะ Honeypot ยัง `apt` / `docker pull` ได้

## ติดตั้ง (root ทีละเครื่อง)

สำรอง ruleset ก่อน แล้วเลือกไฟล์ตามเครื่อง (`honeypot`, `web` หรือ `defender`)

```bash
sudo nft list ruleset > /root/trap-backup/nftables.before-isolation.nft
ROLE=honeypot   # web | defender
sudo install -m 0644 /opt/trap/deploy/isolation/$ROLE.nft /etc/trap/isolation.nft
sudo nft --check --file /etc/trap/isolation.nft
sudo cp /opt/trap/deploy/isolation/trap-isolation.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now trap-isolation
sudo nft list table inet trap_isolation
```

service โหลดก่อน `docker.service` และโหลดซ้ำได้ (ไฟล์ลบ table เดิมก่อนสร้างใหม่) ห้ามใช้
`nft flush ruleset` เพราะจะลบกฎของ Docker และ `adaptive_defender` ด้วย

ถอดออก: `sudo systemctl disable --now trap-isolation` (ลบเฉพาะ table นี้)

## ตรวจแบบไม่ต้องใช้ VM

```bash
unshare -rn --kill-child bash deploy/isolation/netns-test.sh deploy/isolation
```

จำลอง 3 เครื่องและ container ใน network namespace (ไม่ต้องเป็น root ไม่แตะเครื่องจริง) ทดสอบ
ทุกคู่ที่รอบ 8 FAIL และทางที่ระบบต้องใช้ ทุกบรรทัดต้องขึ้น `ok` ได้ผล 36/36 เมื่อ 11 ต.ค. 2026
รวมกรณีที่ถอดกฎบน Honeypot ออก (สมมติผู้โจมตีได้ root) แล้วกฎบน Web และ Defender ยังกันได้
ผลนี้ไม่แทนการทดสอบบน VM จริง: ไม่มี br_netfilter และ Docker จริงใน namespace

## สิ่งที่รอบ 9 ต้องวัด

1. D2 ซ้ำทั้ง catalog: ทุกคู่ที่รอบ 8 ได้ `FAIL isolation` ต้องเป็น timeout และ
   `nft list table inet trap_isolation` ต้องมี counter ขึ้นตรงกฎ
2. container ออกอินเทอร์เน็ต (1.1.1.1:443) ไม่ได้ ส่วน Honeypot host ยังออกทาง NAT ได้
3. D4 ซ้ำ: redirect SSH/HTTP, Rabbit Hole, web-honeypot → web-app, trap-sync, deploy agent ต้องผ่านเหมือนเดิม
4. low-risk SSH/Telnet ไป Web จริงยังเข้าได้ และ Nginx → Web 8080 ยัง 200
5. `cowrie` ขึ้นได้ด้วย `read_only: true` (ดู `docker logs cowrie` ว่าไม่มี error เขียนไฟล์) และ D3 ซ้ำ
6. reboot Honeypot หนึ่งครั้ง แล้วตรวจว่า table ยังอยู่และ container กลับมาฟังพอร์ต

## ข้อจำกัดที่ยังเหลือ

- ถ้าผู้โจมตีได้ root บน Honeypot VM จะถอดกฎบนเครื่องนั้นได้ จึงต้องมีกฎบน Web และ Defender ด้วย
  แต่ยังปลอม source เป็น 192.168.56.x ส่งตรงไป Web ได้ (ไม่ได้ handshake กลับเพราะคำตอบวิ่งไป Defender)
  ถ้าจะปิดสนิทต้องแยก Honeypot ไว้คนละ subnet/VLAN ให้ทุก packet ผ่าน Defender
- `web-honeypot` ยัง mount `/var/lib/trap` (ro) และ `/var/log/trap` (rw) ทั้งโฟลเดอร์ เพราะ
  `rabbit-hole.json` ถูกแทนแบบ atomic (rsync) และ logrotate สร้างไฟล์ log ใหม่ mount ทีละไฟล์จึงตามไม่ทัน
  การแคบลงต้องย้าย config/secret/log ไปโฟลเดอร์เฉพาะ ซึ่งยังไม่ได้ทำ

## ปุ่ม Clone ใน Dashboard

เดิม deploy agent สั่ง container ของ SNARE บน Honeypot ไปดึงเว็บจริง ซึ่งเป็นทางที่ isolation ปิด ตอนนี้
**Defender เป็นคน clone** (`defender/deploy_agent/clone.py` ใน Dashboard) แล้วส่งสำเนาไปที่
`POST /v1/versions` ของ agent ผ่านพอร์ต 8091 ทิศ Defender → Honeypot ที่เปิดอยู่แล้ว Honeypot จึงไม่ต้อง
ต่อเว็บจริงและไม่ต้องยกเว้นกฎใด ๆ ตั้ง host ที่ clone ได้ใน `web_deploy.allowed_targets` ของ `trap.json`
