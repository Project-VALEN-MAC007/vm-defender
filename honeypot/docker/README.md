# Honeypot ใน Docker — แยก container ต่อ decoy

| container | พอร์ตบน 10.10.10.2 | log บนเครื่อง Honeypot |
|---|---|---|
| `cowrie` (SSH/Telnet) | 2222, 2223 | `/var/log/cowrie/cowrie.json` |
| `web-honeypot` (Rabbit Hole web, ด่านหน้า) | 8084 | `/var/log/trap/rabbit-hole-web.jsonl` |
| `web-app` (เว็บบริษัทลวง BACKEND=decoy) | ไม่ publish (internal) | ผ่าน web-honeypot |

log อยู่บน host (bind mount) จึงไม่หายเมื่อ container ถูกสร้างใหม่ และ `deploy/trap-sync.sh`
บน Defender ดึง path เดิมได้ตามปกติ

## เว็บลวงให้เหมือนเว็บจริง

`web-app` คือเว็บบริษัทชุดโค้ดเดียวกับ Project-Web (BACKEND=decoy = ข้อมูลปลอม) อยู่บน network
`decoy` ที่ปิดการออกเน็ต มีแค่ `web-honeypot` (Rabbit Hole) คุยด้วย ตั้งใน `/var/lib/trap/rabbit-hole.json`:

```json
"web": { "host": "0.0.0.0", "trusted_proxies": ["10.10.10.1/32"], "upstream": "http://web-app:8080" }
```

Rabbit Hole ตอบเส้นทางลวงเอง (`/backup/`, `/.env`, `/api/...`) ส่วน request อื่นส่งต่อให้ web-app
ทำให้หน้าแรก/หน้า 404/หน้า login เหมือนเว็บจริง แต่ยัง log ครบที่ `rabbit-hole-web.jsonl`
build: `docker compose -p trap-honeypot -f compose.yaml build web-honeypot web-app`

## Hardening และ isolation

ทุก container: non-root, `cap_drop: ALL`, `no-new-privileges`, root filesystem `read_only`
(Cowrie เขียนได้เฉพาะ log bind mount, volume `cowrie-var` และ `/tmp`)

Docker ไม่ได้กัน container ออกนอกเครื่อง (default bridge มี MASQUERADE) และข้าม ufw สำหรับพอร์ตที่
publish จึงใช้ `deploy/isolation/honeypot.nft` แทน: container ออกนอก bridge ตัวเองไม่ได้ และรับการ
เชื่อมต่อใหม่จากวง lab เฉพาะ Defender ดู `deploy/isolation/README.md`

## การกู้คืนอัตโนมัติ

1. **Docker restart policy** (`unless-stopped`): process ใน container ตาย → Docker เริ่มใหม่ภายในไม่กี่วินาที
2. **watchdog** (`trap-honeypot-watchdog.timer` ทุก 20 วินาที) สร้าง **container ใหม่** จาก image ที่ pin ไว้เมื่อ
   - container หาย, หยุด, dead หรือ paused → ทันที
   - ติดวนรีสตาร์ต (crash loop) → ทันที
   - ยังรันแต่มี process ถูกหยุด (state T เช่นโดน SIGSTOP) หรือพอร์ตไม่ฟัง 3 รอบติด (~1 นาที) → สร้างใหม่

ข้อจำกัด: process ที่ยังรันและพอร์ตยังฟังแต่ค้างภายใน (deadlock) ตรวจไม่ได้โดยไม่เชื่อมต่อเข้าไป

container ที่เพิ่ง start ไม่ถึง `--grace` วินาที (ค่าเริ่ม 120) และพอร์ตยังไม่ฟัง จะไม่ถูกนับว่าผิดปกติ
(รอบ 5 วัดได้ว่า Cowrie ใช้ ~1 นาทีกว่าจะฟังพอร์ต) เพื่อไม่ให้ watchdog สร้างใหม่ซ้ำก่อน container ขึ้นเสร็จ
ส่วน process ที่ถูกหยุด (state T) ไม่ได้รับการยกเว้นนี้ ตอนสร้างใหม่ใช้ stop timeout 3 วินาที (`--stop-timeout`)

watchdog ตรวจพอร์ตจาก network namespace ของ container (`nsenter … ss -ltn`) ไม่เชื่อมต่อเข้า decoy
เพื่อไม่ให้ Cowrie/เว็บลวงบันทึกการตรวจเป็นผู้เข้าชม ทุกการกระทำบันทึกที่ `/var/log/trap/honeypot-watchdog.jsonl`

## ติดตั้ง (root บน Project-Honeypot)

```bash
apt-get install -y docker.io docker-compose-v2      # หรือ Docker CE
cd /opt/trap/honeypot/docker
cp .env.example .env            # COWRIE_IMAGE=cowrie/cowrie@sha256:<digest>, RABBIT_UID/GID = id -u/-g traprabbit
install -d /etc/trap/cowrie /var/log/cowrie /var/lib/trap/cowrie-fs
cp cowrie.cfg.example /etc/trap/cowrie/cowrie.cfg   # แล้วย้ายค่าที่ใช้อยู่จาก /opt/cowrie มา
#   ตรวจชื่อ option กับ src/cowrie/data/etc/cowrie.cfg.dist ในอิมเมจ
#   ([shell] filesystem, [honeypot] contents_path)
# userdb.txt → /etc/trap/cowrie/; fs.pickle และ honeyfs/ → /var/lib/trap/cowrie-fs/ (mount ทั้งโฟลเดอร์)
# ให้ uid ของ cowrie ในอิมเมจเขียน /var/log/cowrie ได้; web-honeypot รันด้วย uid ของ traprabbit
#   จึงอ่าน secret (0600) และเขียน /var/log/trap ได้โดยไม่ต้องเปลี่ยนเจ้าของไฟล์
docker compose -p trap-honeypot -f compose.yaml build web-honeypot
systemctl disable --now cowrie trap-rabbit-hole     # ปิด service แบบเดิม (ไม่ลบ ใช้ย้อนกลับได้)
docker compose -p trap-honeypot -f compose.yaml up -d
cp trap-honeypot-watchdog.service trap-honeypot-watchdog.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now trap-honeypot-watchdog.timer docker
# isolation (ต้องมี ก่อนเปิดให้ผู้โจมตีเข้า)
install -m 0644 /opt/trap/deploy/isolation/honeypot.nft /etc/trap/isolation.nft
cp /opt/trap/deploy/isolation/trap-isolation.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now trap-isolation
```

`trap-cowrie-sync.service` (honeypot/rabbit-hole) ใช้ `docker restart cowrie` และ path
`/var/lib/trap/cowrie-fs` ตรงกับ compose นี้อยู่แล้ว

อิมเมจ Cowrie v3.1.1 ที่ตรวจบน VM ใช้ distroless ไม่มี `/bin/sh` และรันเป็น UID/GID
`999:999` โดย `etc/` เป็นที่วาง config override ส่วน config ค่าเริ่มต้นอยู่ที่
`/cowrie/cowrie-git/src/cowrie/data/etc/cowrie.cfg.dist` ตรวจอิมเมจที่ pin จริงผ่าน Python:

```bash
docker run --rm --entrypoint /cowrie/cowrie-env/bin/python3 "$COWRIE_IMAGE" \
  -c 'import os,pathlib; print(os.getuid()); print(pathlib.Path("/cowrie/cowrie-git/src/cowrie/data/etc/cowrie.cfg.dist").read_text())'
```

ถ้าเครื่องเดิมใช้ account หรือ config path ต่างจาก compose ให้สำรองก่อนย้าย config
มา `/var/lib/trap/rabbit-hole.json` และจัดสิทธิ์ให้ UID/GID ของ `traprabbit` อ่าน secret
และเขียน log ได้ รวมทั้งแก้ exporter และตัว sync ของ lab ให้ใช้ config และ log path ใหม่
โดยให้ Dashboard เป็นต้นทางของ scenario เพื่อไม่เขียนทับการแก้ไขด้วย config เก่าจาก Honeypot

## ย้อนกลับ

```bash
systemctl disable --now trap-honeypot-watchdog.timer
docker compose -p trap-honeypot -f compose.yaml down
systemctl enable --now cowrie trap-rabbit-hole
```
