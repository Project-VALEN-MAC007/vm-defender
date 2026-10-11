# Production (real) server — Project-Web

เครื่องที่ 3 ของ TRAP: ปลายทางของทราฟฟิกที่ Decision Engine ประเมินว่าเสี่ยงต่ำ

| บริการ | ที่อยู่ | ผู้ส่งต่อจาก Defender |
|---|---|---|
| เว็บจริง (WordPress + MariaDB ผ่าน Docker Compose) | `10.10.10.3:8080` | Nginx `real` → `http://10.10.10.3:8080` |
| SSH จริง (OpenSSH) | `10.10.10.3:22` | nftables DNAT จาก `192.168.56.10:22` |
| Telnet จริง (inetutils-telnetd) | `10.10.10.3:23` | nftables DNAT จาก `192.168.56.10:23` |

## เครือข่าย

- NIC 1: NAT (บริหาร/ติดตั้งแพ็กเกจ) — มี default route
- NIC 2: VirtualBox internal network `Project-Lab`, `10.10.10.3/24`, ไม่มี gateway
- Route กลับหาเครือข่ายผู้เชื่อมต่อผ่าน Defender: `192.168.56.0/24 via 10.10.10.1`
  (ไม่มี source NAT เพื่อให้ log ของเครื่องนี้เห็น IP จริงของผู้เชื่อมต่อ)

## ติดตั้งเว็บ

```bash
cd /opt/trap/production
cat > .env <<'ENV'
DB_PASSWORD=<สุ่มใหม่>
DB_ROOT_PASSWORD=<สุ่มใหม่>
ENV
chmod 600 .env
docker compose up -d
curl -fsS -o /dev/null -w '%{http_code}\n' http://10.10.10.3:8080/
```

ห้าม commit `.env`

## เว็บจริงใช้ company web app

ตั้งแต่รอบ 7 เว็บจริงใช้ `webapp/` (BACKEND=real) ชุดโค้ดเดียวกับเว็บลวง เพื่อให้หน้าเว็บตรงกัน
ไฟล์ `production/docker-compose.yml` (WordPress) เก็บไว้เป็นทางเลือกสำรอง

```bash
cd /opt/trap
docker build -f webapp/Dockerfile -t trap/web-app:local .
docker run -d --name trap-web --restart unless-stopped -e BACKEND=real \
  -p 10.10.10.3:8080:8080 trap/web-app:local
```
