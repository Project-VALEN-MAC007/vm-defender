# การตั้งค่า Nginx สำหรับเปลี่ยนเส้นทางเว็บ

Nginx รับ HTTP/HTTPS ที่ outer IP เลือก backend จาก source IP ใน
`redirect_map.conf` และบันทึกผลให้ตรวจสอบย้อนหลังได้

## ไฟล์

| ไฟล์ | หน้าที่ |
|---|---|
| `adaptive-honeypot.conf.template` | template ที่ต้องแทน token ก่อนใช้ |
| `generated/adaptive-honeypot.http.conf` | generated config สำหรับ outer IP ตัวอย่าง |
| `generated/redirect_map.conf` | map ที่ Decision Engine จัดการ |
| `redirect_map.conf.example` | ตัวอย่างรูปแบบ map |

## ค่าที่ต้องยืนยัน

- outer IP ของ Defender
- certificate และ private key
- Real Web: `10.10.10.3:8080`
- WordPress Honeypot: `10.10.10.2:8081`
- phpMyAdmin Honeypot: `10.10.10.2:8082`
- SNARE + TANNER: SNARE ที่ `10.10.10.2:8083` (IP ตัวอย่าง ต้องแทนด้วยเครื่อง Honeypot จริง)
- Rabbit Hole web decoy: `10.10.10.2:8084` (IP ตัวอย่าง ดู `docs/rabbit-hole.md`)
- health path ของทุก backend
- path ของ redirect map

- profile ที่ใช้กับคำขอที่ติด prefilter (`__PREFILTER_PROFILE__`) ให้ตรงกับ
  `web_profile` ของ Decision Engine เช่น `rabbithole` หรือ `snare`

ห้ามเดาค่า endpoint และห้ามใช้ config ที่ยังมี `__TOKEN__`

ต้นแบบต้องแทนค่า `__REAL_WEB_IP__`, `__REAL_WEB_PORT__`,
`__WORDPRESS_IP__`, `__WORDPRESS_PORT__`, `__PHPMYADMIN_IP__` และ
`__PHPMYADMIN_PORT__` ก่อนติดตั้ง ห้ามแก้ไฟล์ใน `generated/` แล้วถือเป็น
แหล่งตั้งค่าหลัก

แทน `__SNARE_IP__` และ `__SNARE_PORT__` ด้วย endpoint ของ SNARE ด้วย
config ของ Decision Engine ทั้ง `lab.json` และ `live.json` เลือก
`web_profile: "snare"` แล้ว คำขอเว็บที่ถึงเกณฑ์ redirect จึงไป SNARE;
SNARE ส่งคำขอให้ TANNER วิเคราะห์ภายใน Docker network ไม่ proxy ไป TANNER โดยตรง
ดูขั้นตอนติดตั้งใน `honeypot/snare-tanner/README.md` และเริ่มด้วย lab dry-run ก่อน

แทน `__RABBIT_HOLE_IP__` และ `__RABBIT_HOLE_PORT__` ด้วย endpoint ของ Rabbit Hole web decoy
ถ้าต้องการให้คำขอเว็บที่ถึงเกณฑ์ไปที่เส้นทางลวงต่อเนื่อง ให้ตั้ง `web_profile: "rabbithole"`
Template ส่ง `X-Real-Port` และ `X-Forwarded-Port` เพิ่ม เพื่อให้ decoy บันทึกพอร์ตต้นทางและปลายทางได้
decoy จะเชื่อ header เหล่านี้เฉพาะเมื่อ peer อยู่ใน `web.trusted_proxies` ของ `rabbit-hole.json`

## ขั้นตอนตรวจสอบ

```bash
rg '__[A-Z0-9_]+__' /etc/nginx/sites-available/trap
curl -fsS http://BACKEND_IP:BACKEND_PORT/HEALTH_PATH
sudo nginx -t
```

ผ่านครบแล้วจึง reload:

```bash
sudo systemctl reload nginx
sudo systemctl --no-pager --full status nginx
```

## ตรวจคำขอก่อนส่งต่อ (prefilter)

เดิม Nginx เลือกปลายทางจาก source IP อย่างเดียว IP จะถูกเพิ่มลง map ก็ต่อเมื่อ
Suricata แจ้งเตือนและ Decision Engine ตัดสินแล้ว คำขอแรกที่ทำให้เกิด alert จึงถึง
เว็บจริงก่อนเสมอ เพราะ Suricata ทำงานแบบ IDS และไม่ได้ทำให้คำขอรอผล

prefilter ให้ Nginx ดูเนื้อหาของคำขอเองก่อน proxy ถ้า URL หรือ User-Agent ตรงรูปแบบ
ที่อันตรายในตัว คำขอนั้นจะไป `__PREFILTER_PROFILE__` ทันทีตั้งแต่ครั้งแรก

ลำดับการตัดสินใจ:

1. IP อยู่ใน map ของ Decision Engine → ใช้ profile นั้นเสมอ
2. ไม่อยู่ใน map แต่คำขอตรง prefilter → ไป honeypot เฉพาะคำขอนั้น
3. ไม่เข้าทั้งสองข้อ → `real`

รูปแบบที่ใช้ลอกมาจากกฎ ET Open ที่ Decision Engine redirect ได้จาก alert เดียวอยู่แล้ว
(คะแนนถึง 40) จึงไม่เพิ่ม false positive ใหม่นอกเหนือนโยบายเดิม:

| รูปแบบ | ตรวจที่ | กฎต้นแบบ |
|---|---|---|
| `.htpasswd` | path (decode แล้ว) และ URI ดิบ | 2101071 |
| `union ... select ... ;` | URI | 2006446 |
| `(Nikto` | User-Agent | 2002677 (Suricata รอ 5 ครั้งใน 60 วินาที) |
| ขึ้นต้นด้วย `sqlmap` | User-Agent | 2008538 |
| `Nmap NSE` | User-Agent | 2009359 |

ไม่ใส่ `.env`, `/etc/passwd` และ Masscan เพราะ Decision Engine ให้แค่ `monitor`
เมื่อเจอครั้งเดียว Suricata ยังเห็นคำขอเดิมและแจ้งเตือนตามปกติ IP จึงถูกเพิ่มลง map
สำหรับคำขอถัดไปทุกคำขอ ช่อง `prefilter` ใน access log บอกว่าคำขอนั้นติด prefilter (1)
หรือไม่ (0)

ข้อจำกัด: ตรวจได้เฉพาะ HTTP/HTTPS และเฉพาะรูปแบบที่เขียนไว้ ไม่เห็น request body
(SQLi ใน body ยังพึ่ง Suricata) SSH/Telnet ยังใช้ nftables ตาม IP เหมือนเดิม

## ผลที่คาดหวัง

| กรณี | ผล |
|---|---|
| HTTP | redirect ไป HTTPS |
| source ไม่มี mapping | ใช้ profile `real` |
| source ไม่มี mapping แต่คำขอตรง prefilter | ใช้ `__PREFILTER_PROFILE__` เฉพาะคำขอนั้น |
| source มี mapping | ใช้ backend ตาม profile |
| backend ใช้งานไม่ได้ | ตอบ managed `503` |
| config ผิด | `nginx -t` ไม่ผ่านและห้าม reload |

กำหนดเวลารอเชื่อมต่อ `5s` และเวลารอการตอบกลับ `30s` เพื่อรองรับ backend
ที่อยู่หลัง overlay network โดยไม่ปล่อยให้การเชื่อมต่อค้างนานเกินไป

## ตารางเปลี่ยนเส้นทาง

Decision Engine เขียน map แบบ atomic และเก็บ expiry ใน state file คู่กัน
เมื่อ restart ระบบจะโหลด state กลับและลบรายการที่หมดอายุ

ตัวอย่าง:

```nginx
# generated atomically; do not edit
default real;
192.0.2.30 snare;
```

## การย้อนคืน

หาก validation หรือ reload ล้มเหลว adapter จะคืน map ก่อนหน้า สำหรับการคืน
Nginx ทั้งชุดให้ใช้ backup และคำสั่งใน `docs/root-operations.md`

## Round 4 deployed lab

The rendered `/etc/nginx/conf.d/trap.conf` uses both `default` and `real`
backend `http://10.10.10.3:8080` on Project-Web. Honeypot profiles currently
resolve to the observed Web decoy endpoint `10.10.10.2:8084`; the example
8081/8082/8083 endpoints above are not separately deployed in this lab.
HTTPS terminates on Defender and forwards X-Forwarded-Proto and client
address. This lab renders the template HTTP listener as a proxy so HTTP
and HTTPS can be tested independently; the upstream template's HTTP 308
policy is not the runtime lab policy. Use `nginx -t` before reload.
The Decision Engine readiness implementation was not changed for round 4.


## HTTPS inspection hop

พอร์ต 443 ไม่ส่งตรงไป backend แล้ว แต่ส่งผ่าน `127.0.0.1:18443` (ต่อจาก 127.0.0.2)
เพื่อให้ Suricata ตรวจคำขอที่ถอดรหัสแล้วได้ ตัวตัดสิน profile/upstream และ
`adaptive_access.json` อยู่ที่ server loopback (ใช้ realip จาก `X-Trap-Client-IP`
ที่เชื่อเฉพาะ 127.0.0.2) ส่วนขอบ TLS บันทึกที่ `adaptive_tls_edge.json`
ต้องมีโมดูล `ngx_http_realip_module` (มีใน nginx ของ Ubuntu) และตั้ง Suricata ตาม
`defender/suricata/https-inspection.yaml`
