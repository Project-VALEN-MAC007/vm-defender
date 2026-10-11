# แบบเครือข่ายของ TRAP Defender

## หลักการ

เครื่อง Defender ต้องมี interface สามบทบาทแยกจากกัน เพื่อไม่ให้ทราฟฟิกทดสอบ
กระทบช่องทางบริหาร และเพื่อป้องกันการเข้าถึงเครือข่ายภายในโดยตรง

```text
เครือข่ายบริหาร/ติดตั้ง
        |
management interface (มี default route)
        |
   TRAP Defender
        | outer: 192.168.56.10/24
เครือข่ายรับทราฟฟิก
        |
แหล่งทราฟฟิกที่ได้รับอนุญาต

   TRAP Defender
        | inner: 10.10.10.1/24
เครือข่ายบริการภายใน
        |
endpoint ที่ยืนยันแล้ว
```

## ค่าตัวอย่าง

| บทบาท | IP ตัวอย่าง | Default route | DNS |
|---|---|---|---|
| management | ได้จากระบบบริหาร เช่น NAT/DHCP | มี | มีได้ |
| outer | `192.168.56.10/24` | ไม่มี | ไม่มี |
| inner | `10.10.10.1/24` | ไม่มี | ไม่มี |

ค่า IP เป็นค่าเริ่มต้นของแบบระบบ ส่วนชื่อ interface ต้องอ่านจากเครื่องจริงด้วย
`ip -br link` และใส่ใน production config ห้ามสมมติว่าเป็น `enp0s8` หรือ
`enp0s9`

## นโยบายการส่งต่อ

- ก่อนเปิด redirect ให้คง `net.ipv4.ip_forward=0`
- เมื่อเปิดใช้งาน ให้ forward policy เป็น `drop`
- อนุญาตเฉพาะ established/related traffic และ DNAT flow ที่ระบุไว้
- ห้ามเปิดการ route ทั่วไประหว่าง outer กับ inner
- redirect set ต้องมี timeout

## ด่านตรวจก่อนนำไปใช้

ต้องผ่านทุกข้อ:

1. management, outer และ inner เป็นคนละ interface
2. management interface ยังเป็นเจ้าของ default route เพียงตัวเดียว
3. outer/inner ไม่มี gateway และ DNS
4. สำรอง network และ nftables แล้ว
5. ตั้ง timed rollback แล้ว
6. ไม่มี `CHANGE_ME` หรือ `__TOKEN__` ใน staging config
7. ผ่าน `python3 -m defender.validation.production`

ขั้นตอนเตรียม interface อยู่ที่ `defender/network/virtualbox-nic-checklist.md`
และคำสั่ง root อยู่ที่ `docs/root-operations.md`

## Lab deployed in round 4 (2026-10-10)

```text
trap-attacker namespace (no default route)
  -> 192.168.56.10 [Project-Defender: Suricata / Engine / Nginx / nftables]
       inner 10.10.10.1, VirtualBox Project-Lab
       |-- low risk -> Project-Web 10.10.10.3:8080 / :22 / :23
       `-- redirected -> Project-Honeypot 10.10.10.2:8084 / :2222 / :2223
```

Management uses each VM's NAT NIC: host SSH 2221 (Defender), 2222
(Honeypot), 2223 (Web). Defender outer NIC is `trap-out` (veth to the
namespace), inner NIC is `enp0s8`. Project-Web has 2 vCPUs / 2 GB RAM.
The Web lab NIC has only 10.10.10.3/24, no gateway or DNS, and a persistent
192.168.56.0/24 route via 10.10.10.1. SSH/Telnet DNAT preserves client IP;
there is no source NAT on Defender. Production WordPress/MariaDB run in
Docker Compose on Project-Web. Real SSH uses OpenSSH; real Telnet uses
inetutils-telnetd with /bin/login. Local Defender web/Telnet fixtures are
not production services.
