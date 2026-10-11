# การตั้งค่า nftables สำหรับเปลี่ยนเส้นทาง

nftables รับคำสั่งจาก Decision Engine ผ่าน set ที่มี timeout เพื่อเปลี่ยนเส้นทาง
SSH/Telnet

## ชุดข้อมูลที่ระบบใช้

| Set | หน้าที่ |
|---|---|
| `ssh_redirect` | เปลี่ยน SSH ไปยัง endpoint ที่กำหนด |
| `telnet_redirect` | เปลี่ยน Telnet ไปยัง endpoint ที่กำหนด |

ทุก set ต้องใช้ `flags timeout` และมีอายุไม่เกินค่าที่กำหนดใน config

## ไฟล์

| ไฟล์ | การใช้งาน |
|---|---|
| `ssh-redirect.nft.template` | template หลัก ห้าม apply โดยตรง |
| `generated/ssh-redirect.cowrie-2222.ssh-only.nft` | ตัวอย่าง SSH-only ที่ยังต้องใส่ชื่อ interface |
| `generated/ssh-redirect.cowrie-2222.partial.nft` | partial render ห้าม apply จนแทน token ครบ |

## ขั้นตอนเตรียมไฟล์ก่อนนำไปใช้

```bash
cp defender/nftables/ssh-redirect.nft.template /tmp/trap.nft
$EDITOR /tmp/trap.nft
rg '__[A-Z0-9_]+__|PARTIAL RENDER' /tmp/trap.nft
sudo nft --check --file /tmp/trap.nft
```

คำสั่ง `rg` ต้องไม่พบข้อความ และ syntax check ต้องผ่านก่อน apply

## ขั้นตอนนำไปใช้

ต้องสำรอง ruleset และตั้ง timed rollback ตาม `docs/root-operations.md` ก่อน

```bash
sudo nft --file /tmp/trap.nft
sudo nft list table inet adaptive_defender
```

ทดสอบด้วย source IP ในเครือข่ายที่ได้รับอนุญาตเท่านั้น:

```bash
sudo nft add element inet adaptive_defender ssh_redirect \
  '{ 192.0.2.30 timeout 1800s }'
sudo nft list set inet adaptive_defender ssh_redirect
```

## การตรวจแพ็กเก็ต

ตรวจทั้งสอง interface พร้อมกัน:

```bash
sudo tcpdump -ni OUTER_INTERFACE 'tcp port 22 or tcp port 23'
sudo tcpdump -ni INNER_INTERFACE 'tcp port 2222 or tcp port 2323'
sudo conntrack -L
```

แทนชื่อ interface ด้วยค่าจริง ห้ามใช้ข้อความตัวอย่างใน production

## การย้อนคืน

ลบเฉพาะ table ของโครงการ แล้วคืน ruleset เดิม:

```bash
sudo nft flush table inet adaptive_defender 2>/dev/null || true
sudo nft -f /root/trap-backup/nftables.before.nft
```

ห้ามใช้ `nft flush ruleset` เพราะจะลบกฎของระบบอื่นด้วย

## Round 4 deployed lab

Render the template with outer `trap-out`, inner `enp0s8`, production
`10.10.10.3`, Cowrie SSH `10.10.10.2:2222` and Telnet `10.10.10.2:2223`.
Keep source-specific redirect-set DNAT rules before unconditional
production DNAT for TCP 22 and 23. Forward permits only established traffic
and the specified DNAT destinations, including production ports 22/23.
Preserve source addresses; both downstream VMs route 192.168.56.0/24 back
via 10.10.10.1. Management SSH enters the NAT NIC and does not match
`iifname trap-out`. Validate atomically with `nft -c -f` and keep a timed
rollback while applying. Persistent rules are `/etc/trap/redirect.nft`,
loaded by `trap-firewall.service`. Temporary redirect sets are managed
by the existing Engine.
