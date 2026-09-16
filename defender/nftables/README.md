# D5 SSH/Telnet redirect safety gate

เทมเพลตนี้ไม่มี interface หรือ Cowrie endpoint ที่เดา ก่อน apply:

- ยืนยันชื่อ outer/inner ด้วย `ip -br link` และ routes ด้วย `ip route`;
- รับ Cowrie SSH IP/port, Telnet honeypot IP/port และ return routes จาก person 2;
- จับภาพ `sudo nft list ruleset` ไปยังการสำรองข้อมูลที่ root-only;
- render ไปยังไฟล์ staging และรัน `sudo nft -c -f STAGING_FILE`;
- เปิด VirtualBox console ไว้และเตรียม timed rollback ใน
  `docs/root-operations.md`;
- apply แล้วตรวจสอบ `nft list ruleset`, `tcpdump` บนทั้งสอง NICs *ที่สังเกตการณ์* และ
  `conntrack -L` โดยใช้เฉพาะ lab traffic ที่ได้รับอนุญาต

Rollback จะลบเฉพาะ `table inet adaptive_defender` แล้วกลับคืนสู่ ruleset
ก่อนการเปลี่ยนแปลงเท่านั้น การคงอยู่จะไม่ถูกเปิดใช้งานจนกว่าการทดสอบ runtime และ restore
จะผ่าน

## ค่า endpoint ที่ยืนยันแล้ว

SSH/Cowrie honeypot endpoint ที่ได้รับจาก lab operator:

```text
__COWRIE_IP__=10.10.10.2
__COWRIE_PORT__=2222
```

ใช้ `10.10.10.2` ใน nftables DNAT rules คำนำหน้า `/24` เป็นของการตั้งค่า
honeypot interface ไม่ใช่ใน DNAT destination Telnet ยังถูกบลอกจากการ render
จริงจนกว่า `__TELNET_IP__`, `__TELNET_PORT__`, `__OUTER_INTERFACE__` และ
`__INNER_INTERFACE__` จะได้รับการยืนยัน

## SSH-only render

ใช้ `generated/ssh-redirect.cowrie-2222.ssh-only.nft` เมื่อเฉพาะ SSH/Cowrie
redirect ได้รับอนุมัติ มันไม่มีกฎ Telnet ดังนั้น tokens ที่เหลืออยู่เพียง
`__OUTER_INTERFACE__` และ `__INNER_INTERFACE__`

Render tokens เหล่านั้นจากชื่อ NIC ที่สังเกตการณ์ แล้วตรวจสอบก่อน apply:

```bash
cp defender/nftables/generated/ssh-redirect.cowrie-2222.ssh-only.nft /tmp/ssh-redirect.nft
$EDITOR /tmp/ssh-redirect.nft
sudo nft -c -f /tmp/ssh-redirect.nft
sudo nft -f /tmp/ssh-redirect.nft
sudo nft add element inet adaptive_defender ssh_redirect '{ 192.0.2.30 timeout 1800s }'
```

แทนที่ `192.0.2.30` ด้วย IP ต้นทางที่ได้รับอนุญาตที่ควรถูก redirect
