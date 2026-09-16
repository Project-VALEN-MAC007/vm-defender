# รายการตรวจส่วนเชื่อมต่อเครือข่ายสำหรับ VirtualBox

เอกสารนี้ใช้เมื่อเครื่อง Defender ทำงานบน VirtualBox หากใช้ hypervisor อื่นให้
รักษาหลักการเดียวกันคือ management, outer และ inner ต้องแยก network กัน

## ก่อนปิดเครื่อง

- บันทึกผล `ip -br link`, `ip -br addr` และ `ip route`
- ระบุ interface ที่มี default route เป็น management interface
- ตรวจว่ามีช่องทาง local console สำหรับกู้คืน

## เพิ่มอะแดปเตอร์

ปิด VM ก่อนแก้ virtual hardware

1. คง Adapter 1 เป็น network สำหรับบริหาร เช่น NAT
2. เพิ่ม Adapter 2 เป็น Internal Network สำหรับ outer traffic
3. เพิ่ม Adapter 3 เป็น Internal Network สำหรับ inner traffic
4. ห้ามเลือก Bridged Adapter สำหรับ outer/inner โดยไม่ผ่านการอนุมัติด้านความปลอดภัย
5. เปิด cable connected ให้ adapter ที่ต้องใช้งาน

ชื่อ network ตัวอย่าง:

```text
outer: mimic-outer
inner: mimic-inner
```

## หลังเปิดเครื่อง

```bash
ip -details -brief link
ip -brief address
ip route show table all
```

บันทึกชื่อและ MAC address ของ interface ใหม่ ตรวจว่าไม่มี default route แล้วจึง
กำหนด IP:

```text
outer = 192.168.56.10/24
inner = 10.10.10.1/24
```

ห้ามกำหนด gateway หรือ DNS ให้ outer/inner

## ก่อนนำโปรไฟล์เครือข่ายไปใช้

1. สำรอง Netplan/NetworkManager ตาม `docs/root-operations.md`
2. ตั้ง timed rollback
3. เปิด local console ค้างไว้
4. ตรวจ production config ว่าชื่อ interface ตรงกับค่าที่สังเกตจริง
5. apply ทีละ profile

## ผลที่ต้องตรวจ

```bash
ip -br addr
ip route
ping -c 2 192.168.56.10
ping -c 2 10.10.10.1
```

- management connectivity ต้องยังอยู่
- default route ต้องอยู่ที่ management interface เท่านั้น
- outer และ inner ต้องไม่เข้าถึงกันโดยตรงหากไม่มี policy ที่อนุญาต
- หากผลไม่ตรง ให้ปล่อย timed rollback ทำงานหรือกู้คืนผ่าน console
