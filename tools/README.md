# tools/ — ใช้ในแล็บเท่านั้น

## jev_mock.py

mock API ของ Jev สำหรับเดโม/ออฟไลน์ (`POST /v1/systemone` รูปร่างเดียวกับของจริง)
ตอบต่างกันตาม `state` ที่ planner ส่งมา — ใช้เฉพาะเมื่อไม่มีคีย์จริงหรือเน็ตไม่ออก

```bash
# ตัวอย่าง service (lab):
#   ExecStart=/usr/bin/python3 /opt/trap-mock-jev-disabled/trap-mock/jev_mock.py
#   ต้องมี Authorization: Bearer <อะไรก็ได้>
# เปิดใช้: ตั้ง ai.api_url = http://127.0.0.1:18081/v1/systemone แล้ว restart planner
```

**ห้ามใช้ใน production** — ไม่ตรวจคีย์, ไม่มี rate limit, และคำตอบเป็น heuristic
