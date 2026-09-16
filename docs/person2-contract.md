# สัญญาข้อมูลระหว่าง Defender กับบริการภายใน

ไฟล์นี้คงชื่อเดิมไว้เพื่อรองรับลิงก์เก่า เนื้อหานี้ไม่ผูกกับบุคคล ผู้ดูแล
บริการภายในต้องส่งค่าที่ตรวจสอบจากเครื่องจริง และ Defender ต้องตรวจการเข้าถึง
ผ่าน inner network ก่อนเปิด redirect

## ข้อมูลจุดเชื่อมต่อ

```json
{
  "schema_version": "1.0",
  "service_host": {
    "ip": "REQUIRED",
    "interface": "REQUIRED",
    "return_route_via": "REQUIRED"
  },
  "profiles": {
    "wordpress": {
      "port": "REQUIRED",
      "health_path": "REQUIRED",
      "expected_status": "REQUIRED"
    },
    "phpmyadmin": {
      "port": "REQUIRED",
      "health_path": "REQUIRED",
      "expected_status": "REQUIRED"
    },
    "cowrie": {
      "ip": "REQUIRED",
      "port": "REQUIRED",
      "health_method": "REQUIRED",
      "json_log_path": "REQUIRED"
    },
    "telnet": {
      "ip": "REQUIRED",
      "port": "REQUIRED",
      "health_method": "REQUIRED",
      "json_log_path": "REQUIRED"
    }
  }
}
```

คำว่า `REQUIRED` หมายถึงยังห้ามนำ config ไปใช้จริง ห้ามเดาค่า endpoint

## รูปแบบเหตุการณ์มาตรฐาน

| ฟิลด์ | ความหมาย |
|---|---|
| `timestamp` | เวลา ISO 8601 พร้อม timezone offset |
| `source_ip` | IP ต้นทาง |
| `destination_port` | พอร์ตปลายทาง |
| `protocol` | `http`, `tls`, `ssh`, `telnet` หรือ `scan` |
| `signature_id` | SID ของ Suricata |
| `severity` | ระดับความรุนแรงจาก alert |
| `risk_score` | คะแนนสะสม 0–100 |
| `profile` | profile ปลายทางที่เลือก |
| `action` | action จาก Decision Engine |
| `reason` | เหตุผลและคะแนนประกอบการตัดสินใจ |

นาฬิกาของทุกเครื่องต้องซิงก์ด้วย NTP เพื่อให้ลำดับเหตุการณ์ถูกต้อง

## ข้อมูลกฎผู้สมัคร

```json
{
  "rule_id": "REQUIRED",
  "version": "REQUIRED",
  "status": "candidate",
  "evidence": "REDACTED_REFERENCE_REQUIRED",
  "confidence": 0.0,
  "reviewer": "REQUIRED",
  "expected_sid": "REQUIRED",
  "rule": "REQUIRED",
  "test_pcap": "REQUIRED",
  "quality_report": "REQUIRED"
}
```

หลักฐานต้องอ้างอิงแบบตัดข้อมูลลับออก ห้ามใส่ credential จริงลงใน candidate
