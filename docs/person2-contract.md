# สัญญาข้อมูลระหว่าง Defender กับบริการภายใน

ไฟล์นี้คงชื่อเดิมไว้เพื่อรองรับลิงก์เก่า เนื้อหานี้ไม่ผูกกับบุคคล ผู้ดูแล
บริการภายในต้องส่งค่าที่ตรวจสอบจากเครื่องจริง และ Defender ต้องตรวจการเข้าถึง
ผ่าน inner network ก่อนเปิด redirect

## ข้อมูลจุดเชื่อมต่อ

```json
{
  "schema_version": "1.0",
  "defender": {
    "outer_ip": "192.168.56.10",
    "inner_ip": "10.10.10.1",
    "inner_interface": "ztpp6hfkv2",
    "public_url": "https://defender.lab"
  },
  "profiles": {
    "real_web": {
      "host": "10.10.10.3",
      "port": 8080,
      "health_path": "/",
      "expected_status": 200
    },
    "wordpress": {
      "host": "10.10.10.2",
      "port": 8081,
      "health_path": "/",
      "expected_status": 200
    },
    "phpmyadmin": {
      "host": "10.10.10.2",
      "port": 8082,
      "health_path": "/",
      "expected_status": 200
    },
    "cowrie": {
      "host": "10.10.10.2",
      "port": 2222,
      "health_method": "tcp_connect",
      "json_log_path": "/home/vboxuser/honeypot/cowrie-logs/cowrie.json"
    },
    "telnet": {
      "host": "10.10.10.2",
      "port": 2223,
      "health_method": "tcp_connect",
      "json_log_path": "/home/vboxuser/honeypot/cowrie-logs/cowrie.json"
    }
  }
}
```

ค่าชุดนี้ตรวจจากเครื่องจริงเมื่อวันที่ 17 กันยายน 2026 การเปลี่ยน IP, port,
interface หรือ URL ต้องทดสอบจาก Defender และแก้เอกสารนี้พร้อม config ที่ใช้งาน

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
