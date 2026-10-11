# TRAP lab access (รอบ 5)

Defender: `ssh -p 2221 kali@127.0.0.1`

Honeypot: `ssh -p 2222 kali@127.0.0.1`

Project-Web: `ssh -p 2223 kali@127.0.0.1`

Honeypot compose: `/opt/trap/honeypot/docker/compose.yaml`, project `trap-honeypot`.

Cowrie log: `/var/log/cowrie/cowrie.json`; Web log: `/var/log/trap/rabbit-hole-web.jsonl`; watchdog: `/var/log/trap/honeypot-watchdog.jsonl`.

Dashboard จาก Defender ใช้พอร์ต 9090 ผ่าน SSH tunnel. รายงานนี้ไม่รวมรหัสผ่านหรือ TOTP secret.
