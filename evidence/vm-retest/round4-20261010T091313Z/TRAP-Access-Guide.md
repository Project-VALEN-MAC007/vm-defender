# TRAP Access Guide — three VM lab (round 4)

| VM | Management SSH | Lab services |
|---|---|---|
| Project-Defender | ssh -p 2221 kali@127.0.0.1 | 192.168.56.10 HTTP 80 / HTTPS 443; inner 10.10.10.1 |
| Project-Honeypot | ssh -p 2222 kali@127.0.0.1 | 10.10.10.2 Cowrie 2222/2223, Web 8084 |
| Project-Web | ssh -p 2223 kali@127.0.0.1 | 10.10.10.3 WordPress 8080, SSH 22, Telnet 23 |

View the production website through Defender from Windows using a SOCKS tunnel:

`ssh -p 2221 -N -D 1080 kali@127.0.0.1`

Set the browser SOCKS5 proxy to 127.0.0.1:1080, then visit
http://192.168.56.10/ or https://192.168.56.10/.
For a terminal-only local port tunnel:

`ssh -p 2221 -N -L 8089:192.168.56.10:80 kali@127.0.0.1`

WordPress canonical URLs use the lab address. For a simple local terminal check:
`curl.exe -H "Host: 192.168.56.10" http://127.0.0.1:8089/`

Use the lab namespace for IDS/routing tests; target only 192.168.56.10.
Normal SSH/Telnet application account: webadmin on Project-Web.
WordPress normal login: normaluser; administration: trapwpadmin.
Passwords and TOTP secrets are intentionally excluded from this guide.
Production credentials are stored privately at /root/trap-round4-credentials.json
on Project-Web; DB .env is /opt/trap/production/.env, mode 600.
Dashboard credentials remain in /home/kali/.trap-dashboard-access.json on Defender.
Production Compose directory: /opt/trap/production. Persistent volume data is retained.
The old placeholder webpage/host HTTP 8083 mapping has been disabled.
