# D3 rule test matrix

Tests must target only the authorized lab addresses after D1 is ready.

| SID | Positive input | Benign/negative input | Expected alert |
|---|---|---|---|
| 2200001 | `GET /wp-admin/` | `GET /health` | WordPress path, severity high |
| 2200002 | `GET /phpmyadmin/` | `GET /index.html` | phpMyAdmin probe, severity high |
| 2200003 | `User-Agent: sqlmap-lab` | `User-Agent: curl/8` | scanner UA, severity medium |
| 2200101 | TLS SNI ending `.lab` | unrelated SNI | TLS metadata, severity low |
| 2200201 | non-OpenSSH SSH version | OpenSSH version | client-version alert |
| 2200202 | 5 SYNs/30s to lab port 22 | fewer than threshold | burst alert |
| 2200203 | 5 SYNs/30s to lab port 23 | fewer than threshold | Telnet burst alert |
| 2200301 | 10 SYNs/5s to authorized lab host | normal single connect | scan-history alert |

The scan rule changes only the risk of a subsequent connection; it does not
attempt to redirect a scan that has already completed.  Actual alert fields
remain `NOT_RUN` until lab peers/interfaces exist.
