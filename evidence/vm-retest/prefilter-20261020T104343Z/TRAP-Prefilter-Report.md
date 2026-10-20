# TRAP Nginx Prefilter VM Retest

**Date:** 2026-10-20 (Asia/Bangkok)  
**Result:** Prefilter installed and `nginx -t` passed. 13 of 14 required cases passed; case 13 is partial because Telnet redirected but SSH did not. Case 15 is optional and recorded as an observation.

## Test results

| # | Case | Result | Evidence / observed result |
|---|---|---|---|
| 1 | HTTP `GET /`, normal UA | PASS | `192.168.56.17`, real, prefilter 0, status 200, upstream `10.10.10.3:8080` (`adaptive-access.jsonl`). |
| 2 | HTTPS `GET /`, normal UA, `-k` | PASS | `192.168.56.18`, real, prefilter 0, status 200, upstream `10.10.10.3:8080` (`adaptive-access.jsonl`). |
| 3 | First HTTP `GET /.htpasswd` | PASS | `192.168.56.65`, `rabbithole`, prefilter 1, status 404, upstream `10.10.10.2:8084`; SID 2101071 and redirect decision are in captured logs. |
| 4 | HTTPS `GET /.htpasswd` | PASS | `192.168.56.73`, `rabbithole`, prefilter 1, status 404, upstream `10.10.10.2:8084`; SID 2101071. |
| 5 | SQLi URI `UNION SELECT` | PASS | `192.168.56.74`, `rabbithole`, prefilter 1, status 404, upstream `10.10.10.2:8084`; SID 2006446. |
| 6 | One Nikto UA request | PASS | First request from `192.168.56.89` was already `rabbithole`, prefilter 1. After repeated requests Suricata raised SID 2002677 and the engine added the IP to its map. |
| 7 | `sqlmap/1.8#stable` UA | PASS | Clean rerun using `192.168.56.121`: requests logged `rabbithole`, prefilter 1, upstream `10.10.10.2:8084`. The prior `.120` IP had historical activity and is excluded. |
| 8 | `/docs/htpasswd-guide` | PASS | `192.168.56.122`, real, prefilter 0, status 404, upstream `10.10.10.3:8080`. |
| 9 | `/.env` and `/?f=/etc/passwd` | PASS | Clean `/.env` rerun from `.26`: real, prefilter 0, status 404, upstream real. `/etc/passwd` from `.19`: real, prefilter 0, status 200; SID 2049400 produced monitor action (no redirect). |
| 10 | Immediate and +2s repeat after case 3 | PASS | `.65` immediately repeated `GET /` and again about 2 seconds later; both were `rabbithole`, prefilter 0, upstream `10.10.10.2:8084`. See timeline below. |
| 11 | Repeat from an IP already mapped | PASS | `.65 GET /`: `rabbithole`, prefilter 0, status 200, upstream honeypot. The IP map decision took precedence over the prefilter result. |
| 12 | Spoof `X-Trap-Client-IP` over HTTPS | PASS | Clean rerun from `.28` with a forged mapped client address remained real, prefilter 0, upstream `10.10.10.3:8080`. |
| 13 | SSH/Telnet regression | PARTIAL | Real SSH banner and Telnet login prompt were reachable. Telnet alert SID 2101251 led to `redirect_telnet`/Cowrie; Cowrie recorded a Telnet session from `.213`. SSH scan SID 2001219 was monitor only and `.213` was not added to `ssh_redirect`; SSH redirection threshold was not demonstrated. |
| 14 | Suricata alerts and Decision Engine updates | PASS | Confirmed web alert/redirect behavior for `.65` (2101071), `.73` (2101071), `.74` (2006446), `.89` (2002677 after repeated hits), and `.121` (2008538). Decision events include redirect_web and `nginx_ready=true`. |
| 15 | Optional real Nmap HTTP-title probe | OBSERVATION | Nmap sent `Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)`. It did not match configured literal `Nmap NSE`; request went real with prefilter 0 and SID 2009359 was not observed. |

## Case 3 and 10 timeline

Times below are UTC; the Nginx access log timestamps are UTC+07.

| Event | Time |
|---|---|
| First `.65 GET /.htpasswd` request | 2026-10-20 10:52:06.645Z |
| Suricata SID 2101071 alert | 2026-10-20 10:52:06.677Z |
| Decision Engine `redirect_web`, profile `rabbithole`, `nginx_ready=true` | 2026-10-20 10:52:06.717Z |
| Immediate repeat begins | 2026-10-20 10:52:06.930Z; logged as honeypot, prefilter 0 |
| Repeat about 2 seconds later | 2026-10-20 10:52:09.213Z; logged as honeypot, prefilter 0 |

The map became effective after the decision and before the immediate follow-up; its exact activation instant was not separately sampled. The first request itself was sent to the honeypot by prefilter.

## Configuration and caveats

`__PREFILTER_PROFILE__` was rendered as `rabbithole`: the live Decision Engine `web_profile` was `rabbithole`, and a health check to the Rabbit Hole backend returned HTTP 200. The configuration was merged into the existing VM config, retaining its VM-specific upstream and TLS settings. No unresolved active template tokens remained. Nginx syntax validation passed and Nginx was reloaded; Suricata and Decision Engine were not restarted.

The Project-Web access log available during the run was stale (latest records dated 2026-10-10), and container access logs had no current request rows. Therefore the claim that risky requests did not reach the real server is based on Nginx's logged upstream `10.10.10.2:8084` and the honeypot's request log, not a contemporaneous Project-Web access-log check.

The Nmap UA pattern is too specific for the observed Nmap NSE UA. Consider updating the pattern if detection of default Nmap NSE traffic is required. SSH redirect was not proven in this retest; Telnet Cowrie redirection was.

The redirect map snapshot still includes `192.168.56.65`, `.73`, `.74`, `.89`, `.120`, `.121`, `.157`, `.203`–`.207`. Historical/exploratory entries `.120`, `.157`, `.203`–`.207` were retained as instructed and should expire naturally. The final attacker namespace address evidence shows only its baseline `.30`–`.70` addresses; temporary test addresses were removed. No map entries were deleted.

## Rollback

The pre-install backup is `/root/trap-backup-20261020T104343Z/`. Restore the saved Nginx tree and redirect map, validate, then reload:

```sh
sudo cp -a /root/trap-backup-20261020T104343Z/nginx/. /etc/nginx/
sudo cp -a /root/trap-backup-20261020T104343Z/redirect_map.conf /etc/nginx/maps/redirect_map.conf
sudo nginx -t && sudo systemctl reload nginx
```

## Local verification and commit

Local unit command passed 43 tests before VM installation:

```sh
python -m unittest tests.test_nginx_config tests.test_https_inspection tests.test_snare_profile tests.test_decision_engine
```

Branch and commit are recorded in the final response after the scoped commit is created.
