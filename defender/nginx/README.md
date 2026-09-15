# D4 safe deployment

Nginx is not installed on the observed VM.  The configuration remains a
template because the lab outer address and person-2 backend ports/health
endpoints are not verified.

The active generated lab config redirects HTTP to HTTPS and terminates TLS on
Nginx before proxying to the selected inner backend.  The lab certificate paths
used by `defender/nginx/generated/adaptive-honeypot.http.conf` are:

```text
/etc/adaptive-defender/tls/defender.lab.crt
/etc/adaptive-defender/tls/defender.lab.key
```

Create a lab-only self-signed certificate at those paths before running
`nginx -t`, or replace the paths with the confirmed lab certificate and key.

Deployment gate:

1. Back up `/etc/nginx` with a UTC timestamp.
2. Render every `__TOKEN__`; reject output if a token remains.
3. Health-check each confirmed backend from Defender's inner interface.
4. Write the map to a sibling temporary file and atomically rename it.
5. Run `sudo nginx -t`; reload only on exit 0.
6. Confirm HTTP 308 redirect, HTTPS proxying, source-IP log fields and managed 503 response.
7. On failure, restore the backup, run `nginx -t`, then reload.

No certificate, credential or real backend value is stored here.

For the inner WordPress honeypot backend, render:

```text
__WORDPRESS_IP__=10.10.10.2
__WORDPRESS_PORT__=8081
```

Verify it before activating Nginx:

```bash
curl -fsS http://10.10.10.2:8081/wp-login.php
```
