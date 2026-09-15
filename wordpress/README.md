# WordPress honeypot backend

This directory defines the WordPress backend for the Defender `wordpress`
profile. It keeps WordPress separate from the Python decision engine while
giving Nginx a stable local target.

## Local backend values

Use these values when rendering `defender/nginx/adaptive-honeypot.conf.template`
from VM-Defender to the inner honeypot VM:

```text
__WORDPRESS_IP__=10.10.10.2
__WORDPRESS_PORT__=8081
health_path=/wp-login.php
expected_status=200
```

The matching person-2 contract entry is:

```json
{
  "profiles": {
    "wordpress": {
      "port": 8081,
      "health_path": "/wp-login.php",
      "expected_status": 200
    }
  }
}
```

## Run

Copy the example environment file and replace the placeholder passwords before
starting the stack:

```bash
cd "/home/yakult/Desktop/Default Project/wordpress"
cp .env.example .env
docker compose up -d
curl -fsS http://127.0.0.1:8081/wp-login.php
```

If this VM does not have Docker yet, install it first from the local operations
runbook. On VM-Defender, route traffic through the Defender Nginx template to
`10.10.10.2:8081`; do not bind Docker to `10.10.10.2` unless the stack is
running on the honeypot VM that owns that address.
