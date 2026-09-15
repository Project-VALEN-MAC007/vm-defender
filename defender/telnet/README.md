# Telnet Honeypot Configuration

## Overview

The telnet honeypot simulates a vulnerable telnet service to attract and log attacker behavior. All connections and authentication attempts are logged for analysis.

## Quick Start

### Safe local testing (localhost only):

```bash
cd "/home/yakult/Desktop/Default Project"
python3 run_telnet.py
```

Connect from another terminal:
```bash
telnet 127.0.0.1 2323
```

### Configuration Options

The `TelnetHoneypot` class accepts:

- `host`: IP address to bind (default: "127.0.0.1" for safety)
- `port`: Port to listen on (default: 2323, non-privileged)
- `log_path`: Path to JSONL log file

## Log Format

Telnet sessions are logged to `evidence/telnet-logs/telnet.jsonl` in JSONL format:

```json
{
  "timestamp": "2026-09-15T10:30:45.123456",
  "session_id": "192.168.1.100:54321_1726395045.123",
  "remote_addr": "192.168.1.100:54321",
  "event_type": "connection",
  "data": {"status": "established"}
}
```

Event types:
- `connection`: Session start/end
- `login_attempt`: Username provided
- `auth_attempt`: Password provided (logged for threat intelligence)
- `login_retry`: Multiple login attempts

## Security Considerations

⚠️ **Default configuration binds to localhost only** to prevent accidental exposure.

To expose on the network (lab environment only):

```python
honeypot = TelnetHoneypot(host="10.10.10.1", port=23, log_path=log_path)
```

**Port 23 requires root:**
```bash
sudo python3 run_telnet.py  # if binding to port 23
```

## Integration with VM-Defender

The telnet honeypot logs can be analyzed by the decision engine for adaptive responses:

1. Parse `evidence/telnet-logs/telnet.jsonl` for authentication attempts
2. Extract source IPs and attack patterns
3. Feed into risk scoring system
4. Trigger nftables blocks or redirects based on threat level

## Testing

Test the honeypot with:

```bash
# Terminal 1: Start honeypot
python3 run_telnet.py

# Terminal 2: Connect as attacker
telnet 127.0.0.1 2323
# Try username: admin
# Try password: password123

# Terminal 3: Watch logs
tail -f evidence/telnet-logs/telnet.jsonl
```

## Production Deployment

For production honeypot deployment:

1. Configure appropriate network interface (e.g., `10.10.10.1`)
2. Use standard telnet port 23 (requires root)
3. Ensure firewall rules allow external access
4. Monitor logs for suspicious activity
5. Integrate with decision engine for automated responses

See `docs/root-operations.md` for elevated privilege operations.
