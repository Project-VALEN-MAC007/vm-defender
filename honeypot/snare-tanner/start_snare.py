"""Start upstream SNARE locally, with a demo until an explicit clone is chosen."""
import hashlib
import json
import os
from pathlib import Path

base = Path('/opt/snare')
page = os.environ.get('PAGE_DIR', 'demo')
if page == 'demo':
    folder = base / 'pages' / 'demo'
    folder.mkdir(parents=True, exist_ok=True)
    if not (folder / 'meta.json').exists():
        meta = {}
        for url, body in {
            '/index.html': '<!doctype html><html><head><title>TRAP demo</title></head><body><h1>Web honeypot demo</h1><p>Clone your lab website to replace this page.</p><form action="/search" method="get"><input name="q"><button>Search</button></form></body></html>',
            '/status_404': '<!doctype html><html><head><title>Not found</title></head><body><h1>404 Not Found</h1></body></html>',
        }.items():
            name = hashlib.md5(url.encode()).hexdigest()
            (folder / name).write_text(body, encoding='utf-8')
            meta[url] = {'hash': name, 'headers': [{'Content-Type': 'text/html; charset=utf-8'}], 'status': 404 if url == '/status_404' else 200}
        (folder / 'meta.json').write_text(json.dumps(meta), encoding='utf-8')
os.execvp('snare', ['snare', '--page-dir', page, '--host-ip', '0.0.0.0', '--port', '8080', '--tanner', 'tanner', '--no-dorks', 'true', '--auto-update', 'false', '--skip-check-version'])
