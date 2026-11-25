#!/usr/bin/env python3
"""Mock Jev API for the TRAP lab.

Accepts POST /v1/systemone with the same body/answer shape as the real API
(see defender/rabbit_hole/jev.py) and answers *differently depending on the
state the planner sends*: intent/skill/engagement are inferred from the
behaviour text and each clue slot is filled with the item whose description
best matches the inferred goal, so different attackers get different clues.

Lab only. No external calls, no real credentials.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG = Path('/root/trap-mock/requests.jsonl')
EXPECTED_KEY = os.environ.get('MOCK_JEV_KEY', 'demo-key-placeholder-0000')

# คำที่บ่งบอกพฤติกรรมใน state ที่ planner ส่งมา (state ไม่มี IP)
INTENT_HINTS = {
    'exploitation': ('sqlmap', 'union select', 'nikto', 'sqli', 'injection', 'traversal'),
    'credential_hunting': ('.env', 'passwd', '.htpasswd', 'credential', 'password', 'key'),
    'data_theft': ('backup', 'dump', 'export', 'db', 'sql', 'tar', 'zip'),
    'persistence': ('cron', 'authorized_keys', 'systemd', 'rc.local'),
    'recon': ('nmap', 'masscan', 'scan', 'robots', 'dir'),
}

# คำที่ใช้ให้คะแนนว่า lure ชิ้นไหนตรงกับเป้าหมายที่เดาได้
GOAL_HINTS = {
    'credential_hunting': ('password', 'credential', 'key', 'env', 'secret', 'login', 'db'),
    'data_theft': ('backup', 'dump', 'export', 'customers', 'orders', 'sql', 'data'),
    'exploitation': ('admin', 'upload', 'api', 'form', 'vulnerab', 'config'),
    'persistence': ('cron', 'ssh', 'service', 'startup'),
    'recon': ('notes', 'readme', 'index', 'config', 'list', 'dir'),
}


def digest(*parts: str) -> bytes:
    return hashlib.sha256('|'.join(parts).encode('utf-8')).digest()


def infer_intent(state: str) -> tuple:
    low = state.lower()
    hits = {k: sum(1 for w in words if w in low) for k, words in INTENT_HINTS.items()}
    best = max(hits, key=lambda k: (hits[k], k != 'recon'))
    strength = hits[best]
    if strength == 0:
        return 'recon', 0.55
    return best, min(0.95, 0.6 + 0.07 * strength)


def score_item(description: str, goal: str, seed: bytes, item: str) -> float:
    low = description.lower()
    hits = sum(1 for w in GOAL_HINTS.get(goal, ()) if w in low)
    jitter = digest(seed.hex(), item)[0] / 255.0  # stable per behaviour+item
    return hits * 1.0 + jitter * 0.4


def answer_choice(name, question, seed, goal):
    criteria = question.get('criteria') or {}
    if not isinstance(criteria, dict) or not criteria:
        return None
    items = list(criteria)
    scored = sorted(items, key=lambda i: (score_item(str(criteria[i]), goal, seed, i), i), reverse=True)
    top = scored[0]
    base = score_item(str(criteria[top]), goal, seed, top)
    # ยิ่งตรงเป้าหมาย/ยิ่งมีคำตรง ยิ่งมั่นใจ แต่ยังต่างกันตามพฤติกรรม
    conf = min(0.95, 0.58 + 0.06 * base + (digest(seed.hex(), name)[1] / 255.0) * 0.1)
    weights = {}
    for rank, item in enumerate(scored[:4]):
        weights[item] = round(max(0.02, conf - 0.16 * rank), 3)
    return {'choice': top, 'confidence': round(conf, 3), 'probabilities': weights}


def answer_score(question, seed):
    # ฝีมือประเมินจากความหลากหลายของพฤติกรรม: state ยิ่งยาว/มีหลายคำ ยิ่งดูชำนาญ
    length = len(str(question.get('_state') or ''))
    score = min(0.95, 0.35 + (digest(seed.hex(), 'skill')[0] / 255.0) * 0.5 + min(0.2, length / 4000))
    return {'score': round(score, 3), 'confidence': 0.82}


def answer_noul(question, seed):
    value = 0.55 + (digest(seed.hex(), 'noul')[0] / 255.0) * 0.4
    return {'noul': round(value, 3), 'confidence': 0.8}


def response_for(body):
    state = str(body.get('state') or '')
    seed = digest(state, str(body.get('model') or ''))
    goal, intent_conf = infer_intent(state)
    answers = {}
    for name, question in (body.get('questions') or {}).items():
        kind = question.get('type')
        if kind == 'choice':
            if name in {'intent', 'goal'}:
                criteria = list((question.get('criteria') or {}).keys())
                chosen = goal if goal in criteria else (criteria[0] if criteria else 'other')
                probs = {k: (round(intent_conf, 3) if k == chosen else round((1 - intent_conf) / max(1, len(criteria) - 1), 3))
                         for k in criteria}
                answers[name] = {'choice': chosen, 'confidence': round(intent_conf, 3), 'probabilities': probs}
            else:
                answer = answer_choice(name, question, seed, goal)
                if answer:
                    answers[name] = answer
        elif kind == 'score':
            answers[name] = answer_score(question, seed)
        elif kind == 'noul':
            answers[name] = answer_noul(question, seed)
    return {'model': 'mock-jev', 'answers': answers, 'usage': {'requests': 1}}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/v1/systemone':
            self.send_error(404)
            return
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer ') or not auth[7:].strip():
            self.send_error(401, 'missing key')
            return
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1_000_000:
            self.send_error(413)
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode('utf-8'))
        except Exception:
            self.send_error(400)
            return
        record = {'timestamp': datetime.now(timezone.utc).isoformat(),
                  'key_hint': auth[7:][:4] + '…' + auth[-3:], 'body': body}
        with LOG.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
        payload = json.dumps(response_for(body), ensure_ascii=False).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 18081), Handler).serve_forever()
