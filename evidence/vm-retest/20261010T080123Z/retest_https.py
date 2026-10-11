source=__import__('pathlib').Path('/tmp/trap-retest.py').read_text()
exec(source[:source.index('# Prove the selected')])
RESULTS=rows(D/'cases.json') if False else json.loads((D/'cases.json').read_text())
API=json.loads((D/'api.json').read_text());COMMANDS=json.loads((D/'commands.json').read_text())
ip='192.168.56.111'
for p in ['/var/log/suricata/eve.json','/var/log/adaptive-defender/decisions.jsonl','/var/log/trap/honeypot/rabbit-hole-web.jsonl']:
    check(ip not in pathlib.Path(p).read_text(),'Retest IP already used')
command(['ip','netns','exec','trap-attacker','ip','addr','add',ip+'/24','dev','trap-in'],False)
def https():
    curl(ip,'/?id=1',extra=['-A','sqlmap/1.x'])
    check(wait(lambda:any(x['action']=='redirect_web' for x in decisions(ip))),'No redirect decision')
    # nginx reload returns after signaling the master; allow new workers to start.
    time.sleep(2)
    r=curl(ip,'/?regression=https-retest',tls=True)
    check('HTTP/1.1 200' in r['stdout'],'HTTPS not 200')
    command(['systemctl','start','trap-log-sync'],False)
    entries=[x for x in fresh('/var/log/trap/honeypot/rabbit-hole-web.jsonl') if x.get('source_ip')==ip and x.get('query')=='regression=https-retest' and x.get('protocol')=='https']
    nginx=[x for x in fresh('/var/log/nginx/adaptive_access.json') if x.get('source_ip')==ip and '?regression=https-retest' in x.get('request','')]
    check(entries,'No HTTPS request in Honeypot log')
    check(any(x.get('upstream')=='10.10.10.2:8084' for x in nginx),'Nginx did not send to Honeypot')
    return {'response':r,'honeypot_requests':entries,'nginx':nginx,'reload_settle_seconds':2,'supersedes':'Regression-HTTPS'}
run_case('Regression-HTTPS-retest',[ip],https)
