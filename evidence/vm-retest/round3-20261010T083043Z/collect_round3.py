import pathlib,json,datetime,hashlib,subprocess,tarfile,shutil,statistics
D=pathlib.Path(pathlib.Path('/var/lib/trap/current-retest-dir').read_text());start=datetime.datetime.fromisoformat((D/'test-start.txt').read_text().strip().replace('Z','+00:00'))
def selected(path):
    data=[]
    for line in pathlib.Path(path).read_text().splitlines():
        try:x=json.loads(line)
        except ValueError:continue
        t=x.get('timestamp') or x.get('start_time')
        if t and datetime.datetime.fromisoformat(t.replace('Z','+00:00'))>=start:data.append(x)
    return data
R=D/'raw';R.mkdir(exist_ok=True)
# Restart the oneshot only after traffic has ended, to force a new completed copy.
subprocess.run(['systemctl','restart','trap-log-sync'],check=True)
paths={'eve.json':'/var/log/suricata/eve.json','decisions.jsonl':'/var/log/adaptive-defender/decisions.jsonl','nginx.jsonl':'/var/log/nginx/adaptive_access.json','cowrie.json':'/var/log/trap/honeypot/cowrie.json','web.jsonl':'/var/log/trap/honeypot/rabbit-hole-web.jsonl'}
data={}
for name,p in paths.items():
    data[name]=selected(p);(R/name).write_text('\n'.join(json.dumps(x,ensure_ascii=False) for x in data[name])+'\n')
cases=json.loads((D/'cases.json').read_text());verifications=[]
for c in cases:
    name=c['name'];status=c['status'];proof={}
    if name.startswith('Immediate-'):
        ip=c['source_ips'][0];index=int(ip.rsplit('.',1)[1])-129
        ds=[x for x in data['decisions.jsonl'] if x.get('source_ip')==ip and x.get('action')=='redirect_web']
        nginx=[x for x in data['nginx.jsonl'] if x.get('source_ip')==ip and f'round3=immediate-{index} ' in x.get('request','')]
        web=[x for x in data['web.jsonl'] if x.get('source_ip')==ip and x.get('query')==f'round3=immediate-{index}']
        good=bool(ds and nginx and web) and all(x.get('nginx_ready') is True for x in ds) and all(x.get('profile')!='real' and x.get('upstream')=='10.10.10.2:8084' and x.get('status')==200 for x in nginx)
        status='PASS' if good else 'FAIL';proof={'decisions':ds,'nginx':nginx,'honeypot':web}
    elif c['status']=='FAIL' and c['error'] and 'No correlated web request' in c['error']:
        ip=c['source_ips'][0];web=[x for x in data['web.jsonl'] if x.get('source_ip')==ip and x.get('query')=='regression=https']
        nginx=[x for x in data['nginx.jsonl'] if x.get('source_ip')==ip and '?regression=https ' in x.get('request','')]
        good=bool(web and nginx) and all(x.get('upstream')=='10.10.10.2:8084' and x.get('status')==200 for x in nginx)
        status='PASS' if good else 'FAIL';proof={'nginx':nginx,'honeypot':web}
    c['alerts']=[x for x in data['eve.json'] if x.get('event_type')=='alert' and (x.get('src_ip') in c['source_ips'] or x.get('dest_ip') in c['source_ips'])]
    verifications.append({'name':name,'initial_status':c['status'],'initial_error':c['error'],'final_status':status,'proof':proof,'basis':'Original request correlated with final raw logs; no traffic replay' if proof else 'Original case assertions and evidence'})
(D/'cases-with-final-alerts.json').write_text(json.dumps(cases,ensure_ascii=False,indent=2))
immediate=[x for x in verifications if x['name'].startswith('Immediate-')]
latencies=[x['proof']['decisions'][0]['nginx_ready_seconds'] for x in immediate]
summary={'test_start':start.isoformat(),'case_count':len(verifications),'final_pass':sum(x['final_status']=='PASS' for x in verifications),'final_fail':sum(x['final_status']=='FAIL' for x in verifications),'initial_fail_count':sum(x['initial_status']=='FAIL' for x in verifications),'immediate_pass':sum(x['final_status']=='PASS' for x in immediate),'readiness_seconds':{'count':len(latencies),'min':min(latencies),'median':statistics.median(latencies),'max':max(latencies)},'et_pass':sum(x['name'].startswith('ET-') and x['final_status']=='PASS' for x in verifications),'cases':verifications}
(D/'final-verification.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
for p in ['/etc/adaptive-defender/live.json','/var/lib/trap/engine/thresholds.json','/var/lib/trap/rules/result.json','/etc/suricata/rules/et-open-selected.rules']:
    shutil.copyfile(p,R/pathlib.Path(p).name)
for name,cmd in [('nft.txt',['nft','list','table','inet','adaptive_defender']),('services.txt',['systemctl','is-active','adaptive-defender','trap-dashboard','suricata','nginx','trap-apply-rules.path','trap-log-sync.timer']),('nginx-test.txt',['nginx','-t']),('namespace-routes.txt',['ip','netns','exec','trap-attacker','ip','route']),('helper-journal.txt',['journalctl','-u','trap-apply-rules.service','--since',start.isoformat(),'--no-pager'])]:
    p=subprocess.run(cmd,capture_output=True,text=True);(R/name).write_text(p.stdout+p.stderr)
hashes={pathlib.Path(p).name:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in [paths['cowrie.json'],paths['web.jsonl']]}
(D/'defender-sync-hashes.json').write_text(json.dumps(hashes,indent=2))
# Restore temporary worker PID logging after all tests; keep enriched logs as evidence.
shutil.copyfile(D/'baseline/nginx-trap.conf','/etc/nginx/conf.d/trap.conf')
subprocess.run(['nginx','-t'],check=True);subprocess.run(['systemctl','reload','nginx'],check=True)
with tarfile.open('/tmp/trap-round3-evidence.tar.gz','w:gz') as t:
    for p in D.iterdir():
        if p.name!='baseline':t.add(p,arcname=p.name)
print(json.dumps({k:v for k,v in summary.items() if k!='cases'},indent=2));print('Hashes:',json.dumps(hashes))
