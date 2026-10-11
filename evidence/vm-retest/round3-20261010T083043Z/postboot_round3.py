import ast
source=__import__('pathlib').Path('/tmp/trap-retest.py').read_text();exec(source[:source.index('# Prove the selected')])
for node in ast.parse(source).body:
    if isinstance(node,ast.FunctionDef) and node.name in {'web_case','ssh_case'}:exec(compile(ast.Module(body=[node],type_ignores=[]),'<regression>','exec'))
RESULTS=json.loads((D/'cases.json').read_text());API=json.loads((D/'api.json').read_text());COMMANDS=json.loads((D/'commands.json').read_text())
IP={'http':'192.168.56.189','ssh':'192.168.56.190'}
admin=Client();admin.login('trapadmin');user=Client();user.login('trapuser')
def boot_check():
    names=['suricata','nginx','adaptive-defender','trap-dashboard','trap-apply-rules.path','trap-log-sync.timer']
    health=command(['systemctl','is-active']+names,False)
    check(health.get('exit_code')==0,'Required services did not auto-start')
    before=(D/'boot-id-before.txt').read_text().strip();after=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    check(before!=after,'boot ID did not change')
    saved=(D/'thresholds-before-reboot.json').read_bytes();current=pathlib.Path('/var/lib/trap/engine/thresholds.json').read_bytes()
    check(saved==current,'Threshold file changed across reboot')
    return {'boot_id_before':before,'boot_id_after':after,'services':dict(zip(names,health['stdout'].splitlines())),'thresholds_sha256_before':hashlib.sha256(saved).hexdigest(),'thresholds_sha256_after':hashlib.sha256(current).hexdigest(),'thresholds':json.loads(current)}
run_case('Reboot-services-and-threshold-persistence',[],boot_check)
for ip in IP.values():
    for p in ['/var/log/suricata/eve.json','/var/log/adaptive-defender/decisions.jsonl','/var/log/trap/honeypot/cowrie.json','/var/log/trap/honeypot/rabbit-hole-web.jsonl']:
        check(ip not in pathlib.Path(p).read_text(),'Postboot IP alreadyused')
    command(['ip','netns','exec','trap-attacker','ip','addr','add',ip+'/24','dev','trap-in'],False)
run_case('Post-reboot-HTTP',[IP['http']],lambda:web_case('http',False))
run_case('Post-reboot-SSH',[IP['ssh']],ssh_case)
def roles():
    credentials=json.loads(pathlib.Path('/home/kali/.trap-dashboard-access.json').read_text())['trapuser']
    unauth=Client();status,challenge=unauth.req('/api/login',{'username':'trapuser','password':credentials['password']},True)
    check(status==200 and challenge.get('totp_required'),'No TOTPchallenge')
    status,bad=unauth.req('/api/login/totp',{'challenge':challenge['challenge'],'totp':'invalid'},True);check(status==401,'InvalidTOTPnot401')
    s1,_=user.req('/api/rules.json');s2,_=user.req('/api/thresholds',{'monitor':5,'redirect':10});s3,_=admin.req('/api/rules.json')
    check((s1,s2,s3)==(403,403,200),'Role enforcement mismatch')
    return {'bad_totp':status,'user_rules':s1,'user_thresholds':s2,'master_rules':s3}
run_case('Dashboard-TOTP-negative-and-role-enforcement',[],roles)
thresholds(15,40)
for path in ['/api/status.json','/api/thresholds.json','/api/capabilities.json','/api/summary.json','/api/analytics.json?window=all','/api/honeypot.json','/api/rabbit-hole.json','/api/reports.csv?window=all']:
    status,data=admin.req(path)
    if 'reports.csv' in path and status==200:(D/'dashboard-report.csv').write_text(data)
save();print('POST-BOOT complete',flush=True)
