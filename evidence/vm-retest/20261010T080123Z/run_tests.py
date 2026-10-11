import sys,pathlib,json,time,datetime,subprocess,shlex,urllib.request,urllib.error,http.cookiejar,hashlib,traceback,socket
sys.path.insert(0,'/opt/trap')
from defender.dashboard.security import totp_code
D=pathlib.Path('/var/lib/trap/current-retest-dir').read_text();D=pathlib.Path(D)
START=datetime.datetime.fromisoformat((D/'test-start.txt').read_text().strip().replace('Z','+00:00'))
RESULTS=[];API=[];COMMANDS=[]
IP={k:'192.168.56.'+str(n) for k,n in [('libssh',101),('hydra',102),('scan',103),('rule',104),('threshold',105),('http',106),('https',107),('ssh',108),('telnet',109),('restored',110)]}
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def stamp(x):return datetime.datetime.fromisoformat(x.replace('Z','+00:00'))
def rows(p):
    try:
        result=[]
        for l in pathlib.Path(p).read_text().splitlines():
            try:result.append(json.loads(l))
            except ValueError:pass
        return result
    except FileNotFoundError:return []
def fresh(p):return [x for x in rows(p) if x.get('timestamp',x.get('start_time')) and stamp(x.get('timestamp',x.get('start_time')))>=START]
def alert(ip,sid):return [x for x in fresh('/var/log/suricata/eve.json') if x.get('event_type')=='alert' and x.get('src_ip')==ip and x['alert']['signature_id']==sid]
def decisions(ip,sid=None):return [x for x in fresh('/var/log/adaptive-defender/decisions.jsonl') if x.get('source_ip')==ip and (sid is None or x.get('signature_id')==sid)]
def wait(fn,seconds=12):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        v=fn()
        if v:return v
        time.sleep(.3)
    return fn()
def command(args,ns=True,timeout=30):
    cmd=(['ip','netns','exec','trap-attacker'] if ns else [])+args
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout)
        r={'time':now(),'command':shlex.join(cmd),'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    except subprocess.TimeoutExpired as e:
        decode=lambda v:v.decode(errors='replace') if isinstance(v,bytes) else (v or '')
        r={'time':now(),'command':shlex.join(cmd),'timeout':timeout,'stdout':decode(e.stdout),'stderr':decode(e.stderr)}
    COMMANDS.append(r);return r
def curl(ip,path='/',tls=False,extra=[]):
    return command(['curl','--interface',ip,'-skS','-i','--max-time','5']+extra+[('https' if tls else 'http')+'://192.168.56.10'+path])
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save():
    (D/'cases.json').write_text(json.dumps(RESULTS,ensure_ascii=False,indent=2))
    (D/'api.json').write_text(json.dumps(API,ensure_ascii=False,indent=2))
    (D/'commands.json').write_text(json.dumps(COMMANDS,ensure_ascii=False,indent=2))
class Client:
    def __init__(self):self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));self.csrf=''
    def req(self,path,data=None,private=False):
        req=urllib.request.Request('http://127.0.0.1:9090'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':self.csrf})
        try:r=self.opener.open(req,timeout=20)
        except urllib.error.HTTPError as e:r=e
        body=r.read().decode()
        try:obj=json.loads(body)
        except ValueError:obj=body
        if isinstance(obj,dict) and obj.get('csrf_token'):self.csrf=obj['csrf_token']
        entry={'time':now(),'path':path,'method':'POST' if data is not None else 'GET','status':r.status}
        if private:entry['response']={k:v for k,v in obj.items() if k in ['ok','error','user','totp_required']}
        else:entry.update(request=data,response=obj)
        API.append(entry);save();return r.status,obj
    def login(self,name):
        creds=json.loads(pathlib.Path('/home/kali/.trap-dashboard-access.json').read_text())[name]
        status,obj=self.req('/api/login',{'username':name,'password':creds['password']},True)
        if status!=200 or not obj.get('totp_required'):raise RuntimeError('Missing TOTP challenge')
        users=json.loads(pathlib.Path('/var/lib/trap/dashboard-users/users.json').read_text())['users']
        last=next(x.get('totp_last_counter',-1) for x in users if x['username']==name)
        while int(time.time())//30<=last:time.sleep(.5)
        code=totp_code(creds['totp_secret'],int(time.time())//30)
        status,res=self.req('/api/login/totp',{'challenge':obj['challenge'],'totp':code},True)
        if status!=200:raise RuntimeError('TOTP login failed')
        return res
def check(condition,message):
    if not condition:raise AssertionError(message)
def run_case(name,ips,fn):
    ci,ai=len(COMMANDS),len(API);t=now();detail={}
    try:detail=fn() or {};status='PASS';error=None
    except Exception as e:status='FAIL';error=f'{type(e).__name__}: {e}';detail={'traceback':traceback.format_exc()}
    command(['systemctl','start','trap-log-sync'],False)
    evidence={'name':name,'start_time':t,'source_ips':ips,'status':status,'error':error,'detail':detail,'commands':COMMANDS[ci:],'api':API[ai:],
              'alerts':[x for x in fresh('/var/log/suricata/eve.json') if x.get('event_type')=='alert' and x.get('src_ip') in ips],
              'decisions':[x for x in fresh('/var/log/adaptive-defender/decisions.jsonl') if x.get('source_ip') in ips],
              'cowrie':[x for x in fresh('/var/log/trap/honeypot/cowrie.json') if x.get('src_ip') in ips],
              'web':[x for x in fresh('/var/log/trap/honeypot/rabbit-hole-web.jsonl') if x.get('source_ip') in ips]}
    RESULTS.append(evidence);save();print(name,status,error or '',flush=True)
def thresholds(m,r):
    status,data=admin.req('/api/thresholds',{'monitor':m,'redirect':r});check(status==200,f'threshold API returned {status}: {data}');time.sleep(.6);return data
def applied(expected_text=None,state='applied',before=None):
    def ready():
        p=pathlib.Path('/var/lib/trap/rules/result.json')
        if not p.exists():return False
        d=json.loads(p.read_text())
        active=pathlib.Path('/etc/suricata/rules/et-open-selected.rules').read_text()
        if d.get('state')==state and (before is None or d.get('time')!=before) and (expected_text is None or expected_text in active):return d
        return False
    out=wait(ready,40);check(out,'No expected helper result within 40 sec');return out
def result_time():return json.loads(pathlib.Path('/var/lib/trap/rules/result.json').read_text()).get('time')

# Prove the selected source addresses were unused in both original lab logs.
for ip in IP.values():
    for p in ['/var/log/suricata/eve.json','/var/log/adaptive-defender/decisions.jsonl','/var/log/trap/honeypot/cowrie.json','/var/log/trap/honeypot/rabbit-hole-web.jsonl']:
        check(ip not in pathlib.Path(p).read_text(),f'Source IP already used: {ip}')
    command(['ip','netns','exec','trap-attacker','ip','addr','add',ip+'/24','dev','trap-in'],False)
(D/'source-ips.json').write_text(json.dumps(IP,indent=2))
admin=Client();admin.login('trapadmin');user=Client();user.login('trapuser')
CONFIG_SHA=sha('/etc/adaptive-defender/live.json')
thresholds(15,40)

def libssh_case():
    ip=IP['libssh'];pcap=D/'libssh-retest.pcap'
    capture=subprocess.Popen(['tcpdump','-U','-i','trap-out','-w',str(pcap),'host',ip],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    time.sleep(.5)
    script=f'''import socket,paramiko,time
for i in range(6):
 s=socket.socket();s.settimeout(4);s.bind(('{ip}',0));s.connect(('192.168.56.10',22))
 t=paramiko.Transport(s);t.local_version='SSH-2.0-libssh_0.10.6';t.start_client(timeout=4)
 print(i,t.remote_version,flush=True);t.close();time.sleep(.3)
'''
    r=command(['python3','-c',script],timeout=29)
    time.sleep(1);capture.terminate();capture.communicate(timeout=5)
    wait(lambda:decisions(ip,2006546))
    telemetry=[x for x in fresh('/var/log/suricata/eve.json') if x.get('event_type')=='ssh' and x.get('src_ip')==ip]
    (D/'libssh-telemetry.json').write_text(json.dumps(telemetry,indent=2))
    if not alert(ip,2006546):
        offline=D/'libssh-offline';offline.mkdir(exist_ok=True)
        command(['suricata','-c','/etc/suricata/suricata.yaml','-r',str(pcap),'-S','/etc/suricata/rules/et-open-selected.rules','-l',str(offline)],False,60)
    check(r.get('exit_code')==0,'Paramiko handshake command failed')
    check(alert(ip,2006546),'SID2006546 absent; inspect libssh-telemetry.json and offline replay')
    check(any(x['action']=='redirect_ssh' for x in decisions(ip)),'No redirect_ssh decision')
    return {'handshakes':6,'banner':'SSH-2.0-libssh_0.10.6','pcap':pcap.name}
run_case('FAIL1-LibSSH-handshakes',[IP['libssh']],libssh_case)

def hydra_case():
    ip=IP['hydra'];command(['ip','netns','exec','trap-attacker','ip','route','replace','192.168.56.0/24','dev','trap-in','src',ip],False)
    try:r=command(['hydra','-l','root','-P','/var/lib/trap/lab-wordlist.txt','-t','6','-W','1','-V','ssh://192.168.56.10'],timeout=38)
    finally:command(['ip','netns','exec','trap-attacker','ip','route','replace','192.168.56.0/24','dev','trap-in','src','192.168.56.30'],False)
    wait(lambda:decisions(ip,2006546));check(alert(ip,2006546),'Hydra did not trigger SID2006546')
    check(any(x['action']=='redirect_ssh' for x in decisions(ip)),'Hydra source did not redirect_ssh')
    return {'traffic':r}
run_case('FAIL1-Hydra',[IP['hydra']],hydra_case)

def scan_case():
    thresholds(5,10);ip=IP['scan']
    for i in range(3):curl(ip,'/?scan='+str(i),extra=['-A','masscan/1.3']);time.sleep(.5)
    ds=wait(lambda:decisions(ip,2017616));check(ds,'No Masscan decisions')
    check(all(x['action']=='monitor' and 'scan_only_policy:monitor' in x['reason'] for x in ds),'Masscan escaped monitor policy')
    probe=curl(ip,'/.htpasswd');wait(lambda:decisions(ip,2101071));r=curl(ip)
    check(any(x['action']=='redirect_web' for x in decisions(ip,2101071)),'.htpasswd from same source did not redirect')
    thresholds(15,40);return {'scan_decisions':ds,'followup_http':r,'redirect_threshold':10}
run_case('FAIL2-Masscan-scan-only-and-followup',[IP['scan']],scan_case)

def rule_case():
    candidate=json.loads(pathlib.Path('/opt/trap/tests/fixtures/candidate.json').read_text())
    candidate.update(rule_id='trap-retest-'+D.name,expected_sid=9900001,evidence='Real VM retest '+D.name)
    candidate['rule']=candidate['rule'].replace('2200401','9900001').replace('/lab-repeat','/trap-retest-probe')
    status,res=admin.req('/api/candidates/save',candidate);check(status==200,str(res))
    before=result_time();status,added=admin.req('/api/candidates/approve',{'rule_id':candidate['rule_id']});check(status==200,str(added))
    result=applied('sid:9900001',before=before)
    curl(IP['rule'],'/trap-retest-probe');check(wait(lambda:alert(IP['rule'],9900001)),'Installed probe rule did not alert')
    before=result_time();status,restored=admin.req('/api/rules/change',{'action':'restore','backup':added['backup']});check(status==200,str(restored));restore=applied(before=before)
    active=pathlib.Path('/etc/suricata/rules/et-open-selected.rules').read_text();check('sid:9900001' not in active,'Probe SID still active after restore')
    curl(IP['restored'],'/trap-retest-probe');time.sleep(2);check(not alert(IP['restored'],9900001),'Removed rule still generated alert')
    return {'activation':result,'restored':restore,'restore_backup':added['backup']}
run_case('FAIL3-Rule-approve-activate-alert-restore',[IP['rule'],IP['restored']],rule_case)

def invalid_rule_case():
    p='/etc/suricata/rules/et-open-selected.rules';beforehash=sha(p);before=result_time()
    bad='alert http any any -> any any (msg:"TRAP invalid syntax"; trap_unknown_keyword:1; classtype:web-application-attack; sid:9900002; rev:1;)'
    status,res=admin.req('/api/rules/change',{'action':'add','rule':bad});check(status==200,str(res))
    outcome=applied(state='failed',before=before);afterhash=sha(p)
    check(outcome.get('step')=='syntax_test','Failure not at syntax validation')
    check(beforehash==afterhash,'Invalid rules changed active rules')
    before=result_time();status,restore=admin.req('/api/rules/change',{'action':'restore','backup':res['backup']});check(status==200,str(restore));recovered=applied(before=before)
    return {'failed_result':outcome,'sha256_before':beforehash,'sha256_after':afterhash,'recovered':recovered}
run_case('FAIL3-Invalid-rule-rejected-active-unchanged',[],invalid_rule_case)

def threshold_case():
    ip=IP['threshold'];before=sha('/etc/adaptive-defender/live.json')
    high=thresholds(5,90);curl(ip,'/.env');wait(lambda:decisions(ip,2031502));first=decisions(ip,2031502);check(first and first[-1]['action']=='monitor','High threshold did not monitor')
    low=thresholds(5,10);saved=json.loads(pathlib.Path('/var/lib/trap/engine/thresholds.json').read_text())
    curl(ip,'/.htpasswd');wait(lambda:decisions(ip,2101071));second=decisions(ip,2101071)
    check(second and second[-1]['action']=='redirect_web','Next decision did not use new threshold')
    status,res=user.req('/api/thresholds',{'monitor':5,'redirect':90});check(status==403,f'User threshold update returned {status}')
    after=sha('/etc/adaptive-defender/live.json');check(before==after==CONFIG_SHA,'Read-only engine config changed during API tests')
    thresholds(15,40)
    return {'api_high':high,'api_low':low,'threshold_file':saved,'etc_sha256_before':before,'etc_sha256_after':after,'user_status':status,'first_decisions':first,'next_decisions':second}
run_case('FAIL4-Threshold-API-reload-and-User-denied',[IP['threshold']],threshold_case)

def web_case(key,tls):
    ip=IP[key];curl(ip,'/?id=1',extra=['-A','sqlmap/1.x']);check(wait(lambda:any(x['action']=='redirect_web' for x in decisions(ip))),'No web redirect decision')
    r=curl(ip,'/?regression='+key,tls=tls);check('HTTP/1.1 200' in r['stdout'],'HTTP response not 200')
    command(['systemctl','start','trap-log-sync'],False)
    entries=[x for x in fresh('/var/log/trap/honeypot/rabbit-hole-web.jsonl') if x.get('source_ip')==ip and x.get('query')=='regression='+key]
    check(entries,'No correlated web request in Honeypot VM log')
    return {'response':r,'honeypot_requests':entries}
run_case('Regression-HTTP',[IP['http']],lambda:web_case('http',False))
run_case('Regression-HTTPS',[IP['https']],lambda:web_case('https',True))

def ssh_case():
    thresholds(5,30);ip=IP['ssh']
    seed=f"import socket,time\nfor i in range(6):\n s=socket.socket();s.settimeout(3);s.bind(('{ip}',0));s.connect(('192.168.56.10',22));s.recv(256);s.close();time.sleep(.25)"
    command(['python3','-c',seed]);check(wait(lambda:any(x['action']=='redirect_ssh' for x in decisions(ip))), 'SSH scan SID2001219 did not redirect')
    script=f'''import socket,paramiko,time,json
s=socket.socket();s.bind(('{ip}',0));s.settimeout(5);s.connect(('192.168.56.10',22))
c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy());c.connect('192.168.56.10',username='sysadmin',password='[REDACTED]',sock=s,look_for_keys=False,allow_agent=False,timeout=5)
ch=c.invoke_shell()
for cmd in ['whoami','ls','uname -a']:
 ch.send(cmd+'\\n');time.sleep(1);out=''
 while ch.recv_ready():out+=ch.recv(65535).decode(errors='replace')
 print(json.dumps({{'command':cmd,'output':out}}),flush=True)
ch.send('exit\\n');time.sleep(.3);c.close()
'''
    r=command(['python3','-c',script]);check(r.get('exit_code')==0,'SSH login/shell failed')
    command(['systemctl','start','trap-log-sync'],False)
    events=[x for x in fresh('/var/log/trap/honeypot/cowrie.json') if x.get('src_ip')==ip]
    commands={x.get('input') for x in events if x.get('eventid')=='cowrie.command.input'}
    check({'whoami','ls','uname -a'}.issubset(commands),'Cowrie did not log all commands')
    thresholds(15,40);return {'shell':r,'cowrie_commands':sorted(commands)}
run_case('Regression-SSH',[IP['ssh']],ssh_case)

def telnet_case():
    thresholds(5,20);ip=IP['telnet']
    script=f'''import socket,telnetlib,time,json
orig=socket.create_connection
socket.create_connection=lambda address,timeout=None,source_address=None:orig(address,timeout,('{ip}',0))
for i in range(2):
 t=telnetlib.Telnet('192.168.56.10',23,timeout=5)
 a=t.read_until(b'login: ',3);t.write(b'invalid\\r\\n');b=t.read_until(b'Password: ',3);t.write(b'wrong-lab-password\\r\\n');c=t.read_until(b'incorrect',4)
 print(json.dumps({{'attempt':i,'banner':a.decode(errors='replace'),'reply':c.decode(errors='replace')}}));t.close();time.sleep(2)
'''
    r=command(['python3','-c',script],timeout=28);check(r.get('exit_code')==0,'Telnet traffic command failed')
    check(wait(lambda:any(x['action']=='redirect_telnet' for x in decisions(ip))),'No redirect_telnet')
    command(['systemctl','start','trap-log-sync'],False)
    ev=[x for x in fresh('/var/log/trap/honeypot/cowrie.json') if x.get('src_ip')==ip]
    check(any(x.get('eventid')=='cowrie.login.failed' for x in ev),'Cowrie did not log Telnet bad login')
    thresholds(15,40);return {'traffic':r}
run_case('Regression-Telnet',[IP['telnet']],telnet_case)
thresholds(15,40)
for path in ['/api/status.json','/api/thresholds.json','/api/capabilities.json','/api/analytics.json?window=all','/api/alerts.json?limit=500','/api/decisions.json?limit=500','/api/honeypot.json']:
    admin.req(path)
command(['nft','list','table','inet','adaptive_defender'],False)
command(['systemctl','is-active','adaptive-defender','trap-dashboard','suricata','nginx','trap-apply-rules.path','trap-log-sync.timer'],False)
save()
print('FINAL',[(x['name'],x['status']) for x in RESULTS],flush=True)
