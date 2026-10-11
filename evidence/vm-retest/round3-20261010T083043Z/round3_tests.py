import ast,signal,statistics
source=__import__('pathlib').Path('/tmp/trap-retest.py').read_text()
exec(source[:source.index('# Prove the selected')])
names={'rule_case','invalid_rule_case','threshold_case','web_case','ssh_case','telnet_case'}
for node in ast.parse(source).body:
    if isinstance(node,ast.FunctionDef) and node.name in names:exec(compile(ast.Module(body=[node],type_ignores=[]),'<round2-functions>','exec'))
IP={'rule':'192.168.56.187','restored':'192.168.56.188','threshold':'192.168.56.186','http':'192.168.56.180','https':'192.168.56.181','ssh':'192.168.56.182','telnet':'192.168.56.183'}
def allocate(ip):
    for p in ['/var/log/suricata/eve.json','/var/log/adaptive-defender/decisions.jsonl','/var/log/trap/honeypot/cowrie.json','/var/log/trap/honeypot/rabbit-hole-web.jsonl','/var/log/nginx/adaptive_access.json']:
        check(ip not in pathlib.Path(p).read_text(),f'IP already used: {ip}')
    command(['ip','netns','exec','trap-attacker','ip','addr','add',ip+'/24','dev','trap-in'],False)
    used=json.loads((D/'source-ips.json').read_text()) if (D/'source-ips.json').exists() else []
    used.append(ip);(D/'source-ips.json').write_text(json.dumps(used,indent=2))
for n in list(range(130,150))+[150,151,152]+list(range(160,173))+list(range(180,189)):
    allocate('192.168.56.'+str(n))
admin=Client();admin.login('trapadmin');user=Client();user.login('trapuser')
CONFIG_SHA=sha('/etc/adaptive-defender/live.json')
thresholds(15,40)
IMMEDIATE=[]
def next_redirect(ip,offset):
    with open('/var/log/adaptive-defender/decisions.jsonl') as stream:
        stream.seek(offset);end=time.monotonic()+20
        while time.monotonic()<end:
            pos=stream.tell();line=stream.readline()
            if not line or not line.endswith('\n'):
                stream.seek(pos);time.sleep(.005);continue
            d=json.loads(line)
            if d.get('source_ip')==ip and d.get('action')=='redirect_web':return d
    raise AssertionError('No redirect_web decision within20sec')
def immediate(ip,tls,index):
    offset=pathlib.Path('/var/log/adaptive-defender/decisions.jsonl').stat().st_size
    curl(ip,'/.htpasswd')
    decision=next_redirect(ip,offset)
    # NO sleep or readiness polling after the observed decision.
    observed=now();r=curl(ip,'/?round3=immediate-'+str(index),tls=tls)
    entry={'index':index,'ip':ip,'protocol':'https' if tls else 'http','decision':decision,'decision_observed_utc':observed,'response':r}
    IMMEDIATE.append(entry);(D/'immediate.json').write_text(json.dumps(IMMEDIATE,indent=2))
    nginx=[x for x in fresh('/var/log/nginx/adaptive_access.json') if x.get('source_ip')==ip and 'round3=immediate-'+str(index)+' ' in x.get('request','')]
    entry['nginx']=nginx
    command(['systemctl','start','trap-log-sync'],False)
    web=[x for x in fresh('/var/log/trap/honeypot/rabbit-hole-web.jsonl') if x.get('source_ip')==ip and x.get('query')=='round3=immediate-'+str(index)]
    entry['web']=web;(D/'immediate.json').write_text(json.dumps(IMMEDIATE,indent=2))
    check(decision.get('nginx_ready') is True,'nginx_ready not True')
    check('HTTP/1.1 200' in r['stdout'],'NotHTTP200')
    check(nginx and all(x.get('profile')!='real' and x.get('upstream')=='10.10.10.2:8084' for x in nginx),'Immediate request reached Real/wrong upstream')
    check(web,'Immediate request absent from Honeypot log')
    return entry
for i,n in enumerate(range(130,150),1):
    tls=i<=10;ip='192.168.56.'+str(n)
    run_case(('Immediate-HTTPS-' if tls else 'Immediate-HTTP-')+str(i if tls else i-10),[ip],lambda ip=ip,tls=tls,i=i:immediate(ip,tls,i))
waits=[x['decision'].get('nginx_ready_seconds') for x in IMMEDIATE]
(D/'readiness-statistics.json').write_text(json.dumps({'count':len(waits),'min':min(waits),'median':statistics.median(waits),'max':max(waits)},indent=2))

def timeout_case():
    master=int(pathlib.Path('/run/nginx.pid').read_text())
    watchdog=command(['systemd-run','--unit=trap-round3-resume-nginx','--on-active=15s','/bin/kill','-CONT',str(master)],False)
    check(watchdog.get('exit_code')==0,'Resume watchdog could not start')
    os=__import__('os');timed=[]
    try:
        os.kill(master,signal.SIGSTOP)
        for ip in ['192.168.56.150','192.168.56.151']:
            offset=pathlib.Path('/var/log/adaptive-defender/decisions.jsonl').stat().st_size
            curl(ip,'/.htpasswd');d=next_redirect(ip,offset);timed.append(d)
            check(d.get('nginx_ready') is False,'Stopped master did not yield readiness false')
    finally:
        os.kill(master,signal.SIGCONT)
        command(['systemctl','stop','trap-round3-resume-nginx.timer'],False)
    # Prove engine handles a subsequent normal reload after resuming master.
    ip='192.168.56.152';offset=pathlib.Path('/var/log/adaptive-defender/decisions.jsonl').stat().st_size
    curl(ip,'/.htpasswd');recovery=next_redirect(ip,offset)
    check(recovery.get('nginx_ready') is True,'Engine did not recover after resuming master')
    return {'simulation':'SIGSTOP nginx master only; workers kept serving; automatic SIGCONT watchdog15s','master_pid':master,'timeout_decisions':timed,'recovery_decision':recovery}
run_case('Readiness-timeout-and-engine-continues',['192.168.56.150','192.168.56.151','192.168.56.152'],timeout_case)

def rule_test(ip,sid,args,expected_action=None):
    for a in args:command(a)
    ds=wait(lambda:decisions(ip,sid),20)
    check(alert(ip,sid) or any(x.get('event_type')=='alert' and x.get('dest_ip')==ip and x.get('alert',{}).get('signature_id')==sid for x in fresh('/var/log/suricata/eve.json')),f'NoSID{sid}')
    check(ds,'No matching decision')
    if expected_action:check(all(x['action']==expected_action for x in ds),f'Unexpectedaction{ds}')
    return {'sid':sid,'decisions':ds}
target='http://192.168.56.10'
def req(ip,path='/',extra=[]):return ['curl','--interface',ip,'-skS','-i','--max-time','5']+extra+[target+path]
specs=[('sqlmap-UA',2008538,160,[('-A','sqlmap/1.x')],'/?id=1','redirect_web'),('Nikto-UA-threshold',2002677,161,[('-A','Mozilla/5.00 (Nikto/2.1.5)')]*6,'/','redirect_web'),('Nmap-NSE-UA',2009359,162,[('-A','Mozilla/5.0 (compatible; Nmap NSE)')],'/','redirect_web'),('Masscan-UA',2017616,163,[('-A','masscan/1.3')]*3,'/','monitor'),('UNION-URI',2006446,164,[()], '/?id=1%20UNION%20SELECT%201,2,3%3B','redirect_web'),('UNION-body',2053468,165,[('-d','q=1 UNION SELECT user,pass FROM users')],'/','redirect_web'),('passwd-URI',2049400,166,[()], '/?file=../../etc/passwd','monitor'),('env',2031502,167,[()], '/.env','monitor'),('htpasswd',2101071,168,[()], '/.htpasswd','redirect_web')]
for name,sid,n,extras,path,action in specs:
    ip='192.168.56.'+str(n);args=[req(ip,path,list(extra)) for extra in extras]
    run_case('ET-'+name,[ip],lambda ip=ip,sid=sid,args=args,action=action:rule_test(ip,sid,args,action))
ip='192.168.56.169'
scan=f"import socket,time\nfor i in range(6):\n s=socket.socket();s.settimeout(3);s.bind(('{ip}',0));s.connect(('192.168.56.10',22));s.recv(256);s.close();time.sleep(.2)"
run_case('ET-SSH-scan',[ip],lambda:rule_test(ip,2001219,[['python3','-c',scan]],'monitor'))
def hydra():
    ip='192.168.56.170';command(['ip','netns','exec','trap-attacker','ip','route','replace','192.168.56.0/24','dev','trap-in','src',ip],False)
    try:r=command(['hydra','-l','root','-P','/var/lib/trap/lab-wordlist.txt','-t','6','-W','1','-V','ssh://192.168.56.10'],timeout=38)
    finally:command(['ip','netns','exec','trap-attacker','ip','route','replace','192.168.56.0/24','dev','trap-in','src','192.168.56.30'],False)
    ds=wait(lambda:decisions(ip,2006546));check(alert(ip,2006546),'Hydra missedSID2006546');check(ds and all(x['action']=='redirect_ssh' for x in ds),'LibSSH did not redirect');return {'traffic':r,'sid':2006546}
run_case('ET-LibSSH-Hydra',['192.168.56.170'],hydra)
def telnet_args(ip,username):
    script=f'''import socket,telnetlib
s=socket.socket();s.bind(('{ip}',0));s.settimeout(4);s.connect(('192.168.56.10',23))
t=telnetlib.Telnet();t.sock=s
print(t.read_until(b'login: ',3));t.write({(username+'\r\n').encode()!r});print(t.read_until(b'Password: ',3));t.write(b'wrong-lab-password\\r\\n');print(t.read_until(b'Login ',3));print(t.read_some());t.close()
'''
    return ['python3','-c',script]
for name,sid,n,username in [('Telnet-incorrect',2101251,171,'invalid'),('Telnet-failed',2100492,172,'failcase')]:
    ip='192.168.56.'+str(n);args=[telnet_args(ip,username)]
    run_case('ET-'+name,[ip],lambda ip=ip,sid=sid,args=args:rule_test(ip,sid,args,'monitor'))

run_case('Regression-HTTP',[IP['http']],lambda:web_case('http',False))
run_case('Regression-HTTPS',[IP['https']],lambda:web_case('https',True))
run_case('Regression-SSH',[IP['ssh']],ssh_case)
run_case('Regression-Telnet',[IP['telnet']],telnet_case)
def rabbit_web():
    ip='192.168.56.184';curl(ip,'/.htpasswd');check(wait(lambda:decisions(ip)),'No redirect')
    cookie=str(D/'rabbit-cookies.txt');extra=['-A','TRAP-Round3-Rabbit','-b',cookie,'-c',cookie]
    steps=[]
    for path in ['/robots.txt','/backup/','/backup/config.json','/api/v1/']:
        r=curl(ip,path,extra=extra);steps.append(r)
    cfg=json.loads(steps[2]['stdout'].split('\r\n\r\n')[-1] if '\r\n\r\n' in steps[2]['stdout'] else steps[2]['stdout'].split('\n\n',1)[1])
    api=curl(ip,'/api/v1/users',tls=True,extra=extra+['-H','X-API-Key: '+cfg['api']['key']]);check('HTTP/1.1 200' in api['stdout'],'RabbitAPI not200')
    return {'steps':steps,'api':api}
run_case('Rabbit-Hole-Web',['192.168.56.184'],rabbit_web)
def rabbit_ssh():
    thresholds(5,30);ip='192.168.56.185'
    seed=f"import socket,time\nfor i in range(6):\n s=socket.socket();s.settimeout(3);s.bind(('{ip}',0));s.connect(('192.168.56.10',22));s.recv(256);s.close();time.sleep(.2)"
    command(['python3','-c',seed]);check(wait(lambda:any(x['action']=='redirect_ssh' for x in decisions(ip))),'No SSHredirect')
    script=f'''import socket,paramiko,time,json
s=socket.socket();s.bind(('{ip}',0));s.settimeout(5);s.connect(('192.168.56.10',22))
c=paramiko.SSHClient();c.set_missing_host_key_policy(paramiko.AutoAddPolicy());c.connect('192.168.56.10',username='sysadmin',password='[REDACTED]',sock=s,look_for_keys=False,allow_agent=False)
ch=c.invoke_shell()
for cmd in ['cat notes.txt','ls /opt/backup/','cat /opt/backup/backup.conf']:
 ch.send(cmd+'\\n');time.sleep(.7);out=''
 while ch.recv_ready():out+=ch.recv(65535).decode(errors='replace')
 print(json.dumps({{'command':cmd,'output':out}}))
c.close()
'''
    r=command(['python3','-c',script]);check(r.get('exit_code')==0 and '/opt/backup/backup.conf' in r['stdout'] and 'DB_HOST=' in r['stdout'],'SSH Rabbit clues/filesmissing');thresholds(15,40);return {'shell':r}
run_case('Rabbit-Hole-SSH',['192.168.56.185'],rabbit_ssh)
run_case('Dashboard-Threshold-TOTP-User-Master',[IP['threshold']],threshold_case)
run_case('Dashboard-Rule-approve-applied-restore',[IP['rule'],IP['restored']],rule_case)
run_case('Dashboard-Invalid-rule-rejected',[],invalid_rule_case)
thresholds(15,40)
(D/'thresholds-before-reboot.json').write_bytes(pathlib.Path('/var/lib/trap/engine/thresholds.json').read_bytes())
(D/'boot-id-before.txt').write_text(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text())
command(['systemctl','is-enabled','suricata','nginx','adaptive-defender','trap-dashboard','trap-apply-rules.path','trap-log-sync.timer'],False)
save();print('PRE-REBOOT CASES',[(x['name'],x['status'],x['error']) for x in RESULTS],flush=True)
