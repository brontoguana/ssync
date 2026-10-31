#!/usr/bin/env python3
"""Backup modes: actual uploads and attacks confined to labelled rootless peers."""
import json
from pathlib import Path
import time
import application as app
from application import lab

A,B=lab.PEERS
BASE='/work/app-tests'
P=app.PASSWORD
Q='QRST-UVWX-YZab-cdef-ghij-kmnp'
SRC=BASE+'/backup source=one'
SRC2=BASE+'/backup-source-two'
CONF=BASE+'/backup-client.ssync'
SERV=BASE+'/backup-server.ssync'
JOBS={}
IPS={}


def write(peer,path,text,mode=0o600):
    app.execute(peer,'''import pathlib,sys,os
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(int(sys.argv[3]))
''',path,text,mode)


def client(servers=None,entries=None,quals=(),timeout=120):
    servers=servers or [f'{IPS[A]}',f'{IPS[B]}:40401']
    entries=entries or [(P,SRC),(Q,SRC2)]
    # Deliberately mix line order to prove destinations are global.
    text='\n'.join([f'{pw}={path}' for pw,path in entries]+['@'+host for host in servers])+'\n'
    write(A,CONF,text)
    return app.command(A,[*quals,'backup-client',CONF],password='environment-is-not-this-password',timeout=timeout)


def start_server(peer):
    if peer in JOBS:app.stop(JOBS.pop(peer))
    args=['backup-server',SERV] if peer==A else ['backup-server','40401',SERV]
    job=app.start(peer,args);app.ready(job);JOBS[peer]=job


def measures(result):
    return [json.loads(line.split(' ',1)[1]) for line in result['out'].splitlines() if line.startswith('SSYNC_STATS ')]


def assert_equal(peer,source,dest):
    expected=app.snapshot(A,source);actual=app.snapshot(peer,dest)
    assert {k:v[:3] for k,v in actual.items()}=={k:v[:3] for k,v in expected.items()},(source,dest,actual,expected)


def proxy(mode):
    path=BASE+f'/backup-proxy-{mode}-{time.monotonic_ns()}'
    app.execute(B,'''import subprocess,sys
subprocess.Popen(['python3','/app/proxy.py','40402','40401',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
''',mode,path)
    for _ in range(100):
        if app.execute(B,"import pathlib,sys;print(pathlib.Path(sys.argv[1]+'.ready').exists())",path)=='True':return path
        time.sleep(.05)
    raise AssertionError('proxy not ready')


def main():
    status=app.setup(app.BINARY)
    for peer in (A,B):
        IPS[peer]=lab.owned('container',peer)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
        lab.podman('cp',str(app.ROOT/'target/x86_64-unknown-linux-musl/release/examples/adversary'),peer+':/app/adversary')
        lab.podman('cp',str(Path(__file__).with_name('proxy.py')),peer+':/app/proxy.py')
        for name in ['bay-one','bay-two']:
            app.execute(peer,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',BASE+'/'+name)
        write(peer,SERV,f'# bays\n{P}={BASE}/bay-one\n{Q}={BASE}/bay-two\n')
    app.fixture(A,SRC,4_000_003);app.fixture(A,SRC2,321_012)
    for action in ['backup-server','backup-client']:
        path=BASE+'/'+action+'-missing.ssync'
        r=app.command(A,[action,path]);assert r['code']!=0 and 'created private example' in r['err'],r
        app.execute(A,'''import pathlib,sys,stat
p=pathlib.Path(sys.argv[1]);assert stat.S_IMODE(p.stat().st_mode)==0o600
assert all(not l.strip() or l.lstrip().startswith('#') for l in p.read_text().splitlines())
''',path)
        r=app.command(A,[action,path]);assert r['code']!=0 and 'active' in r['err'],r
        app.record('private commented template',action=action)
    invalid=BASE+'/invalid.ssync'
    for text in [f'{P}={BASE}/bay-one\n{P}={BASE}/bay-two', f'{P}={BASE}/bay-one\n{Q}={BASE}/bay-one/sub', f'{P}=relative', f'short={BASE}/bay-one', f'{P}={BASE}', f'{P}=/missing-bay']:
        write(B,invalid,text);r=app.command(B,['backup-server',invalid]);assert r['code']!=0 and 'now accepting' not in r['out'],r
        assert P not in r['err'] and Q not in r['err'],r
    write(B,invalid,f'{P}={BASE}/bay-one',0o644)
    r=app.command(B,['backup-server',invalid]);assert r['code']!=0 and 'private' in r['err'],r
    app.execute(B,'''import pathlib,sys,os
p=pathlib.Path(sys.argv[1]);p.unlink();p.symlink_to(sys.argv[2])
''',invalid,SERV)
    assert app.command(B,['backup-server',invalid])['code']!=0
    app.record('server rejects duplicate/overlap/relative/missing/inside-root/private/link configs without secret disclosure')
    start_server(A);start_server(B)
    result=client();assert result['code']==0,result
    assert len(measures(result))==4,result
    for peer in (A,B):
        assert_equal(peer,SRC,BASE+'/bay-one');assert_equal(peer,SRC2,BASE+'/bay-two')
    app.record('two sources to two servers, default/custom port, password bay selection, no environment override',stats=measures(result))
    result=client();assert result['code']==0 and sum(s['content_bytes'] for s in measures(result))==0,result
    app.record('identical repeat transfers zero content',stats=measures(result))
    app.execute(A,'''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'big.bin'
with p.open('r+b') as f:f.seek(1_000_001);f.write(b'X')
''',SRC)
    result=client();assert result['code']==0 and sum(s['content_bytes'] for s in measures(result))==400_000,result
    app.record('one changed block sends 200000 bytes per destination',stats=measures(result))
    for peer in (A,B):write(peer,BASE+'/bay-one/extra','keep until complete')
    before={peer:app.snapshot(peer,BASE+'/bay-one') for peer in (A,B)}
    result=client(quals=['dryrun']);assert result['code']==0,result
    assert all(app.snapshot(peer,BASE+'/bay-one')==before[peer] for peer in (A,B))
    result=client(quals=['nodelete']);assert result['code']==0,result
    assert all('extra' in app.snapshot(peer,BASE+'/bay-one') for peer in (A,B))
    result=client(quals=['skip:extra']);assert result['code']==0,result
    assert all('extra' in app.snapshot(peer,BASE+'/bay-one') for peer in (A,B))
    result=client();assert result['code']==0,result
    assert all('extra' not in app.snapshot(peer,BASE+'/bay-one') for peer in (A,B))
    app.record('dryrun write-free, nodelete/filter protected extras, complete mirror deletion')
    # Validate entire config before connecting: a valid first line cannot cause partial execution.
    before=app.snapshot(B,BASE+'/bay-one')
    write(A,CONF,f'@{IPS[B]}:40401\n{P}={SRC}\nshort={SRC2}\n')
    result=app.command(A,['backup-client',CONF]);assert result['code']!=0 and not measures(result),result
    assert app.snapshot(B,BASE+'/bay-one')==before
    result=client(servers=[f'{IPS[A]}',f'{IPS[B]}:49999']);assert result['code']!=0 and len(measures(result))==2,result
    assert '2 succeeded, 2 failed' in result['out'],result
    app.record('full config preflight and independent unavailable destinations')
    result=client(servers=[f'{IPS[B]}:40401'],entries=[('incorrect-password',SRC)])
    assert result['code']!=0 and 'authentication' in result['err'],result
    assert app.snapshot(B,BASE+'/bay-one')==before
    # Standard upload/download cannot use backup credentials to enter the backup protocol.
    for action in ['put','get']:
        result=app.command(A,['force',action,f'{IPS[B]}:40401',SRC]);assert result['code']!=0,result
    app.record('wrong password and standard upload/download rejected before metadata')
    start_server(B)
    # One-bay credential never accesses the other bay, including malicious path attempts.
    for mode,path in [('path','../bay-two/escape'),('path','/work/app-tests/bay-two/escape'),('path','link/escape'),('unknown',''),('size','bad'),('block','bad'),('digest','bad'),('incomplete','')]:
        if path=='link/escape':app.execute(B,"import pathlib;pathlib.Path('/work/app-tests/bay-one/link').symlink_to('/work/app-tests/bay-two',target_is_directory=True)")
        before_two=app.snapshot(B,BASE+'/bay-two')
        result=json.loads(app.execute(A,'''import os,subprocess,json,sys
env=os.environ.copy();env['SSYNC_PASSWORD']=sys.argv[1]
r=subprocess.run(['/app/adversary','--backup',sys.argv[2],sys.argv[3],sys.argv[4]],env=env,capture_output=True,text=True,timeout=30)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''',P,f'{IPS[B]}:40401',mode,path,timeout=40))
        assert result['code']==0 and 'Rejected' in result['out'],(mode,result)
        assert app.snapshot(B,BASE+'/bay-two')==before_two
        app.record('backup malicious peer rejected',mode=mode,path=path)
        if path=='link/escape':app.execute(B,"import pathlib;pathlib.Path('/work/app-tests/bay-one/link').unlink()")
    # Encryption, replay and incomplete mutual confirmation on the new multi-bay handshake.
    for mode in ['capture','capture','replay','tamper-handshake','missing-final','tamper','duplicate','truncate']:
        start_server(B)
        p=proxy(mode);before=app.snapshot(B,BASE+'/bay-two')
        result=client(servers=[f'{IPS[B]}:40402'],entries=[(Q,SRC2)])
        if mode=='capture':assert result['code']==0,result
        else:assert result['code']!=0,(mode,result);assert app.snapshot(B,BASE+'/bay-two')==before
        app.execute(B,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]+'.wire')
if p.exists():
 b=p.read_bytes();assert sys.argv[2].encode() not in b and b'Unicode' not in b and b'backup-source-two' not in b
''',p,Q)
        app.record('backup encrypted channel',mode=mode)
    start_server(B)
    # Interrupted changed data preserve original; resume reuses verified partial blocks.
    app.fixture(A,SRC2,20_000_003)
    before=app.snapshot(B,BASE+'/bay-two')
    p=proxy('interrupt');result=client(servers=[f'{IPS[B]}:40402'],entries=[(Q,SRC2)])
    assert result['code']!=0,result
    assert app.snapshot(B,BASE+'/bay-two')==before
    result=client(servers=[f'{IPS[B]}:40401'],entries=[(Q,SRC2)])
    assert result['code']==0 and measures(result)[0]['reused_bytes']>0,result
    assert_equal(B,SRC2,BASE+'/bay-two')
    app.record('interruption preserves prior file; verified resume',stats=measures(result))
    # Hold a confirmed upload and show a second connection to that bay fails as busy.
    app.execute(A,'''import pathlib,subprocess,os,sys
env=os.environ.copy();env['SSYNC_PASSWORD']=sys.argv[1]
with open('/work/app-tests/held.out','w') as out:
 p=subprocess.Popen(['/app/adversary','--backup',sys.argv[2],'hold','busy-file'],env=env,stdout=out,stderr=out)
pathlib.Path('/work/app-tests/held.pid').write_text(str(p.pid))
''',P,f'{IPS[B]}:40401')
    # stdout to file is buffered; stage existence establishes the holder reached file requests.
    for _ in range(100):
        if app.execute(B,"import pathlib;print(pathlib.Path('/work/app-tests/bay-one/.ssync-state').exists())")=='True':break
        time.sleep(.1)
    time.sleep(.5)
    result=client(servers=[f'{IPS[B]}:40401'],entries=[(P,SRC),(Q,SRC2)])
    assert result['code']!=0 and len(measures(result))==1 and 'busy' in result['err'],result
    app.execute(A,"import os,pathlib;os.kill(int(pathlib.Path('/work/app-tests/held.pid').read_text()),9)")
    app.record('same bay busy; different bay remains available')
    start_server(B)
    # Cancel a progressing update and preserve its previously committed file.
    app.execute(A,"import pathlib,sys;(pathlib.Path(sys.argv[1])/'big.bin').write_bytes(b'Z'*20_000_003)",SRC2)
    before=app.snapshot(B,BASE+'/bay-two')
    proxy('slow')
    write(A,CONF,f'@{IPS[B]}:40402\n{Q}={SRC2}\n')
    cancelled=app.start(A,['backup-client',CONF])
    for _ in range(150):
        if 'Authenticated transfer' in app.logs(cancelled)['out']:break
        time.sleep(.1)
    else:raise AssertionError(app.logs(cancelled))
    time.sleep(.7)
    assert app.stop(cancelled,sig=15)['code']!=0
    assert app.snapshot(B,BASE+'/bay-two')==before
    start_server(B)
    result=client(servers=[f'{IPS[B]}:40401']);assert result['code']==0,result
    app.record('SIGTERM cancels sockets and preserves uncommitted destination; listener restart/resume succeeds')
    # Upper bay bound with a password at the final candidate, plus IPv6/default port.
    entries=[]
    for index in range(32):
        path=BASE+f'/many-bay-{index}'
        app.execute(A,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',path)
        entries.append((f'unique-password-{index:04d}',path))
    write(A,SERV,'\n'.join(f'{pw}={path}' for pw,path in entries))
    start_server(A)
    result=client(servers=['[::1]'],entries=[(entries[-1][0],SRC)])
    assert result['code']==0,result
    assert_equal(A,SRC,entries[-1][1])
    app.record('32-bay bound, last password selection and IPv6 default port',stats=measures(result))
    for peer in (A,B):assert app.execute(peer,"import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY';print('OK')")=='OK'
    app.record('listener survives rejected sessions; final successful backup and outside canaries intact')


if __name__=='__main__':
    try:main()
    finally:
        for job in JOBS.values():
            try:app.stop(job)
            except Exception:pass
        app.cleanup()
