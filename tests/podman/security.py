#!/usr/bin/env python3
"""Negative authentication, adversarial peers, resume and lifecycle tests in Podman."""
import json
from pathlib import Path
import time
import application as app
from application import lab

A,B=lab.PEERS
BASE='/work/app-tests'
PASSWORD=app.PASSWORD
PORT=40401
IP=lab.owned('container',B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']


def mkdir(peer,path):app.execute(peer,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir(parents=True,exist_ok=True)',path)


def server(path,quals=(),action='get',password=PASSWORD):
    job=app.start(B,['force',*quals,action,str(PORT),path],password=password);app.ready(job);return job


def put(path,quals=(),port=PORT,password=PASSWORD):return app.command(A,['force',*quals,'put',f'{IP}:{port}',path],password=password)


def unchanged(before,path):assert app.snapshot(B,path)==before,(path,before,app.snapshot(B,path))


def proxy(mode):
    job=f'{BASE}/proxy-{mode}-{time.monotonic_ns()}'
    app.execute(B,'''import subprocess,sys
subprocess.Popen(['python3','/app/proxy.py','40402','40401',sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
''',mode,job)
    for _ in range(100):
        ready=app.execute(B,'import pathlib,sys;print(pathlib.Path(sys.argv[1]+".ready").exists())',job)
        if ready=='True':break
        time.sleep(.05)
    else:raise AssertionError('proxy not ready')
    return job


def main():
    lab.status()
    for peer in (A,B):
        lab.podman('cp',str(app.ROOT/'target/x86_64-unknown-linux-musl/release/examples/adversary'),peer+':/app/adversary')
        lab.podman('cp',str(Path(__file__).with_name('proxy.py')),peer+':/app/proxy.py')
    source=f'{BASE}/security-source';app.fixture(A,source,2_000_003)
    dest=f'{BASE}/security-dest';mkdir(B,dest)
    for password in [PASSWORD[:-1]+'R',PASSWORD.lower(),PASSWORD.replace('-','')]:
        job=server(dest);before=app.snapshot(B,dest);result=put(source,password=password);assert result['code']!=0,result;assert app.wait(job)['code']!=0;unchanged(before,dest)
        app.record('wrong password before metadata',root_unchanged=True)
    # Prove authentication happens before even opening a nonexistent transfer root.
    job=server('/does-not-exist');result=put('/also-missing',password='incorrect-password');assert 'authentication' in result['err'] and result['code']!=0,result;assert app.wait(job)['code']!=0
    app.record('authentication gates nonexistent roots')
    # Capture repeat sessions then replay old KE3 into a fresh handshake.
    handshake=[]
    for _ in range(2):
        job=server(dest);p=proxy('capture');result=put(source,port=40402);app.stats(result);assert app.wait(job)['code']==0
        handshake.append(app.execute(B,'import pathlib,sys;print(pathlib.Path(sys.argv[1]+".handshake").read_text())',p))
        wire=app.execute(B,'''import pathlib,sys
b=pathlib.Path(sys.argv[1]+'.wire').read_bytes()
assert b'Unicode' not in b and b'security-source' not in b and sys.argv[2].encode() not in b
print('private')
''',p,PASSWORD);assert wire=='private'
    assert handshake[0]!=handshake[1];app.record('fresh handshakes and encrypted filenames/password/content')
    for mode in ['replay','tamper-handshake','missing-final','tamper','duplicate','truncate']:
        job=server(dest);before=app.snapshot(B,dest);p=proxy(mode);result=put(source,port=40402);assert result['code']!=0,(mode,result);assert app.wait(job)['code']!=0;unchanged(before,dest);app.record(mode,root_unchanged=True)
    # Arbitrary unauthenticated data, legacy magic and oversize handshake.
    for packet in ['0000000000000006','5353594e4334000101ffffffff','5353594e433400010100000000']:
        job=server(dest);before=app.snapshot(B,dest)
        app.execute(A,'''import socket,sys
with socket.create_connection((sys.argv[1],40401),timeout=3) as s:s.sendall(bytes.fromhex(sys.argv[2]));s.shutdown(socket.SHUT_WR)
''',IP,packet)
        assert app.wait(job)['code']!=0;unchanged(before,dest);app.record('unauthenticated malformed handshake',packet=packet)
    # Authenticated malicious messages cannot broaden root or invoke commands.
    for mode,path in [('path','../outside'),('path','/work/app-tests/outside'),('path','source/../../outside'),('path','source\\x'),('path','source/.ssync-state/x'),('unknown',''),('duplicate',''),('size','source/x'),('incomplete',''),('block','source/x'),('digest','source/x')]:
        job=server(dest);before=app.snapshot(B,dest)
        result=json.loads(app.execute(A,'''import subprocess,os,json,sys
env=os.environ.copy();env['SSYNC_PASSWORD']=sys.argv[1]
r=subprocess.run(['/app/adversary',sys.argv[2],sys.argv[3],sys.argv[4]],capture_output=True,text=True,env=env,timeout=20)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''',PASSWORD,f'{IP}:{PORT}',mode,path))
        remote=app.wait(job);assert remote['code']!=0,(mode,path,remote)
        expected={'path':'unsafe','unknown':'malformed or unknown','duplicate':'duplicate entry','size':'file size limit','incomplete':'incomplete manifest','block':'invalid block range','digest':'block content verification failed'}[mode]
        assert result['code']==0 and 'Rejected' in result['out'] and expected in remote['err'],(mode,result,remote)
        # Directory creation before malformed final state is permitted; existing file bytes must survive.
        after=app.snapshot(B,dest)
        for key,value in before.items():assert after.get(key)==value,(mode,key)
        app.record('adversarial protocol',mode=mode,path=path,server_error=remote['err'])
    # Filesystem links/special files from source are rejected, outside canary unchanged.
    for kind in ['symlink','hardlink','fifo']:
        path=f'{BASE}/bad-{kind}';mkdir(A,path)
        app.execute(A,'''import os,pathlib,sys
p=pathlib.Path(sys.argv[1]);kind=sys.argv[2]
if kind=='symlink':os.symlink('/work/app-tests/outside/canary',p/'attack')
elif kind=='hardlink':os.link('/work/app-tests/outside/canary',p/'attack')
else:os.mkfifo(p/'attack')
''',path,kind)
        job=server(dest);result=put(path);assert result['code']!=0,result;assert app.wait(job)['code']!=0;app.record('unsafe source rejected',kind=kind)
    # Private partial resumes after a measured interrupted transfer.
    resume_source=f'{BASE}/resume-source';app.fixture(A,resume_source,20_000_000)
    resume_dest=f'{BASE}/resume-dest';mkdir(B,resume_dest)
    job=server(resume_dest,quals=['merge']);p=proxy('interrupt');result=put(resume_source,port=40402);assert result['code']!=0,result;assert app.wait(job)['code']!=0
    partial=app.execute(B,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);parts=list((p/'.ssync-state').glob('*'));assert parts;assert not (p/'big.bin').exists();print(sum(f.stat().st_size for f in parts))
''',resume_dest);assert int(partial)>=400000,partial
    job=server(resume_dest,quals=['merge']);result=put(resume_source);measure=app.stats(result);assert app.wait(job)['code']==0
    assert 0<measure['content_bytes']<20_000_009,measure;assert measure['reused_bytes']>=400000,measure;app.record('verified interrupted resume',partial_bytes=int(partial),stats=measure)
    # Dry run must preserve all entries and create no private state.
    dry=f'{BASE}/dry';mkdir(B,dry);before=app.snapshot(B,dry);job=server(dry,quals=['merge','dryrun']);result=put(source);assert app.stats(result)['content_bytes']==0;assert app.wait(job)['code']==0;unchanged(before,dry)
    assert app.execute(B,'import pathlib,sys;print((pathlib.Path(sys.argv[1])/".ssync-state").exists())',dry)=='False';app.record('genuinely write-free dry run')
    # Safe mirroring, filters/nodelete, single file doesn't delete neighbours.
    filtered=f'{BASE}/filtered';mkdir(B,filtered)
    app.execute(B,'import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/"extra").write_bytes(b"extra");(p/"keep.secret").write_bytes(b"keep")',filtered)
    job=server(filtered,quals=['merge','nodelete']);result=put(source);app.stats(result);assert app.wait(job)['code']==0;assert 'extra' in app.snapshot(B,filtered)
    job=server(filtered,quals=['merge','skip:secret']);result=put(source);measure=app.stats(result);assert app.wait(job)['code']==0;assert 'extra' not in app.snapshot(B,filtered);assert 'keep.secret' in app.snapshot(B,filtered);assert measure['deleted']==1;app.record('nodelete and filter-protected scoped deletion',stats=measure)
    job=server(filtered);result=put(source+'/zero');app.stats(result);assert app.wait(job)['code']==0;assert 'keep.secret' in app.snapshot(B,filtered);app.record('single-file deletion containment')
    for peer in (A,B):assert app.execute(peer,"import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY';print('OK')")=='OK'
    app.record('security canaries survived all attacks')


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
