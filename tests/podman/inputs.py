#!/usr/bin/env python3
"""Real CLI prompts, credential inputs, config concurrency and admission limits."""
import json
import time
import application as app
from application import lab
import security as sec

A,B=lab.PEERS
BASE='/work/app-tests'


def main():
    lab.status()
    source=f'{BASE}/input-source';app.fixture(A,source,200001)
    dest=f'{BASE}/input-dest';sec.mkdir(B,dest)
    # Hidden password prompt under a real container PTY. No echo of the secret.
    job=sec.server(dest)
    output=app.execute(A,'''import os,pty,select,sys,time
pid,fd=pty.fork()
if pid==0:
 env=os.environ.copy();env.pop('SSYNC_PASSWORD',None)
 os.execve('/app/ssync',['ssync','force','put',sys.argv[1],sys.argv[2]],env)
buf=bytearray();sent=False;end=time.monotonic()+20
while time.monotonic()<end:
 if select.select([fd],[],[],.2)[0]:
  try:b=os.read(fd,4096)
  except OSError:break
  if not b:break
  buf.extend(b)
  if b'Password:' in buf and not sent:
   time.sleep(.1);os.write(fd,sys.argv[3].encode()+b'\\n');sent=True
else:os.kill(pid,9);raise RuntimeError('PTY timeout')
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0;assert sys.argv[3].encode() not in buf
print(buf.decode())
''',f'{sec.IP}:{sec.PORT}',source,app.PASSWORD)
    assert 'SSYNC_STATS' in output and app.wait(job)['code']==0;app.record('hidden password prompt without echo')
    # Guide uses exactly the same command contract and confirms before transfer.
    job=sec.server(dest)
    result=json.loads(app.execute(A,'''import subprocess,json,os,sys
env={**os.environ,'SSYNC_PASSWORD':sys.argv[3]}
r=subprocess.run(['/app/ssync','?'],input='put\\n'+sys.argv[1]+'\\n'+sys.argv[2]+'\\ny\\n',capture_output=True,text=True,env=env,timeout=20)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''',f'{sec.IP}:{sec.PORT}',source,app.PASSWORD));app.stats(result);assert app.wait(job)['code']==0;app.record('interactive guidance and positive confirmation')
    job=sec.server(dest)
    result=json.loads(app.execute(A,'''import subprocess,json,os,sys
r=subprocess.run(['/app/ssync','put',sys.argv[1],sys.argv[2]],input='n\\n',capture_output=True,text=True,env={**os.environ,'SSYNC_PASSWORD':sys.argv[3]},timeout=20)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''',f'{sec.IP}:{sec.PORT}',source,app.PASSWORD));assert result['code']!=0 and app.wait(job)['code']!=0;app.record('negative confirmation cancels')
    # Private file and inherited descriptor, keeping inline/environment precedence.
    secret=f'{BASE}/private.password'
    app.execute(A,'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]+"\\n");p.chmod(0o600)',secret,app.PASSWORD)
    job=sec.server(dest);r=app.command(A,['force','put',f'{sec.IP}:{sec.PORT}',source],password='',env={'SSYNC_PASSWORD_FILE':secret});app.stats(r);assert app.wait(job)['code']==0
    app.execute(A,'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o644)',secret)
    r=app.command(A,['force','put',f'{sec.IP}:{sec.PORT}',source],password='',env={'SSYNC_PASSWORD_FILE':secret});assert r['code']!=0 and 'private' in r['err'];app.record('private password file and permission rejection')
    job=sec.server(dest)
    r=json.loads(app.execute(A,'''import subprocess,os,json,sys
read,write=os.pipe();os.write(write,sys.argv[3].encode());os.close(write)
env=os.environ.copy();env.pop('SSYNC_PASSWORD',None);env['SSYNC_PASSWORD_FD']=str(read)
r=subprocess.run(['/app/ssync','force','put',sys.argv[1],sys.argv[2]],env=env,pass_fds=(read,),capture_output=True,text=True,timeout=20);os.close(read)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''',f'{sec.IP}:{sec.PORT}',source,app.PASSWORD));app.stats(r);assert app.wait(job)['code']==0;app.record('exact inherited password descriptor input')
    # Two parallel declarative commands using quoted spaced/Unicode filenames.
    app.execute(A,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);(p/'space name').write_bytes(b'space');(p/'你好').write_bytes(b'Unicode')
''',source)
    jobs=[];destinations=[]
    for port in [40404,40405]:
        path=f'{BASE}/batch-{port}';sec.mkdir(B,path);destinations.append(path)
        j=app.start(B,['force','get',str(port),path]);app.ready(j);jobs.append(j)
    cfg=f'{BASE}/parallel.ssync'
    app.execute(A,'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)',cfg,f'force put {sec.IP}:40404 "{source}/space name"\nforce put {sec.IP}:40405 "{source}/你好"\n')
    r=app.command(A,[cfg]);assert r['code']==0 and r['out'].count('SSYNC_STATS ')==2,r
    for j in jobs:assert app.wait(j)['code']==0
    assert 'space name' in app.snapshot(B,destinations[0]) and '你好' in app.snapshot(B,destinations[1]);app.record('concurrent .ssync commands and quoted Unicode/spaced paths')
    # Receiver verify and sender verbose produce actual diagnostics; mtime retained.
    verified=f'{BASE}/verified-inputs';sec.mkdir(B,verified)
    job=sec.server(verified,quals=['merge','verify','verbose']);r=sec.put(source,quals=['verify','verbose']);app.stats(r)
    remote=app.wait(job);assert remote['code']==0 and 'Directory Verification Hash' in remote['out'] and 'Block ' in r['out'] and 'Directory Verification Hash' in r['out'],(r,remote)
    original=app.snapshot(A,source);actual=app.snapshot(B,verified)
    for name,meta in original.items():
        if meta[0]=='file':assert actual[name][4]==meta[4],(name,meta,actual[name])
    app.record('verbose/verify behavior and modification-time preservation')
    app.execute(B,'import pathlib,sys;pathlib.Path(sys.argv[1],"extra").write_bytes(b"keep")',verified)
    job=sec.server(verified,quals=['merge']);r=sec.put(source,quals=['nodelete']);app.stats(r);assert app.wait(job)['code']==0
    assert 'extra' in app.snapshot(B,verified);app.record('sender nodelete narrows receiver deletion')
    # Exact continuous offer-listener + accept-connector pair.
    j=app.start(A,['force','offer','40403',source]);app.ready(j)
    ip=lab.owned('container',A)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    c=app.start(B,['force','accept',f'{ip}:40403',dest])
    end=time.monotonic()+20
    while time.monotonic()<end:
        if app.logs(c)['out'].count('SSYNC_STATS ')>=2:break
        time.sleep(.1)
    else:raise AssertionError(app.logs(c))
    app.stop(c);app.stop(j);app.record('offer listener + continuous accept connector')
    # Deliberately slow unauthenticated frame cannot extend the wall-clock deadline.
    job=sec.server(dest);started=time.monotonic()
    elapsed=app.execute(A,'''import socket,time,sys
started=time.monotonic()
with socket.create_connection((sys.argv[1],40401),timeout=3) as s:
 s.sendall(b'SSYNC4\\0\\x01\\x01'+(1000).to_bytes(4,'big'))
 try:
  for i in range(40):s.sendall(b'x');time.sleep(.5)
 except OSError:pass
print(time.monotonic()-started)
''',sec.IP,timeout=25)
    assert float(elapsed)<18,elapsed;assert app.wait(job)['code']!=0;app.record('slow-trickle handshake deadline',elapsed_seconds=float(elapsed))
    # Many distinct loopback addresses share one listener-wide admission budget.
    job=sec.server(dest,action='accept')
    count=int(app.execute(B,'''import socket,time
admitted=0
for i in range(2,42):
 with socket.socket() as s:
  s.settimeout(2);s.bind((f'127.0.0.{i}',0));s.connect(('127.0.0.1',40401))
  hello=s.recv(9)
  if hello:
   admitted+=1;s.sendall(b'XXXXXXXXX')
   try:s.recv(1)
   except OSError:pass
print(admitted)
''',timeout=30));assert 0<count<=22,count
    # Check recovery after temporary global delay without stopping/revoking the listener.
    for _ in range(31):time.sleep(1)
    r=sec.put(source);app.stats(r);app.stop(job);app.record('distributed-address admission budget and recovery',admitted=count,attempts=40)
    # IPv6 works locally in the same isolated peer.
    job=sec.server(dest)
    app.fixture(B,f'{BASE}/ipv6-source',1000)
    r=app.command(B,['force','put',f'[::1]:{sec.PORT}',f'{BASE}/ipv6-source']);app.stats(r);assert app.wait(job)['code']==0;app.record('IPv6 listener/connector')


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
