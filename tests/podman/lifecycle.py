#!/usr/bin/env python3
"""CLI/config, persistent operation, filesystem races, mutation and failure tests."""
import json
import time
from pathlib import Path
import application as app
from application import lab
import security as sec

A,B=lab.PEERS
BASE='/work/app-tests'


def has_stats(job,n=1):
    end=time.monotonic()+20
    while time.monotonic()<end:
        if app.logs(job)['out'].count('SSYNC_STATS ')>=n:return
        time.sleep(.1)
    raise AssertionError(app.logs(job))


def async_python(peer,script):
    return app.execute(peer,'''import pathlib,subprocess,sys
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2])
child=subprocess.Popen(['python3',str(p)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(child.pid)
''',f'{BASE}/helper-{time.monotonic_ns()}.py',script)


def kill(peer,pid):app.execute(peer,'''import os,sys
try:os.kill(int(sys.argv[1]),15)
except ProcessLookupError:pass
''',pid)


def wait_partial(path):
    end=time.monotonic()+15
    while time.monotonic()<end:
        state=app.execute(B,'''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'.ssync-state'
print(sum(f.stat().st_size for f in p.glob('*')) if p.exists() else 0)
''',path)
        if int(state)>200000:return
        time.sleep(.1)
    raise AssertionError('no partial written')


def main():
    lab.status()
    source=f'{BASE}/lifecycle-source';app.fixture(A,source,8_000_000)
    app.execute(A,'import pathlib,sys;pathlib.Path(sys.argv[1],"new").unlink(missing_ok=True)',source)
    dest=f'{BASE}/lifecycle-dest';sec.mkdir(B,dest)
    for diag in ['hash','deep','scan']:
        path=source if diag=='hash' else source+'/big.bin';r=app.command(A,[diag,path]);assert r['code']==0,r
    r=app.command(A,[source+'/big.bin']);assert r['code']==0 and '8000000 bytes' in r['out'],r
    app.record('hash/deep/scan/file-inspection commands')
    # Environment overrides inline credential while retaining clean location.
    job=sec.server(dest);r=app.command(A,['force','put',f'wrong-inline-value@{sec.IP}:{sec.PORT}',source]);app.stats(r);assert app.wait(job)['code']==0
    app.record('environment > inline password precedence')
    # Aliases and all continuous verbs with a connector are supported.
    alias='Integration-é';job=app.start(B,['force','accept',alias,dest]);app.ready(job)
    r=app.command(A,['force','put',f'{sec.IP}:{alias}',source]);app.stats(r);app.stop(job);app.record('Unicode Java-compatible alias')
    # Repeated continuous connector, change content during service, retain credential.
    job=sec.server(dest,action='accept');connector=app.start(A,['force','offer',f'{sec.IP}:{sec.PORT}',source]);has_stats(connector,2)
    app.execute(A,"import pathlib;pathlib.Path('/work/app-tests/lifecycle-source/new').write_bytes(b'repeated')")
    has_stats(connector,3);app.stop(connector);app.stop(job)
    assert 'source/new' not in app.snapshot(B,dest) # actual basename is lifecycle-source
    assert 'lifecycle-source/new' in app.snapshot(B,dest);app.record('continuous connector repeat and reusable credential')
    # Concurrent downloads from a persistent sender into independent roots.
    offer=app.start(A,['force','offer','40403',source]);app.ready(offer)
    ip=lab.owned('container',A)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    jobs=[]
    for i in range(3):
        d=f'{BASE}/concurrent-{i}';sec.mkdir(B,d);jobs.append(app.start(B,['force','get',f'{ip}:40403',d]))
    for j in jobs:app.stats(app.wait(j))
    app.stop(offer);app.record('concurrent persistent downloads',sessions=3)
    # Receiving root conflicts must fail; no concurrent writers to a tree.
    accept=sec.server(dest,action='accept')
    holder=async_python(A,f"""import subprocess,os
subprocess.run(['/app/adversary','{sec.IP}:{sec.PORT}','hold','lifecycle-source/held'],env={{**os.environ,'SSYNC_PASSWORD':'{app.PASSWORD}'}})
""")
    time.sleep(2)
    r=sec.put(source);assert r['code']!=0 and 'busy' in app.logs(accept)['err'],(r,app.logs(accept))
    kill(A,holder);app.stop(accept);app.record('concurrent destination lock rejects writer')
    # Declarative config: valid quoted transfer; local management/execution prohibited.
    cfg=f'{BASE}/batch.ssync'
    app.execute(A,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)
''',cfg,f'force put {sec.IP}:{sec.PORT} "{source}"\n')
    job=sec.server(dest);r=app.command(A,[cfg]);app.stats(r);assert app.wait(job)['code']==0
    for text in ['install\n','script:x:y put 4000 .\n','force put "unterminated\n']:
        app.execute(A,'import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[2])',cfg,text)
        r=app.command(A,[cfg]);assert r['code']!=0,r
    app.record('.ssync declarative parser and forbidden-operation rejection')
    # Genuinely no changes if sender alone requests dryrun.
    dry=f'{BASE}/sender-dry';sec.mkdir(B,dry);before=app.snapshot(B,dry);job=sec.server(dry);r=sec.put(source,quals=['dryrun']);assert app.stats(r)['content_bytes']==0;assert app.wait(job)['code']==0;sec.unchanged(before,dry);app.record('sender-initiated dryrun')
    # Source mutation mid-stream preserves old receiver file.
    mutant=f'{BASE}/mutation';sec.mkdir(B,mutant)
    app.execute(B,'import pathlib,sys;pathlib.Path(sys.argv[1],"big.bin").write_bytes(b"OLD")',mutant)
    job=sec.server(mutant,quals=['merge']);sec.proxy('slow');client=app.start(A,['force','put',f'{sec.IP}:40402',source]);wait_partial(mutant)
    app.execute(A,'import pathlib,sys;p=pathlib.Path(sys.argv[1],"big.bin");f=p.open("r+b");f.seek(7000000);f.write(b"MUTATED");f.close()',source)
    r=app.wait(client);assert r['code']!=0,r;assert app.wait(job)['code']!=0;assert app.execute(B,'import pathlib,sys;print(pathlib.Path(sys.argv[1],"big.bin").read_bytes().decode())',mutant)=='OLD';app.record('source mutation preserves existing destination')
    # Concurrent destination edit likewise must survive failed commit.
    conflict=f'{BASE}/conflict';sec.mkdir(B,conflict)
    app.execute(B,'import pathlib,sys;pathlib.Path(sys.argv[1],"big.bin").write_bytes(b"OLD")',conflict)
    job=sec.server(conflict,quals=['merge']);sec.proxy('slow');client=app.start(A,['force','put',f'{sec.IP}:40402',source]);wait_partial(conflict)
    app.execute(B,'import pathlib,sys;pathlib.Path(sys.argv[1],"big.bin").write_bytes(b"USER EDIT")',conflict)
    r=app.wait(client);assert r['code']!=0,r;assert app.wait(job)['code']!=0;assert app.execute(B,'import pathlib,sys;print(pathlib.Path(sys.argv[1],"big.bin").read_bytes().decode())',conflict)=='USER EDIT';app.record('destination mutation rejected and user edit preserved')
    term=f'{BASE}/term';sec.mkdir(B,term)
    app.execute(B,'import pathlib,sys;pathlib.Path(sys.argv[1],"big.bin").write_bytes(b"TERM ORIGINAL")',term)
    job=sec.server(term,quals=['merge']);sec.proxy('slow');client=app.start(A,['force','put',f'{sec.IP}:40402',source]);wait_partial(term)
    r=app.stop(client,sig=15);assert r['code']==1 and app.wait(job)['code']!=0
    assert app.execute(B,'import pathlib,sys;print(pathlib.Path(sys.argv[1],"big.bin").read_bytes().decode())',term)=='TERM ORIGINAL'
    app.record('SIGTERM graceful cancellation preserves original')
    # Symlink-directory racing cannot write to pre-existing outside-root canaries.
    race_source=f'{BASE}/race-source';sec.mkdir(A,race_source)
    app.execute(A,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);(p/'nested').mkdir(exist_ok=True);(p/'nested/canary').write_bytes(b'INSIDE')
''',race_source)
    raced=f'{BASE}/race-dest';sec.mkdir(B,raced)
    script=f"""import pathlib,os,time
p=pathlib.Path('{raced}');d=p/'nested';h=p/'holding'
d.mkdir(exist_ok=True)
for _ in range(3000):
 try:
  d.rename(h);os.symlink('/work/app-tests/outside',d);time.sleep(.001);d.unlink();h.rename(d)
 except OSError:pass
if d.is_symlink():d.unlink()
if h.exists() and not d.exists():h.rename(d)
"""
    pid=async_python(B,script)
    job=sec.server(raced,quals=['merge','nodelete']);r=sec.put(race_source);remote=app.wait(job)
    assert (r['code']==0)==(remote['code']==0),(r,remote)
    time.sleep(4)
    assert app.execute(B,"import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY';print('OK')")=='OK'
    app.record('directory symlink race containment',transfer_exit=r['code'])
    # Disk-full causes truthful failures and does not replace the old destination.
    full=f'{BASE}/disk-full';sec.mkdir(B,full)
    app.execute(B,'''import pathlib,os,sys
p=pathlib.Path(sys.argv[1]);(p/'big.bin').write_bytes(b'ORIGINAL')
v=os.statvfs('/work');remaining=v.f_bavail*v.f_frsize-1_500_000
with open('/work/app-tests/filler','wb') as f:
 while remaining>0:
  n=min(1048576,remaining);f.write(b'F'*n);remaining-=n
''',full)
    try:
        job=sec.server(full,quals=['merge']);r=sec.put(source);assert r['code']!=0,r;assert app.wait(job)['code']!=0
        assert app.execute(B,'import pathlib,sys;print(pathlib.Path(sys.argv[1],"big.bin").read_bytes().decode())',full)=='ORIGINAL'
    finally:app.execute(B,"import pathlib;pathlib.Path('/work/app-tests/filler').unlink(missing_ok=True)")
    app.record('disk-full preserves original file and reports failure')
    # Graceful cancellation tears down sockets and releases destination locks.
    cancel=f'{BASE}/cancel';sec.mkdir(B,cancel);job=sec.server(cancel,quals=['merge']);sec.proxy('slow');client=app.start(A,['force','put',f'{sec.IP}:40402',source]);wait_partial(cancel)
    result=app.stop(client);assert result['code']!=0;assert app.wait(job)['code']!=0
    job=sec.server(cancel,quals=['merge']);r=sec.put(source);measure=app.stats(r);assert app.wait(job)['code']==0;app.record('cancel and resume after destination lock release',stats=measure)


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
