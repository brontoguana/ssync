#!/usr/bin/env python3
"""Additional containment, resource-bound, fixture, rotation and resume checks."""
import json
import time
import application as app
from application import lab
import security as sec
import lifecycle as life

A,B=lab.PEERS
BASE='/work/app-tests'


def main():
    lab.status()
    source=f'{BASE}/advanced-source';app.fixture(A,source,3_000_000)
    app.execute(A,'''import pathlib,sys,os
p=pathlib.Path(sys.argv[1]);(p/'-leading').write_bytes(b'leading');(p/'line\\ncontrol\\x1b').write_bytes(b'literal names')
(p/'program').write_bytes(b'#!/bin/sh\\ntouch /work/app-tests/outside/executed\\n');(p/'program').chmod(0o4755)
(p/'deep/a/b/c').mkdir(parents=True)
for i in range(1000):(p/'deep/a/b/c'/f'tiny-{i:04}').write_bytes(str(i).encode())
''',source)
    dest=f'{BASE}/advanced-destination';sec.mkdir(B,dest)
    job=sec.server(dest,quals=['merge']);r=sec.put(source);measure=app.stats(r);assert app.wait(job)['code']==0
    before=app.snapshot(A,source);after=app.snapshot(B,dest)
    for name,value in before.items():assert after[name][:3]==value[:3],(name,value,after.get(name))
    assert after['program'][3]==0o600 and '\x1b' not in r['out']
    app.execute(B,"import pathlib;assert not pathlib.Path('/work/app-tests/outside/executed').exists()")
    app.record('deep tree/1000 small files/control names/leading hyphen and nonexecutable program data',stats=measure)
    # Existing destination link types are rejected before any data write.
    for kind in ['symlink','hardlink']:
        d=f'{BASE}/destination-{kind}';sec.mkdir(B,d)
        app.execute(B,'''import pathlib,os,sys
p=pathlib.Path(sys.argv[1]);outside=pathlib.Path('/work/app-tests/outside/canary')
if sys.argv[2]=='symlink':os.symlink(outside,p/'big.bin')
else:os.link(outside,p/'big.bin')
''',d,kind)
        job=sec.server(d,quals=['merge']);r=sec.put(source);assert r['code']!=0 and app.wait(job)['code']!=0
        app.execute(B,"import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY'")
        app.record('destination link rejected',kind=kind)
    # Changing the credential on listener restart revokes old password only by operator action.
    new='different-credential-24chars'
    job=sec.server(dest,password=new);snapshot=app.snapshot(B,dest);r=sec.put(source);assert r['code']!=0 and app.wait(job)['code']!=0;sec.unchanged(snapshot,dest)
    job=sec.server(dest,password=new);r=sec.put(source,password=new);app.stats(r);assert app.wait(job)['code']==0;app.record('operator credential rotation and listener restart')
    # Receiver mount boundaries and unsupported virtual filesystems fail closed.
    r=app.command(B,['hash','/']);assert r['code']!=0,r
    r=app.command(B,['hash','/proc']);assert r['code']!=0 and 'unsupported' in r['err'],r
    app.record('mount boundary and virtual filesystem rejection')
    # A private partial cannot be changed into a symlink/hardlink through an authenticated peer.
    # State file quota and prospective byte quota are tested with container-local sparse files.
    quota=f'{BASE}/quota';sec.mkdir(B,quota)
    app.execute(B,'''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'.ssync-state';p.mkdir(mode=0o700)
for i in range(128):
 f=p/f'{i:064x}';f.write_bytes(b'');f.chmod(0o600)
''',quota)
    job=sec.server(quota,quals=['merge']);r=sec.put(source);assert r['code']!=0 and app.wait(job)['code']!=0;app.record('128-file private resume-state limit')
    bytequota=f'{BASE}/byte-quota';sec.mkdir(B,bytequota)
    app.execute(B,'''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'.ssync-state';p.mkdir(mode=0o700)
f=p/('f'*64);f.touch(mode=0o600)
with f.open('r+b') as out:out.truncate(16*1024*1024*1024)
''',bytequota)
    job=sec.server(bytequota,quals=['merge']);r=sec.put(source);assert r['code']!=0 and app.wait(job)['code']!=0;app.record('16GiB prospective private-state quota')
    # Frame role reflection is rejected before roots are touched.
    job=sec.server(dest);snapshot=app.snapshot(B,dest);sec.proxy('role');r=sec.put(source,port=40402);assert r['code']!=0 and app.wait(job)['code']!=0;sec.unchanged(snapshot,dest);app.record('role reflection rejects unauthenticated session')
    # Source insertion correctness; fixed blocks may retransmit nearly all shifted content.
    shifted=f'{BASE}/shift-source';app.fixture(A,shifted,2_000_000)
    target=f'{BASE}/shift-target';sec.mkdir(B,target)
    job=sec.server(target,quals=['merge']);app.stats(sec.put(shifted));assert app.wait(job)['code']==0
    app.execute(A,'''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'big.bin';data=p.read_bytes();p.write_bytes(data[:100_000]+b'X'+data[100_000:])
''',shifted)
    job=sec.server(target,quals=['merge']);measure=app.stats(sec.put(shifted));assert app.wait(job)['code']==0
    assert app.snapshot(A,shifted)['big.bin'][:3]==app.snapshot(B,target)['big.bin'][:3];assert measure['content_bytes']<=2_000_001;app.record('fixed-block insertion reconstruction',stats=measure)
    # Abrupt process kill preserves original and retained bytes are revalidated, not trusted.
    kill_source=f'{BASE}/kill-source';app.fixture(A,kill_source,3_000_000)
    kill_dest=f'{BASE}/kill-dest';sec.mkdir(B,kill_dest)
    app.execute(B,'import pathlib,sys;pathlib.Path(sys.argv[1],"big.bin").write_bytes(b"ORIGINAL")',kill_dest)
    job=sec.server(kill_dest,quals=['merge']);sec.proxy('slow');client=app.start(A,['force','put',f'{sec.IP}:40402',kill_source]);life.wait_partial(kill_dest)
    r=app.stop(client,sig=9);assert r['code']==-9 and app.wait(job)['code']!=0
    app.execute(B,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);assert (p/'big.bin').read_bytes()==b'ORIGINAL'
f=max((p/'.ssync-state').iterdir(),key=lambda f:f.stat().st_size)
with f.open('r+b') as out:out.seek(0);out.write(b'CORRUPT')
''',kill_dest)
    job=sec.server(kill_dest,quals=['merge']);measure=app.stats(sec.put(kill_source));assert app.wait(job)['code']==0
    assert app.snapshot(A,kill_source)['big.bin'][:3]==app.snapshot(B,kill_dest)['big.bin'][:3];app.record('SIGKILL and tampered partial verification',stats=measure)
    # CLI invalid UTF-8 never prints the inline password from an argument error.
    result=json.loads(app.execute(A,'''import subprocess,json,sys,os
r=subprocess.run([b'/app/ssync',b'force',b'put',sys.argv[1].encode()+b'@127.0.0.1:1',b'\\xff'],capture_output=True)
assert sys.argv[1].encode() not in r.stderr
print(json.dumps({'code':r.returncode,'err':r.stderr.decode()}))
''',app.PASSWORD));assert result['code']!=0 and 'UTF-8' in result['err'];app.record('invalid argument encoding redacts credentials')


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
