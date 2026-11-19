#!/usr/bin/env python3
"""Detect deleted-but-open file leaks in persistent, disposable SSync peers."""
import hashlib
import json
from pathlib import Path
import time

import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests/handles'
PORT = 40571
RAW = app.ROOT / 'target/podman-handles/samples.jsonl'


def sample(peer, pid):
    value = json.loads(app.execute(peer, '''import json,os,pathlib,stat,sys
pid=int(sys.argv[1]);root=pathlib.Path('/proc')/str(pid)
rows=[];deleted={}
for f in (root/'fd').iterdir():
 try:
  target=os.readlink(f);m=f.stat()
 except FileNotFoundError:continue
 row={'fd':int(f.name),'target':target,'nlink':m.st_nlink,'bytes':m.st_size,'allocated_bytes':m.st_blocks*512,'regular':stat.S_ISREG(m.st_mode),'inode':[m.st_dev,m.st_ino]}
 rows.append(row)
 if m.st_nlink==0 and (stat.S_ISREG(m.st_mode) or stat.S_ISDIR(m.st_mode)):
  deleted[(m.st_dev,m.st_ino)]=row
v=os.statvfs('/work')
print(json.dumps({'pid':pid,'fds':sorted(rows,key=lambda r:r['fd']),'fd_count':len(rows),'threads':len(list((root/'task').iterdir())),'deleted':list(deleted.values()),'deleted_allocated_bytes':sum(r['allocated_bytes'] for r in deleted.values()),'deleted_maps':[l for l in (root/'maps').read_text().splitlines() if '(deleted)' in l],'free_bytes':v.f_bavail*v.f_frsize}))
''', pid))
    with RAW.open('a') as out:
        out.write(json.dumps({'peer': peer, **value})+'\n')
    return value


def pid_of(job):
    return int(app.execute(job[0], "import pathlib,sys;print(pathlib.Path(sys.argv[1]+'.pid').read_text())", job[1]))


def idle(job, baseline=None):
    pid = pid_of(job)
    end = time.monotonic()+10
    previous = None
    while time.monotonic() < end:
        s = sample(job[0], pid)
        good = not s['deleted'] and not s['deleted_maps']
        if baseline is not None:
            good &= (s['fd_count'], s['threads']) == (baseline['fd_count'], baseline['threads'])
        key = (s['fd_count'], s['threads'])
        if good and key == previous:
            assert app.logs(job)['code'] == '', app.logs(job)
            return s
        previous = key if good else None
        time.sleep(.1)
    raise AssertionError(('listener did not release resources', s, baseline))


def write_config(peer, path, text):
    app.execute(peer, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)", path, text)


def mutate(peer, root, iteration, size=2_000_000):
    # Atomic source replacement also catches stale source handles in an offer.
    app.execute(peer, '''import os,pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir(parents=True,exist_ok=True)
i=int(sys.argv[2]);size=int(sys.argv[3])
data=bytes([(i%251)+1])*size
(p/'new').write_bytes(data);os.replace(p/'new',p/'payload')
for n in range(12):(p/f'small-{n}').write_bytes(f'{i}:{n}'.encode())
''', root, iteration, size)


def verify(peer, root, iteration, size=2_000_000):
    app.execute(peer, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);i=int(sys.argv[2]);size=int(sys.argv[3])
assert (p/'payload').read_bytes()==bytes([(i%251)+1])*size
for n in range(12):assert (p/f'small-{n}').read_bytes()==f'{i}:{n}'.encode()
assert not (p/'stale').exists()
assert not list((p/'.ssync-state').glob('*'))
''', root, iteration, size)


def extras(peer, root):
    app.execute(peer, "import pathlib,sys;p=pathlib.Path(sys.argv[1])/'stale';p.mkdir();(p/'extra').write_bytes(b'x'*1000000)", root)


def positive_control():
    # Prove the scanner and filesystem measurements detect the reported symptom.
    pid = int(app.execute(B, '''import subprocess,sys
code="""import pathlib,time,os,sys
p=pathlib.Path(sys.argv[1]);f=p.open('w+b');f.write(b'x'*8000000);f.flush();p.unlink()
while not pathlib.Path(sys.argv[1]+'.close').exists():time.sleep(.02)
f.close();pathlib.Path(sys.argv[1]+'.closed').write_text('yes');time.sleep(30)
"""
p=subprocess.Popen(['python3','-c',code,sys.argv[1]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(p.pid)
''', BASE+'/positive'))
    try:
        end = time.monotonic()+5
        while True:
            held = sample(B, pid)
            if held['deleted_allocated_bytes'] >= 8_000_000:
                break
            assert time.monotonic() < end, held
            time.sleep(.05)
        app.execute(B, "import pathlib,sys;pathlib.Path(sys.argv[1]+'.close').touch()", BASE+'/positive')
        end = time.monotonic()+5
        while True:
            closed = sample(B, pid)
            if not closed['deleted']:
                break
            assert time.monotonic() < end, closed
            time.sleep(.05)
        # The completion marker consumes one filesystem block after close.
        assert closed['free_bytes']-held['free_bytes'] >= held['deleted_allocated_bytes']-4096, (held, closed)
        app.record('detector positive control', held_bytes=held['deleted_allocated_bytes'], reclaimed_bytes=closed['free_bytes']-held['free_bytes'])
    finally:
        app.execute(B, "import os,sys;os.kill(int(sys.argv[1]),9)", pid)


def proxy(mode, backend=PORT, peer=B):
    path = BASE+f'/proxy-{time.monotonic_ns()}'
    app.execute(peer, '''import subprocess,sys
subprocess.Popen(['python3','/app/proxy.py','40572',sys.argv[1],sys.argv[2],sys.argv[3]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
''', backend, mode, path)
    end = time.monotonic()+5
    while time.monotonic() < end:
        if app.execute(peer, "import pathlib,sys;print(pathlib.Path(sys.argv[1]).with_suffix('.ready').exists())", path) == 'True':
            return
        time.sleep(.05)
    raise AssertionError('proxy not ready')


def source_unlink(offer, src, dst, ip_a, baseline):
    """An external source replacement must not pin the old inode indefinitely."""
    mutate(A, src, 201, 12_000_000)
    proxy('slow', peer=A)
    client = app.start(B, ['force','merge','get',f'{ip_a}:40572',dst])
    paused = False
    try:
        end = time.monotonic()+15
        while True:
            s = sample(A, pid_of(offer))
            if any(f['target']==src+'/payload' and f['regular'] for f in s['fds']):
                break
            assert time.monotonic() < end, s
            time.sleep(.02)
        app.execute(B, "import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGSTOP)", pid_of(client))
        paused = True
        app.execute(A, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.unlink();p.write_bytes(b'new source')", src+'/payload')
        held = sample(A, pid_of(offer))
        assert held['deleted_allocated_bytes'] >= 12_000_000, held
    finally:
        if paused:
            app.execute(B, "import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGCONT)", pid_of(client))
    assert app.wait(client,timeout=60)['code'] != 0
    released = idle(offer, baseline)
    assert 'source changed' in app.logs(offer)['err'], app.logs(offer)
    app.record('externally unlinked source released after rejected transfer', transient_deleted_bytes=held['deleted_allocated_bytes'], idle_deleted_bytes=released['deleted_allocated_bytes'])
    # Verify the same still-running listener remains usable afterwards.
    # Restore the interrupted content so its named partial is resumed too.
    mutate(A,src,201,12_000_000)
    app.stats(app.command(B,['force','merge','get',f'{ip_a}:{PORT}',dst]))
    verify(B,dst,201,12_000_000)
    idle(offer,baseline)
    app.record('sender recovers without restart after source unlink')


def main():
    app.setup(app.BINARY)
    RAW.parent.mkdir(parents=True, exist_ok=True)
    RAW.write_text('')
    for peer in (A, B):
        app.execute(peer, "import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()", BASE)
    for peer in (A, B):
        lab.podman('cp', str(Path(__file__).with_name('proxy.py')), peer+':/app/proxy.py')
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    positive_control()
    app.record('binary identity', sha256=hashlib.sha256(app.BINARY.read_bytes()).hexdigest(), version=app.command(A,['version'])['out'].strip())
    src, dst = BASE+'/source', BASE+'/receive'
    app.execute(B, "import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()", dst)
    mutate(A, src, 0)
    listener = app.start(B, ['force','merge','accept',str(PORT),dst])
    app.ready(listener)
    baseline = idle(listener)
    free = []
    for i in range(40):
        mutate(A, src, i)
        extras(B, dst)
        result = app.command(A, ['force','put',f'{ip}:{PORT}',src])
        stats = app.stats(result)
        assert stats['deleted'] == 2, stats
        verify(B, dst, i)
        s = idle(listener, baseline)
        free.append(s['free_bytes'])
        if i%10 == 9:
            app.record('persistent receiver replacement/mirror batch', completed=i+1, idle_fds=s['fd_count'], idle_threads=s['threads'], deleted_open_bytes=s['deleted_allocated_bytes'])
    assert max(free)-min(free) <= 64*4096, free
    app.record('replacement disk usage stable', cycles=40, free_bytes_min=min(free), free_bytes_max=max(free))
    for i in range(10):
        assert app.stats(app.command(A,['force','put',f'{ip}:{PORT}',src]))['content_bytes'] == 0
        idle(listener, baseline)
    app.record('unchanged comparisons release handles', cycles=10)
    for i in range(10):
        r = app.command(A, ['force','put',f'{ip}:{PORT}',BASE+'/missing'])
        assert r['code'] != 0, r
        idle(listener, baseline)
    app.record('authenticated source failures release handles', cycles=10)
    # Real mid-file connection failures retain named partials, not open unlinked data.
    for i in range(3):
        mutate(A, src, 100+i, 6_000_000)
        proxy('interrupt')
        r = app.command(A, ['force','put',f'{ip}:40572',src])
        assert r['code'] != 0, r
        s = idle(listener, baseline)
        partial = json.loads(app.execute(B, '''import pathlib,json,sys
p=pathlib.Path(sys.argv[1]);print(json.dumps([{'bytes':f.stat().st_size,'links':f.stat().st_nlink} for f in (p/'.ssync-state').iterdir()]))
''', dst))
        assert partial and all(f['links']==1 for f in partial) and sum(f['bytes'] for f in partial)>0, partial
        r = app.command(A, ['force','put',f'{ip}:{PORT}',src])
        assert app.stats(r)['reused_bytes'] > 0, r
        verify(B, dst, 100+i, 6_000_000)
        idle(listener, baseline)
    app.record('interrupted receives and resume release handles', cycles=3)
    # Force the old target to be unlinked while its comparison descriptors are live.
    mutate(A, src, 200, 12_000_000)
    proxy('slow')
    client = app.start(A, ['force','put',f'{ip}:40572',src])
    paused = False
    try:
        end = time.monotonic()+15
        while True:
            s = sample(B, pid_of(listener))
            if any(f['target']==dst+'/payload' and f['regular'] for f in s['fds']):
                break
            assert time.monotonic() < end, s
            time.sleep(.02)
        app.execute(A, "import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGSTOP)", pid_of(client))
        paused = True
        app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.unlink();p.write_bytes(b'replacement canary')", dst+'/payload')
        held = sample(B, pid_of(listener))
        assert held['deleted_allocated_bytes'] >= 6_000_000, held
    finally:
        if paused:
            app.execute(A, "import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGCONT)", pid_of(client))
    assert app.wait(client,timeout=60)['code'] != 0
    released = idle(listener, baseline)
    assert 'destination changed' in app.logs(listener)['err'], app.logs(listener)
    app.execute(B, "import pathlib,sys;assert pathlib.Path(sys.argv[1]).read_bytes()==b'replacement canary'", dst+'/payload')
    app.record('externally unlinked target released after rejected transfer', transient_deleted_bytes=held['deleted_allocated_bytes'], idle_deleted_bytes=released['deleted_allocated_bytes'])
    # Complete the same file to clear its intentional named resume state.
    app.stats(app.command(A,['force','put',f'{ip}:{PORT}',src]))
    idle(listener, baseline)
    app.stop(listener)

    # Long-lived sending process, with a fresh receiving process per cycle.
    offer = app.start(A, ['force','offer',str(PORT),src])
    app.ready(offer)
    offer_base = idle(offer)
    ip_a = lab.owned('container', A)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    for i in range(20):
        mutate(A, src, i)
        extras(B, dst)
        app.stats(app.command(B,['force','merge','get',f'{ip_a}:{PORT}',dst]))
        verify(B,dst,i)
        s = idle(offer, offer_base)
    app.record('persistent sender replacement cycles', cycles=20, idle_fds=s['fd_count'], idle_threads=s['threads'], deleted_open_bytes=s['deleted_allocated_bytes'])
    source_unlink(offer,src,dst,ip_a,offer_base)
    app.stop(offer)

    server_conf, client_conf = BASE+'/server.ssync', BASE+'/client.ssync'
    write_config(B,server_conf,f'{app.PASSWORD}={dst}\n')
    write_config(A,client_conf,f'{app.PASSWORD}={src}\n@{ip}:{PORT}\n')
    backup = app.start(B,['backup-server',str(PORT),server_conf])
    app.ready(backup)
    backup_base = idle(backup)
    free = []
    for i in range(20):
        mutate(A,src,i)
        extras(B,dst)
        app.stats(app.command(A,['backup-client',client_conf]))
        verify(B,dst,i)
        s = idle(backup,backup_base)
        free.append(s['free_bytes'])
    assert max(free)-min(free) <= 64*4096, free
    app.record('persistent backup replacement/mirror cycles', cycles=20, idle_fds=s['fd_count'], idle_threads=s['threads'], deleted_open_bytes=s['deleted_allocated_bytes'], free_bytes_min=min(free), free_bytes_max=max(free))
    app.stop(backup)
    app.execute(B, "import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY'")


if __name__ == '__main__':
    try:
        main()
    finally:
        for job in app.STARTED:
            if app.logs(job)['code'] == '':
                app.stop(job)
