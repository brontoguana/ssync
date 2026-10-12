#!/usr/bin/env python3
"""Recreates ONLY labelled synthetic peers in a bounded large-file profile."""
import hashlib
import time
import application as app
from application import lab


def main():
    lab.down();lab.up('large');app.setup(app.BINARY)
    a,b=lab.PEERS
    source='/work/app-tests/large-source';destination='/work/app-tests/large-destination'
    app.execute(a,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();f=(p/'sparse.bin').open('wb');f.truncate(2_400_000_017);f.close()
with (p/'sparse.bin').open('r+b') as f:
 f.seek(2_399_999_997);f.write(b'large-file-end')
''',source)
    app.execute(b,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',destination)
    server=app.start(b,['force','merge','get','40601',destination]);app.ready(server)
    ip=lab.owned('container',b)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    client=app.start(a,['force','put',f'{ip}:40601',source]);started=time.monotonic()
    result=app.wait(client,timeout=300);measure=app.stats(result);assert app.wait(server,timeout=300)['code']==0
    assert measure['content_bytes']==2_400_000_017,measure
    def digest(peer):return app.execute(peer,'''import pathlib,hashlib,sys
with pathlib.Path(sys.argv[1],'sparse.bin').open('rb') as f:print(hashlib.file_digest(f,'sha256').hexdigest())
''',source if peer==a else destination,timeout=60)
    assert digest(a)==digest(b);app.record('multi-GiB sparse source exact transfer',stats=measure,metrics=result['metrics'],elapsed_seconds=time.monotonic()-started,profile='6GiB tmpfs/7GiB memory per peer; 1CPU; no host mounts')
    # Same source/target includes an offset beyond signed-32-bit range.
    server=app.start(b,['force','merge','get','40601',destination]);app.ready(server);result=app.command(a,['force','put',f'{ip}:40601',source],timeout=120);measure=app.stats(result);assert measure['content_bytes']==0 and app.wait(server)['code']==0
    app.record('multi-GiB identical skip',stats=measure,metrics=result['metrics'])
    app.execute(a,'''import pathlib,sys
with pathlib.Path(sys.argv[1],'sparse.bin').open('r+b') as f:f.seek(2_200_000_001);f.write(b'X')
''',source)
    server=app.start(b,['force','merge','get','40601',destination]);app.ready(server);client=app.start(a,['force','put',f'{ip}:40601',source]);result=app.wait(client,timeout=300);measure=app.stats(result);assert app.wait(server,timeout=300)['code']==0
    assert measure['content_bytes']==200000 and digest(a)==digest(b),measure;app.record('multi-GiB one-block delta beyond 2GiB offset',stats=measure,metrics=result['metrics'])
    # Root-owned system installation into container-only tmpfs, using actual default directory.
    def root_command(action):return lab.podman('exec','--user','0',b,'/app/ssync',action)
    out=root_command('install');assert 'Installed SSync 4.0.0' in out,out
    attrs=lab.podman('exec','--user','0',b,'python3','-c',"import os,pathlib,json; p=pathlib.Path('/usr/local/bin/ssync');m=p.stat();assert m.st_uid==0 and m.st_mode&0o777==0o755;print(os.getxattr(p,'user.ssync.install').decode())")
    assert json_load(attrs)['version']=='4.0.0';assert 'already installed' in root_command('install')
    lab.podman('exec','--user','0',b,'python3','-c',"import pathlib;pathlib.Path('/usr/local/bin/unrelated').write_bytes(b'keep')")
    assert 'Uninstalled' in root_command('uninstall')
    lab.podman('exec','--user','0',b,'python3','-c',"import pathlib;assert not pathlib.Path('/usr/local/bin/ssync').exists();assert pathlib.Path('/usr/local/bin/unrelated').read_bytes()==b'keep'")
    app.record('default root-owned atomic install/uninstall with unrelated file preserved')


def json_load(s):import json;return json.loads(s)


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
