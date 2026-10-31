#!/usr/bin/env python3
"""Bootstrap download failures and native install, confined to disposable peer."""
import json
import application as app
from application import lab


def main():
    peer=lab.PEERS[1]
    lab.podman('cp',str(app.BINARY),peer+':/app/ssync')
    lab.podman('cp',str(app.ROOT/'install.sh'),peer+':/app/install.sh')
    app.execute(peer,'''import pathlib
p=pathlib.Path('/app/bootstrap-tools');p.mkdir(exist_ok=True)
p=pathlib.Path('/app/bootstrap-install');p.mkdir(exist_ok=True)
curl=pathlib.Path('/app/bootstrap-tools/curl')
curl.write_text('''+repr(r'''#!/usr/bin/env python3
import hashlib,os,pathlib,sys
args=sys.argv[1:];dest=pathlib.Path(args[args.index('-o')+1]);mode=os.environ['SSYNC_BOOTSTRAP_CASE']
if mode=='download-failure':sys.exit(22)
binary=pathlib.Path('/app/ssync').read_bytes()
if any(a.endswith('/checksums.txt') for a in args):
 value=hashlib.sha256(binary).hexdigest() if mode!='bad-checksum' else '0'*64
 data=(value+'  ssync_linux_amd64\n').encode()
 if mode=='duplicate':data*=2
 if mode=='missing':data=b'0'*64+b'  other-file\n'
else:data=binary
dest.write_bytes(data)
''')+''')
curl.chmod(0o755)
''')
    app.execute(peer,"import py_compile;py_compile.compile('/app/bootstrap-tools/curl',doraise=True)")
    env={'SSYNC_INSTALL_DIR':'/app/bootstrap-install'}
    install=app.command(peer,['install'],env=env);assert install['code']==0,install
    before=app.execute(peer,"import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/app/bootstrap-install/ssync').read_bytes()).hexdigest())")
    for mode in ['bad-checksum','duplicate','missing','download-failure','valid']:
        result=json.loads(app.execute(peer,'''import os,subprocess,json,sys
env=os.environ.copy();env.update({'PATH':'/app/bootstrap-tools:'+env['PATH'],'TMPDIR':'/app','SSYNC_INSTALL_DIR':'/app/bootstrap-install','SSYNC_BOOTSTRAP_CASE':sys.argv[1]})
r=subprocess.run(['bash','/app/install.sh'],env=env,capture_output=True,text=True,timeout=45)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''',mode,timeout=55))
        assert (result['code']==0)==(mode=='valid'),(mode,result)
        if mode!='valid':assert result['out']=='',(mode,result)
        if mode=='bad-checksum':assert 'checksum failed' in result['err'],result
        if mode in ('duplicate','missing'):assert 'checksum entry' in result['err'],result
        after=app.execute(peer,"import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('/app/bootstrap-install/ssync').read_bytes()).hexdigest())")
        assert before==after
        app.record('bootstrap artifact checks preserve installation',mode=mode)
    assert app.command(peer,['uninstall'],env=env)['code']==0


if __name__=='__main__':main()
