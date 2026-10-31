#!/usr/bin/env python3
"""Disposable native installation/update tests; fixture serves loopback only."""
import hashlib
import json
from pathlib import Path
import sys


def serve():
    from http.server import BaseHTTPRequestHandler,HTTPServer
    root=Path('/work/app-tests/management-http');root.mkdir(exist_ok=True)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            mode=(root/'mode').read_text()
            binary=(root/'future-ssync').read_bytes()
            versions=json.loads((root/'versions.json').read_text())
            tag='v'+versions['current' if mode=='current' else 'future']
            base='http://127.0.0.1:40501'
            if self.path=='/latest':
                data=json.dumps({'tag_name':tag,'name':'SSync test '+tag,'body':'Isolated fixture release, never public','html_url':base+'/release','draft':False,'prerelease':False,'assets':[{'name':'ssync_linux_amd64','browser_download_url':base+'/binary','size':len(binary)},{'name':'checksums.txt','browser_download_url':base+'/checksums','size':100}]}).encode()
                if mode=='malformed':data=b'{broken'
            elif self.path=='/checksums':
                h=hashlib.sha256(binary).hexdigest() if mode!='bad-checksum' else '0'*64
                data=(h+'  ssync_linux_amd64\n').encode()
                if mode=='duplicate':data*=2
            elif self.path=='/binary':
                if mode=='download-failure':self.send_error(503);return
                data=binary
            else:self.send_error(404);return
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    server=HTTPServer(('127.0.0.1',40501),Handler)
    (root/'ready').write_text('ready')
    server.serve_forever()


def main():
    import application as app
    from application import lab
    peer=lab.PEERS[1];lab.status()
    future=app.ROOT/'target/update-fixture-build/x86_64-unknown-linux-musl/release/ssync'
    assert future.exists(),'build a private newer-version update fixture first'
    lab.podman('cp',str(future),peer+':/app/ssync-future')
    lab.podman('cp',str(Path(__file__)),peer+':/app/management.py')
    current=app.command(peer,['version'])['out'].strip().split()[-1].removeprefix('v')
    future_version=app.execute(peer,"import subprocess;print(subprocess.check_output(['/app/ssync-future','version'],text=True).strip().split()[-1].removeprefix('v'))")
    assert tuple(map(int,future_version.split('.')))>tuple(map(int,current.split('.'))), 'fixture must be newer than current binary'
    app.execute(peer,'''import pathlib,subprocess,os,signal,shutil
p=pathlib.Path('/work/app-tests/management-http');p.mkdir(exist_ok=True);(p/'mode').write_text('current')
(p/'versions.json').write_text(__import__('sys').argv[1])
# Retire only this runner's exact helper in the verified disposable namespace.
for proc in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  if proc.stat().st_uid==os.getuid() and (proc/'cmdline').read_bytes().split(bytes([0]))[-3:-1]==[b'/app/management.py',b'--serve']:
   os.kill(int(proc.name),signal.SIGTERM)
 except (OSError,ValueError):pass
(p/'ready').unlink(missing_ok=True)
# HTTP payloads belong on data tmpfs, preserving limited executable tmpfs capacity.
shutil.copyfile('/app/ssync-future',p/'future-ssync');pathlib.Path('/app/ssync-future').unlink()
child=subprocess.Popen(['python3','/app/management.py','--serve'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(p/'server.pid').write_text(str(child.pid))
p=pathlib.Path('/app/install-test')
if p.exists():shutil.rmtree(p)
p.mkdir(mode=0o700);(p/'unrelated').write_bytes(b'keep')
''',json.dumps({'current':current,'future':future_version}))
    import time
    for _ in range(50):
        if app.execute(peer,"import pathlib;print(pathlib.Path('/work/app-tests/management-http/ready').exists())")=='True':break
        time.sleep(.1)
    directory='/app/install-test';env={'SSYNC_INSTALL_DIR':directory,'SSYNC_TEST_UPDATE':'1','SSYNC_RELEASE_API_URL':'http://127.0.0.1:40501/latest'}
    def run(action):return app.command(peer,[action],env=env)
    def mode(value):app.execute(peer,"import pathlib,sys;pathlib.Path('/work/app-tests/management-http/mode').write_text(sys.argv[1])",value)
    def snapshot():return app.snapshot(peer,directory)
    result=run('install');assert result['code']==0,result
    assert snapshot()['ssync'][3]==0o755
    result=run('install');assert result['code']==0 and 'already installed' in result['out'],result
    before=snapshot();result=run('update');assert result['code']==0 and 'up to date' in result['out'],result;assert snapshot()==before
    app.record('native install and current-version update',details=result['out'])
    for value in ['bad-checksum','download-failure','duplicate','malformed']:
        mode(value);before=snapshot();result=run('update');assert result['code']!=0,(value,result);assert snapshot()==before,(value,snapshot(),before)
        app.record('failed update preserves executable',mode=value,error=result['err'])
    mode('valid');result=run('update');assert result['code']==0 and 'Installed SSync '+future_version in result['out'],result
    version=app.execute(peer,'''import subprocess
r=subprocess.run(['/app/install-test/ssync','version'],capture_output=True,text=True);assert r.returncode==0;print(r.stdout,end='')
''');assert version=='SSync v'+future_version,version
    app.record('valid verified native update',details=result['out'],installed_version=version)
    before=snapshot();result=run('update');assert result['code']==0 and 'up to date' in result['out'];assert snapshot()==before
    result=run('uninstall');assert result['code']==0,result;assert list(snapshot())==['unrelated'];assert snapshot()['unrelated'][2]==hashlib.sha256(b'keep').hexdigest()
    result=run('uninstall');assert result['code']==0 and 'not installed' in result['out']
    app.execute(peer,"import pathlib;pathlib.Path('/app/install-test/ssync').write_bytes(b'unrelated program')")
    before=snapshot();result=run('install');assert result['code']!=0 and snapshot()==before;result=run('uninstall');assert result['code']!=0 and snapshot()==before
    app.record('uninstall owns only SSync files; unrelated binary refused')
    app.execute(peer,"import pathlib;pathlib.Path('/app/install-test/ssync').unlink()")
    assert run('install')['code']==0
    app.execute(peer,"import pathlib; p=pathlib.Path('/app/install-test/ssync');p.write_bytes(p.read_bytes()+b'modified')")
    before=snapshot();result=run('uninstall');assert result['code']!=0 and snapshot()==before
    app.record('modified installation refuses destructive management')
    default=app.command(peer,['install']);assert default['code']!=0 and 'requires sudo' in default['err'];app.record('default system install requires privilege')
    app.execute(peer,'''import pathlib,os,signal,shutil
p=pathlib.Path('/work/app-tests/management-http/server.pid')
pid=int(p.read_text())
try:
 if pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(bytes([0]))[-3:-1]==[b'/app/management.py',b'--serve']:os.kill(pid,signal.SIGTERM)
except OSError:pass
shutil.rmtree('/app/install-test')
''')


if __name__=='__main__':
    if '--serve' in sys.argv:serve()
    else:main()
