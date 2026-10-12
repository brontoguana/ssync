#!/usr/bin/env python3
"""Actual native SSync integration tests, exclusively inside labelled rootless peers."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lab', Path(__file__).with_name('lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
PASSWORD = '1234-5678-9ABC-DEFG-HJKL-MNPQ'
RESULTS = []
SEQ = 0
BINARY = ROOT / 'target/x86_64-unknown-linux-musl/release/ssync'


def execute(peer, code, *args, timeout=30):
    return lab.podman('exec', '-i', peer, 'python3', '-', *map(str, args), input=code, timeout=timeout)


def setup(binary):
    status = lab.status()
    for peer in lab.PEERS:
        lab.podman('cp', str(binary), peer + ':/app/ssync')
        execute(peer, '''import pathlib,os,shutil
p=pathlib.Path('/app/ssync'); p.chmod(0o755)
p=pathlib.Path('/work/app-tests')
if p.exists(): shutil.rmtree(p)
p.mkdir(mode=0o700)
(p/'outside').mkdir();(p/'outside/canary').write_bytes(b'CANARY')
''')
    return status


def command(peer, args, password=PASSWORD, env=None, timeout=60):
    vars = {'SSYNC_PASSWORD': password, **(env or {})}
    out = execute(peer, '''import json,os,subprocess,sys
args=json.loads(sys.argv[1]);env=os.environ.copy();env.update(json.loads(sys.argv[2]))
r=subprocess.run(['/app/ssync',*args],env=env,capture_output=True,text=True,timeout=int(sys.argv[3]))
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''', json.dumps(args), json.dumps(vars), timeout, timeout=timeout+5)
    return json.loads(out)


def start(peer, args, password=PASSWORD, env=None):
    global SEQ
    SEQ += 1
    job = f'/work/app-tests/job-{SEQ}'
    execute(peer, '''import json,os,pathlib,subprocess,sys
job=sys.argv[1];args=json.loads(sys.argv[2]);env=os.environ.copy();env.update(json.loads(sys.argv[3]))
worker="""import subprocess,json,sys,pathlib,os
j=sys.argv[1];args=json.loads(sys.argv[2]);env=json.loads(sys.argv[3])
with open(j+'.out','w') as out,open(j+'.err','w') as err:
 p=subprocess.Popen(['/app/ssync',*args],env=env,stdout=out,stderr=err)
 pathlib.Path(j+'.pid').write_text(str(p.pid))
 code=p.wait()
pathlib.Path(j+'.result').write_text(str(code))
"""
subprocess.Popen(['python3','-c',worker,job,json.dumps(args),json.dumps(env)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
''', job, json.dumps(args), json.dumps({'SSYNC_PASSWORD': password, **(env or {})}))
    return peer, job


def logs(job):
    peer, path = job
    return json.loads(execute(peer, '''import pathlib,json,sys
j=sys.argv[1]
def read(s):
 p=pathlib.Path(j+s);return p.read_text() if p.exists() else ''
print(json.dumps({'out':read('.out'),'err':read('.err'),'code':read('.result')}))
''', path))


def wait(job, timeout=60):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        result = logs(job)
        if result['code'] != '':
            result['code'] = int(result['code'])
            return result
        time.sleep(.1)
    raise AssertionError(f'job timeout {job}: {logs(job)}')


def ready(job):
    end = time.monotonic()+20
    while time.monotonic()<end:
        result = logs(job)
        if 'now accepting' in result['out']:
            return
        if result['code'] != '':
            raise AssertionError(result)
        time.sleep(.1)
    raise AssertionError(f'listener not ready: {logs(job)}')


def stop(job, sig=2):
    execute(job[0], '''import os,pathlib,sys
p=pathlib.Path(sys.argv[1]+'.pid')
if p.exists():
 try: os.kill(int(p.read_text()),int(sys.argv[2]))
 except ProcessLookupError: pass
''', job[1], sig)
    return wait(job, timeout=10)


def stats(result):
    assert result['code'] == 0, result
    lines = [line for line in result['out'].splitlines() if line.startswith('SSYNC_STATS ')]
    assert len(lines) == 1, result
    return json.loads(lines[0].split(' ', 1)[1])


def record(name, **data):
    row = {'test': name, 'passed': True, **data}
    RESULTS.append(row)
    print(json.dumps(row), flush=True)
    report = ROOT/'target/podman-application/results.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(RESULTS, indent=2)+'\n')


def fixture(peer, path, size=20_000_000):
    execute(peer, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir(parents=True,exist_ok=True,mode=0o700)
(p/'nested').mkdir(exist_ok=True);(p/'empty').mkdir(exist_ok=True)
(p/'zero').write_bytes(b'');(p/'nested/Unicode-é-你好;$(nothing)').write_bytes(b'safe data')
size=int(sys.argv[2]);pattern=bytes(range(256))*781
with (p/'big.bin').open('wb') as f:
 while size: data=pattern[:min(size,len(pattern))];f.write(data);size-=len(data)
''', path, size)


def snapshot(peer, path):
    return json.loads(execute(peer, '''import pathlib,sys,hashlib,json,os
p=pathlib.Path(sys.argv[1]);out={}
for f in sorted(p.rglob('*')):
 if '.ssync-state' in f.relative_to(p).parts: continue
 key=str(f.relative_to(p))
 if f.is_symlink(): out[key]=['link',os.readlink(f)]
 elif f.is_file(): out[key]=['file',f.stat().st_size,hashlib.sha256(f.read_bytes()).hexdigest(),f.stat().st_mode&0o777]
 elif f.is_dir(): out[key]=['dir']
print(json.dumps(out))
''', path))


def transfer(sender, receiver, source, destination, *, server_sends=False, continuous=False, quals=(), port=40301):
    server = sender if server_sends else receiver
    client = receiver if server_sends else sender
    server_action = ('offer' if continuous else 'put') if server_sends else ('accept' if continuous else 'get')
    client_action = 'get' if server_sends else 'put'
    root = source if server_sends else destination
    other = destination if server_sends else source
    job = start(server, ['force', *quals, server_action, str(port), root])
    ready(job)
    ip = lab.owned('container', server)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    result = command(client, ['force', *quals, client_action, f'{ip}:{port}', other])
    client_stats = stats(result)
    if continuous:
        stop(job)
        server_result = logs(job)
    else:
        server_result = wait(job)
        stats(server_result)
    return client_stats, result, server_result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,default=BINARY)
    args=parser.parse_args();status=setup(args.binary)
    a,b=lab.PEERS
    for peer in (a,b):
        version=command(peer,['version']);assert version['out']=='SSync v4.0.0\n' and version['code']==0, version
        pwd=command(peer,['pwd']);groups=pwd['out'].rstrip('\n').split('-');assert pwd['code']==0 and len(groups)==6 and all(len(g)==4 for g in groups) and pwd['err']=='',pwd
        short=command(peer,['force','put','40300','/nonexistent'],password='short');assert short['code']!=0 and '16 characters' in short['err'],short
    record('CLI generator/version/password minimum',binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),runtime='static Linux x86_64 musl')
    source='/work/app-tests/source'
    fixture(a,source)
    for server_sends,continuous in [(False,False),(True,False),(True,True),(False,True)]:
        dest=f'/work/app-tests/direction-{int(server_sends)}-{int(continuous)}';execute(b,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',dest)
        started=time.monotonic();measure,_,_=transfer(a,b,source,dest,server_sends=server_sends,continuous=continuous)
        actual=snapshot(b,dest+'/source');expected=snapshot(a,source)
        for key,v in expected.items(): assert actual[key][:3]==v[:3],(key,v,actual.get(key))
        assert measure['content_bytes']==20_000_009,measure
        record('transfer direction',server_sends=server_sends,continuous_listener=continuous,stats=measure,elapsed_seconds=time.monotonic()-started)
    dest='/work/app-tests/delta';execute(b,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',dest)
    measure,_,_=transfer(a,b,source,dest,quals=['merge']);record('delta baseline',stats=measure)
    measure,_,_=transfer(a,b,source,dest,quals=['merge']);assert measure['content_bytes']==0,measure;record('identical repeat',stats=measure)
    def edit(offsets,append=0,truncate=None):
        execute(a,'''import pathlib,json,sys
p=pathlib.Path(sys.argv[1])/'big.bin'
with p.open('r+b') as f:
 for off in json.loads(sys.argv[2]): f.seek(off);f.write(b'X')
 if int(sys.argv[3]): f.seek(0,2);f.write(b'A'*int(sys.argv[3]))
 if sys.argv[4]!='None': f.truncate(int(sys.argv[4]))
''',source,json.dumps(offsets),append,truncate)
    for name,offsets,append,shrink,budget in [('one block',[1_000_001],0,None,200000),('separated blocks',[4_000_001,8_000_001],0,None,400000),('append',[],12345,None,12345),('shrink',[],0,19_000_000,0)]:
        edit(offsets,append,shrink);measure,_,_=transfer(a,b,source,dest,quals=['merge']);assert measure['content_bytes']<=budget,(name,measure,budget)
        assert snapshot(a,source)['big.bin'][:3]==snapshot(b,dest)['big.bin'][:3]
        record(name,stats=measure,maximum_content_bytes=budget)
    execute(b,'''import os,pathlib,sys
p=pathlib.Path(sys.argv[1])/'big.bin';st=p.stat()
with p.open('r+b') as f:f.seek(6000001);f.write(b'Z')
os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns))
''',dest)
    measure,_,_=transfer(a,b,source,dest,quals=['merge']);assert measure['content_bytes']==200000,measure;record('same-size same-mtime corruption',stats=measure)
    for peer in (a,b): assert execute(peer,"import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY';print('OK')")=='OK'
    record('outside-root canaries unchanged')
    print('Application core tests passed; further security/lifecycle tests are separate gates.')


if __name__=='__main__': main()
