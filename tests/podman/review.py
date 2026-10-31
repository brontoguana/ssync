#!/usr/bin/env python3
"""Security-review regressions, using only the existing two rootless peers."""
import json
from pathlib import Path
import time
import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'


def as_user(peer, uid, script, *args):
    return lab.podman('exec', '--user', str(uid), '-i', peer, 'python3', '-',
                      *map(str, args), input=script)


def preflight_root(bay, rootdir, client=False):
    return json.loads(as_user(B, 0, r'''import pathlib,subprocess,json,sys,os
p=pathlib.Path(sys.argv[1]);p.mkdir(exist_ok=True,mode=0o700)
cfg=p/('client.ssync' if sys.argv[3]=='client' else 'server.ssync')
cfg.write_text(('@127.0.0.1:49999\n' if sys.argv[3]=='client' else '')+sys.argv[4]+'='+sys.argv[2]+'\n');cfg.chmod(0o600)
args=['backup-client',str(cfg)] if sys.argv[3]=='client' else ['backup-server','40912',str(cfg)]
proc=subprocess.Popen(['/app/ssync',*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:out,err=proc.communicate(timeout=4)
except subprocess.TimeoutExpired:
 proc.kill();out,err=proc.communicate()
print(json.dumps({'code':proc.returncode,'out':out,'err':err}))
''', rootdir, bay, 'client' if client else 'server', app.PASSWORD))


def main():
    lab.status()
    assert lab.owned('container', B)['Config']['Labels'].get('io.ssync.test-profile') == 'large', 'review.py requires the large profile with container-only /usr/local/bin tmpfs'
    unique = str(time.monotonic_ns())
    rootdir = '/tmp/ssync-review-root-' + unique
    foreign = '/work/ssync-review-foreign-' + unique
    as_user(B, 1001, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o755);p.chmod(0o777)
(p/'bay').mkdir(mode=0o755);(p/'bay/data').write_bytes(b'other user source')
''', foreign)
    # The root-run server used to accept a bay owned by an unrelated UID.
    result = preflight_root(foreign+'/bay', rootdir)
    assert result['code'] != 0 and 'untrusted directory owner' in result['err'], result
    assert 'now accepting' not in result['out'], result
    app.record('root-run backup rejects a different-user bay before listening', result=result)
    # An owned final bay is insufficient if another user owns its ancestor.
    as_user(B, 0, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir(mode=0o700)', foreign+'/owned-bay')
    as_user(B, 1001, 'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o755)', foreign)
    result = preflight_root(foreign+'/owned-bay', rootdir)
    assert result['code'] != 0 and 'untrusted directory owner' in result['err'], result
    app.record('root-run backup rejects a different-user ancestor of an owned bay', result=result)
    # This restriction must not prevent read-only backup of another user's source.
    result = preflight_root(foreign+'/bay', rootdir, client=True)
    assert result['code'] != 0 and 'cannot connect' in result['err'], result
    assert 'untrusted directory owner' not in result['err'], result
    app.record('root backup client still accepts other-user read-only sources')
    unsafe = BASE+'/unsafe-ancestor-'+unique
    app.execute(B, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();p.chmod(0o777);(p/'bay').mkdir(mode=0o700)
''', unsafe)
    cfg = BASE+'/review-server-'+unique+'.ssync'
    app.execute(B, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]+'='+sys.argv[3]+'\n');p.chmod(0o600)
''', cfg, app.PASSWORD, unsafe+'/bay')
    result = app.command(B, ['backup-server', '40912', cfg])
    assert result['code'] != 0 and 'without sticky protection' in result['err'], result
    app.record('owned bay rejects a writable nonsticky ancestor', result=result)
    # Config paths receive the same ancestor checks, even with a private file/parent.
    app.execute(B, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'config';p.mkdir(mode=0o700)
f=p/'list.ssync';f.write_text('# empty\n');f.chmod(0o600)
''', unsafe)
    result = app.command(B, [unsafe+'/config/list.ssync'])
    assert result['code'] != 0 and 'without sticky protection' in result['err'], result
    app.record('private config rejects an unsafe ancestor')
    # Trusted ancestors only need search permission, not directory-listing permission.
    search_parent = '/work/ssync-review-search-' + unique
    as_user(B, 0, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.mkdir();p.chmod(0o777)', search_parent)
    app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir(mode=0o700)', search_parent+'/bay')
    as_user(B, 0, 'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o711)', search_parent)
    app.execute(B, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]+'='+sys.argv[3]+'\n');p.chmod(0o600)
''', cfg, app.PASSWORD, search_parent+'/bay')
    search_job = app.start(B, ['backup-server', '40912', cfg]);app.ready(search_job);app.stop(search_job)
    app.record('trusted search-only ancestor does not require listing permission')
    # Explicitly selected source mounts are allowed; nested mount traversal is not.
    # /usr/local/bin is already a container-only tmpfs in the validated large profile.
    as_user(B, 0, "import pathlib;p=pathlib.Path('/usr/local/bin/review-source');p.write_bytes(b'explicit mount source');p.chmod(0o644)")
    mounted_destination = BASE+'/review-mounted-source-'+unique
    app.execute(A, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()', mounted_destination)
    # Podman copies image tools/symlinks into this tmpfs; select only our fixture.
    ignored = json.loads(app.execute(B, "import pathlib,json;print(json.dumps([p.name for p in pathlib.Path('/usr/local/bin').iterdir() if p.name!='review-source']))"))
    measure, _, _ = app.transfer(B, A, '/usr/local/bin', mounted_destination,
                                quals=tuple('skip:bin/'+name for name in ignored), port=40913)
    assert app.execute(A, 'import pathlib,sys;print((pathlib.Path(sys.argv[1])/"bin/review-source").read_text())', mounted_destination) == 'explicit mount source'
    as_user(B, 0, "import pathlib;pathlib.Path('/usr/local/bin/review-source').unlink()")
    app.record('explicit directory source mount is authorized independently of its parent', stats=measure)
    # DNS errors in continuous mode are retried and SIGTERM remains effective.
    job = app.start(A, ['force', 'offer', 'a'*256+'.invalid:40912', BASE+'/source'])
    time.sleep(3)
    result = app.logs(job)
    assert result['code'] == '' and 'Continuous connection failed; retrying' in result['err'], result
    assert app.stop(job, sig=15)['code'] != 0
    app.record('continuous connection retries resolver errors and cancels')
    # Reproduce/document the authenticated content-presence oracle inherent in deltas.
    bay = BASE+'/review-oracle-bay-'+unique
    app.execute(B, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();(p/'flag').write_bytes(b'secret-A')
f=pathlib.Path(sys.argv[2]);f.write_text(sys.argv[3]+'='+str(p)+'\n');f.chmod(0o600)
''', bay, cfg, app.PASSWORD)
    lab.podman('cp', str(app.ROOT/'target/x86_64-unknown-linux-musl/release/examples/adversary'), A+':/app/adversary')
    server = app.start(B, ['backup-server', '40912', cfg]);app.ready(server)
    before = app.snapshot(B, bay)
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    for guess, matched in [('secret-A', True), ('secret-B', False)]:
        result = json.loads(app.execute(A, r'''import subprocess,os,sys,json
r=subprocess.run(['/app/adversary','--backup',sys.argv[1],'probe','flag',sys.argv[2]],env={**os.environ,'SSYNC_PASSWORD':sys.argv[3]},capture_output=True,text=True,timeout=20)
print(json.dumps({'code':r.returncode,'out':r.stdout,'err':r.stderr}))
''', f'{ip}:40912', guess, app.PASSWORD))
        assert result['code'] == 0 and f'Content guess matches: {str(matched).lower()}' in result['out'], result
    assert before == app.snapshot(B, bay)
    assert app.execute(B, 'import pathlib,sys;print((pathlib.Path(sys.argv[1])/".ssync-state").exists())', bay) == 'False'
    app.stop(server)
    app.record('documented limitation: authorized delta peers can test guessed content without downloading it', writes=False)
    # A reserved user filename must fail, while recognizable private state stays excluded.
    source = BASE+'/review-reserved-'+unique
    client_config = BASE+'/review-client-'+unique+'.ssync'
    app.execute(A, r'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();(p/'.ssync-state').write_bytes(b'important user data')
(p/'kept').write_bytes(b'kept')
f=pathlib.Path(sys.argv[2]);f.write_text('@'+sys.argv[3]+'\n'+sys.argv[4]+'='+str(p)+'\n');f.chmod(0o600)
''', source, client_config, f'{ip}:40912', app.PASSWORD)
    server = app.start(B, ['backup-server', '40912', cfg]);app.ready(server)
    result = app.command(A, ['backup-client', client_config])
    assert result['code'] != 0 and 'reserved .ssync-state' in result['err'], result
    assert before == app.snapshot(B, bay)
    app.execute(A, '''import pathlib,sys
p=pathlib.Path(sys.argv[1])/'.ssync-state';p.unlink();p.mkdir(mode=0o700)
f=p/('a'*64);f.write_bytes(b'private partial');f.chmod(0o600)
''', source)
    result = app.command(A, ['backup-client', client_config])
    assert result['code'] == 0, result
    assert list(app.snapshot(B, bay)) == ['kept']
    app.stop(server)
    app.record('reserved user data fails without deletion; recognizable internal state remains excluded')


if __name__ == '__main__':
    try: main()
    finally: app.cleanup()
