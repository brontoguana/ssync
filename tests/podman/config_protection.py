#!/usr/bin/env python3
"""Protected config writes/deletion, old peers, dry runs and backup mirroring."""
import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'
OLD = app.ROOT / 'target/release-412-previous/ssync_linux_amd64'


def install(peer, binary):
    lab.podman('cp', str(binary), peer+':/app/ssync')
    app.execute(peer, "import pathlib;pathlib.Path('/app/ssync').chmod(0o755)")


def main():
    app.setup(app.BINARY)
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    source = BASE+'/source'
    app.execute(A, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();(p/'nested').mkdir()
for name in ['normal', 'upload.ssync', '.ssync', 'nested/Mixed.SSYNC']:
 (p/name).write_text('NEW')
(p/'directory.ssync').mkdir();(p/'directory.ssync/child').write_text('NEW')
''', source)
    for number, mode in enumerate(['current', 'old-sender', 'old-receiver', 'dryrun']):
        for peer in (A, B):
            install(peer, OLD if (mode == 'old-sender' and peer == A) or (mode == 'old-receiver' and peer == B) else app.BINARY)
        dest = BASE+'/dest'+str(number)
        app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();(p/'nested').mkdir();(p/'orphan').mkdir()
for name in ['upload.ssync', 'nested/Mixed.SSYNC', 'orphan/keep.ssync', 'directory.ssync', 'stale']:
 (p/name).write_text('KEEP')
''', dest)
        job = app.start(B, ['force', 'merge', *(['dryrun'] if mode == 'dryrun' else []), 'get', '40922', dest]); app.ready(job)
        result = app.command(A, ['force', *(['nodelete'] if mode == 'old-receiver' else []), 'put', ip+':40922', source]); server = app.wait(job)
        app.stats(result); app.stats(server)
        app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1])
for name in ['upload.ssync','nested/Mixed.SSYNC','orphan/keep.ssync','directory.ssync']:
 assert (p/name).read_text()=='KEEP', name
assert not (p/'.ssync').exists()
assert (p/'normal').exists() == (sys.argv[2]!='dryrun')
assert (p/'stale').exists() == (sys.argv[2] in ['dryrun', 'old-receiver'])
''', dest, mode)
        assert 'skipping protected .ssync path' in result['err']+server['err'], (result, server)
        app.record('protected configurations; ordinary transfer completes', mode=mode)
    # Explicitly selected config is skipped successfully even with an old receiver.
    install(A, app.BINARY); install(B, OLD)
    job = app.start(B, ['force', 'get', '40922', BASE+'/dest0']); app.ready(job)
    result = app.command(A, ['force', 'put', ip+':40922', source+'/upload.ssync'])
    app.stats(result); app.stats(app.wait(job))
    assert 'skipping protected' in result['err'], result
    app.record('explicit config selection skips without failing')
    # The backup engine uses the same protections and continues ordinary files.
    install(B, app.BINARY)
    client, server = BASE+'/client.ssync', BASE+'/server.ssync'
    for peer, path, text in [(A, client, '@'+ip+':40922\n'+app.PASSWORD+'='+source+'\n'),
                              (B, server, app.PASSWORD+'='+BASE+'/dest0\n')]:
        app.execute(peer, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)', path, text)
    job = app.start(B, ['backup-server', '40922', server]); app.ready(job)
    try:
        result = app.command(A, ['backup-client', client]); app.stats(result)
        assert 'skipping protected' in result['err'], result
        app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/'upload.ssync').read_text()=='KEEP';assert (p/'normal').read_text()=='NEW'", BASE+'/dest0')
        app.record('backup skips configs and continues')
    finally:
        app.stop(job); app.wait(job)


if __name__ == '__main__':
    try:
        main()
    finally:
        app.cleanup()
