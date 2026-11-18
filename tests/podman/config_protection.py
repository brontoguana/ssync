#!/usr/bin/env python3
"""Inert config copies, reserved state and configured credential exclusions."""
import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'
PORT = 40922


def transfer(source, dest, sender=(), receiver=(), sender_env=None, receiver_env=None, success=True):
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    job = app.start(B, ['force', *receiver, 'get', str(PORT), dest], env=receiver_env)
    app.ready(job)
    result = app.command(A, ['force', *sender, 'put', f'{ip}:{PORT}', source], env=sender_env)
    server = app.wait(job)
    if success:
        app.stats(result); app.stats(server)
    else:
        assert result['code'] != 0 and server['code'] != 0, (result, server)
    return result, server


def mkdir(peer, path):
    app.execute(peer, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()', path)


def main():
    app.setup(app.BINARY)
    source = BASE+'/source'
    app.execute(A, '''import pathlib,sys,os
p=pathlib.Path(sys.argv[1]);p.mkdir();(p/'nested').mkdir()
for name in ['normal', 'upload.ssync', '.ssync', 'nested/Mixed.SSYNC']:
 (p/name).write_text('NEW');(p/name).chmod(0o664)
(p/'directory.ssync').mkdir();(p/'directory.ssync/child').write_text('CHILD')
# Source data is read without configuration-file ownership/mode restrictions.
(p/'.ssync-state').mkdir(mode=0o777);(p/'.ssync-state/unrecognised').write_text('PRIVATE')
(p/'nested/.ssync-state').symlink_to('/work/app-tests/outside',target_is_directory=True)
''', source)
    for mode in ['current', 'dryrun']:
        dest = BASE+'/dest-'+mode
        app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();(p/'nested').mkdir();(p/'orphan').mkdir()
for name in ['upload.ssync', 'nested/Mixed.SSYNC', 'orphan/keep.ssync', 'directory.ssync', 'stale']:
 (p/name).write_text('KEEP')
''', dest)
        transfer(source, dest, receiver=['merge', *(['dryrun'] if mode == 'dryrun' else [])])
        app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);dry=sys.argv[2]=='dryrun'
for name in ['upload.ssync','nested/Mixed.SSYNC','orphan/keep.ssync','directory.ssync']:
 assert (p/name).read_text()=='KEEP', name
assert not (p/'.ssync').exists()
for name in ['upload.ssyncbak','.ssyncbak','nested/Mixed.SSYNCbak']:
 assert (p/name).exists()!=dry,name
 if not dry: assert (p/name).read_text()=='NEW' and (p/name).stat().st_mode&0o777==0o664
assert (p/'directory.ssyncbak/child').exists()!=dry
assert not (p/'nested/.ssync-state').exists()
assert (p/'normal').exists()!=dry and (p/'stale').exists()==dry
''', dest, mode)
        app.record('inert configuration copies, source state exclusion and destination config preservation', mode=mode)
    dest = BASE+'/dest-current'
    transfer(source, dest, receiver=['merge'])
    app.record('repeat inert copies compare unchanged contents')
    transfer(source+'/upload.ssync', dest, sender=['chmod:600'])
    app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/'upload.ssyncbak').stat().st_mode&0o777==0o600;assert (p/'upload.ssync').read_text()=='KEEP'", dest)
    app.record('explicit config selection projects root and applies chmod override')
    for selected in ['.ssync-state', 'nested/.ssync-state']:
        transfer(source+'/'+selected, dest)
        app.record('explicit source state selection is a successful no-op', path=selected)
    filtered = BASE+'/filtered';mkdir(B, filtered)
    transfer(source, filtered, sender=['skip:.ssync'], receiver=['merge'])
    app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/'normal').exists();assert not (p/'upload.ssyncbak').exists()", filtered)
    app.record('filters protect original config names before projection')
    transfer(source, filtered, sender=['skip:directory.ssync/child'], receiver=['merge'])
    app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/'directory.ssyncbak').is_dir();assert not (p/'directory.ssyncbak/child').exists()", filtered)
    app.record('filters match original descendant paths inside projected directories')
    # Detect collisions before any destination payload, including root selections.
    for suffix in ['file', 'directory', 'link']:
        conflict = BASE+'/collision-'+suffix;mkdir(A, conflict)
        app.execute(A, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);(p/'x.ssyncbak').write_text('literal')
if sys.argv[2]=='directory': (p/'x.ssync').mkdir()
elif sys.argv[2]=='link':
 (p/'x.ssync').symlink_to('normal');(p/'x.ssyncbak.ssynclink').write_text('collision')
else: (p/'x.ssync').write_text('config')
''', conflict, suffix)
        before = app.snapshot(B, dest)
        result, _ = transfer(conflict, dest, success=False)
        assert 'conflicts with another source path' in result['err'], result
        assert app.snapshot(B, dest)==before
        app.record('projected config name collision fails before copying', kind=suffix)
    # Only the configured password file can be identified reliably; never guess by filename.
    secret_source = BASE+'/secrets';mkdir(A, secret_source)
    app.execute(A, '''import pathlib,sys,os
p=pathlib.Path(sys.argv[1]);(p/'credential.any').write_text(sys.argv[2]);(p/'credential.any').chmod(0o600)
os.link(p/'credential.any',p/'alias');(p/'normal').write_text('OK')
''', secret_source, app.PASSWORD)
    secret_dest = BASE+'/secret-dest';mkdir(B, secret_dest)
    transfer(secret_source, secret_dest, receiver=['merge'], sender_env={'SSYNC_PASSWORD_FILE':secret_source+'/credential.any'})
    app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert sorted(x.name for x in p.iterdir() if x.name!='.ssync-state')==['normal']", secret_dest)
    app.record('configured password and hard-link aliases omitted even with higher-priority env password')
    transfer(secret_source+'/credential.any', secret_dest, sender_env={'SSYNC_PASSWORD_FILE':secret_source+'/credential.any'})
    app.record('explicit credential selection is a successful no-op')
    # Actual password-file input, without the higher-priority environment password.
    app.execute(A, "import pathlib,sys;(pathlib.Path(sys.argv[1])/'alias').unlink()", secret_source)
    transfer(secret_source, secret_dest, receiver=['merge'], sender_env={'SSYNC_PASSWORD':'','SSYNC_PASSWORD_FILE':secret_source+'/credential.any'})
    app.record('actual password-file authentication excludes credential source')
    # Destination protection must precede hard-link rejection and unchanged-file chmod.
    app.execute(B, '''import pathlib,os,sys
p=pathlib.Path(sys.argv[1]);(p/'credential.any').write_text('PRIVATE');(p/'credential.any').chmod(0o600)
os.link(p/'credential.any',p/'alias');(p/'stale').write_text('REMOVE')
''', secret_dest)
    app.execute(A, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/'alias').write_text('replacement');(p/'credential.any').write_text('replacement')", secret_source)
    transfer(secret_source, secret_dest, sender=['chmod:777'], receiver=['merge'], receiver_env={'SSYNC_PASSWORD_FILE':secret_dest+'/credential.any'})
    app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);a=p/'credential.any';b=p/'alias'
assert a.read_text()==b.read_text()=='PRIVATE'
assert a.stat().st_mode&0o777==0o600 and a.stat().st_ino==b.stat().st_ino
assert not (p/'stale').exists()
''', secret_dest)
    app.record('credential destinations and hard-link aliases are neither replaced nor chmodded')
    app.execute(A, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/'alias').unlink();(p/'credential.any').unlink()", secret_source)
    transfer(secret_source, secret_dest, receiver=['merge'], receiver_env={'SSYNC_PASSWORD_FILE':secret_dest+'/credential.any'})
    app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/'credential.any').read_text()=='PRIVATE';assert (p/'alias').read_text()=='PRIVATE'", secret_dest)
    app.record('mirror cleanup preserves configured credentials and their aliases')
    # Config projection and state/password exclusions use the same path through backups.
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    client, server = BASE+'/client.ssync', BASE+'/server.ssync'
    for peer, path, text in [(A, client, '@'+ip+':40922\n'+app.PASSWORD+'='+source+'\n'),
                              (B, server, app.PASSWORD+'='+dest+'\n')]:
        app.execute(peer, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)', path, text)
    app.execute(A, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/'password').write_text('PRIVATE');(p/'password').chmod(0o600)", source)
    job = app.start(B, ['backup-server', str(PORT), server]);app.ready(job)
    try:
        result = app.command(A, ['backup-client', client], env={'SSYNC_PASSWORD_FILE':source+'/password'});app.stats(result)
        app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/'upload.ssync').read_text()=='KEEP';assert (p/'upload.ssyncbak').read_text()=='NEW';assert not (p/'password').exists();assert not (p/'nested/.ssync-state').exists()", dest)
        app.record('backups project configs and exclude reserved state and configured password')
    finally:
        app.stop(job);app.wait(job)
    # Ignoring source state never weakens checks when that directory is used for receiving.
    invalid_dest = BASE+'/invalid-state';mkdir(B, invalid_dest)
    app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/'.ssync-state').write_text('not staging')", invalid_dest)
    transfer(secret_source, invalid_dest, receiver=['merge'], success=False)
    app.record('malformed receiving state still fails safely')


if __name__ == '__main__':
    try:
        main()
    finally:
        app.cleanup()
