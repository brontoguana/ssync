#!/usr/bin/env python3
"""Source rwx modes, unchanged files, failure cleanup and legacy-peer refusal."""
import argparse
import json
from pathlib import Path
import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'


def modes(peer, path):
    return json.loads(app.execute(peer, '''import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);out={'':p.stat().st_mode&0o7777}
for f in p.rglob('*'):
 if '.ssync-state' not in f.relative_to(p).parts: out[str(f.relative_to(p))]=f.stat().st_mode&0o7777
print(json.dumps(out))
''', path))


def install(peer, binary):
    lab.podman('cp', str(binary), peer+':/app/ssync')
    app.execute(peer, "import pathlib;pathlib.Path('/app/ssync').chmod(0o755)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    app.setup(app.BINARY)
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    source = BASE+'/source'
    app.execute(A, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir()
for name,mode in [('page',0o644),('script',0o755),('private',0o600),('readonly',0o444),('zero',0o640)]:
 f=p/name;f.write_text('' if name=='zero' else name);f.chmod(mode)
for name,mode in [('nested',0o555),('empty',0o750),('shared',0o775)]:
 d=p/name;d.mkdir();(d/'page').write_text(name);(d/'page').chmod(0o640);d.chmod(mode)
p.chmod(0o755)
''', source)
    expected = modes(A, source)
    for sends in (False, True):
        dest = BASE+'/dest-'+str(sends)
        app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();p=p/'source';p.mkdir()
(p/'page').write_text('OLD');(p/'page').chmod(0o600)
(p/'script').write_text('script');(p/'script').chmod(0o600)
(p/'stale').write_text('DELETE')
''', dest)
        app.transfer(A, B, source, dest, server_sends=sends, quals=['verify'])
        assert modes(B, dest+'/source') == expected
        app.record('source modes, replacements, unchanged content, readonly/empty/shared directories', server_sends=sends)
        # Reusing a read-only destination directory must still permit updates.
        app.execute(A, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);d=p/'nested';d.chmod(0o755);(d/'page').write_text('changed');d.chmod(0o555)
''', source)
        app.transfer(A, B, source, dest)
        assert modes(B, dest+'/source') == modes(A, source)
        app.execute(B, 'import pathlib,sys;assert (pathlib.Path(sys.argv[1])/"source/nested/page").read_text()=="changed"', dest)
        app.record('repeat transfer into read-only destination directory', server_sends=sends)
    # Merge copies source-root mode; dryrun changes neither modes nor content.
    dest = BASE+'/merge'
    app.execute(B, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o700)', dest)
    app.transfer(A, B, source, dest, quals=['merge'])
    assert modes(B, dest) == modes(A, source)
    before = modes(B, dest), app.snapshot(B, dest)
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.chmod(0o750);(p/"page").chmod(0o600)', source)
    app.transfer(A, B, source, dest, quals=['merge', 'dryrun'])
    assert before == (modes(B, dest), app.snapshot(B, dest))
    app.record('merge root permissions and write-free dryrun')
    # Failure after completed files still restores directory modes.
    app.execute(A, 'import pathlib,sys;(pathlib.Path(sys.argv[1])/"z_conflict").write_text("NEW")', source)
    app.execute(B, '''import os,pathlib,sys
p=pathlib.Path(sys.argv[1]);os.link('/work/app-tests/outside/canary',p/'z_conflict')
''', dest)
    job = app.start(B, ['force','merge','get','40924',dest]); app.ready(job)
    result = app.command(A, ['force','put',ip+':40924',source]); remote = app.wait(job)
    assert result['code'] != 0 and remote['code'] != 0, (result, remote)
    assert 'regular file has 2 hard links' in remote['err'] and '"z_conflict"' in remote['err'], remote
    assert 'regular file has 2 hard links' in result['err'] and '"z_conflict"' in result['err'], result
    assert dest not in result['err'], result
    actual = modes(B, dest); expected = modes(A, source)
    for path, mode in expected.items():
        if path != 'z_conflict': assert actual[path] == mode, (path, actual, expected)
    app.execute(B, "import pathlib;assert pathlib.Path('/work/app-tests/outside/canary').read_bytes()==b'CANARY'")
    app.record('late failure preserves completed file modes and finalizes directories')
    app.execute(A, 'import pathlib,sys;(pathlib.Path(sys.argv[1])/"z_conflict").unlink()', source)
    # Unsafe mode requests never bypass local strict-directory policy.
    strict = BASE+'/strict'
    app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir(mode=0o700)', strict)
    job = app.start(B, ['force','sole-owned','merge','get','40924',strict]); app.ready(job)
    result = app.command(A, ['force','put',ip+':40924',source]); remote = app.wait(job)
    assert result['code'] != 0 and remote['code'] != 0 and 'sole-owned policy' in remote['err'], (result, remote)
    assert 'setting destination permissions' in result['err'] and 'sole-owned policy' in result['err'], result
    assert not (modes(B, strict).get('shared', 0) & 0o022)
    app.record('source modes cannot override local sole-owned policy')

    # Both peers identify a nested unreadable source, without sharing its absolute path.
    blocked = source + '/nested-unreadable'
    app.execute(A, """import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir()
f=p/'private-page';f.write_bytes(b'unreadable');f.chmod(0)
""", blocked)
    try:
        job = app.start(B, ['force','get','40924',strict]); app.ready(job)
        result = app.command(A, ['force','put',ip+':40924',blocked]); remote = app.wait(job)
        assert result['code'] != 0 and remote['code'] != 0, (result, remote)
        assert blocked+'/private-page' in result['err'] and 'Permission denied' in result['err'], result
        assert 'nested-unreadable/private-page' in remote['err'] and 'permission denied' in remote['err'], remote
        assert blocked not in remote['err'], remote
    finally:
        app.execute(A, 'import shutil,sys;shutil.rmtree(sys.argv[1])', blocked)
    app.record('unreadable source is named in both failure logs')

    # Receiver-only mirror entries stay local, with an actionable reason sent back.
    mirror = BASE+'/mirror-errors'
    mirror_source = BASE+'/mirror-source'
    app.execute(A, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()', mirror_source)
    app.execute(B, """import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir()
f=p/'receiver-only';f.write_text('extra');(p/'second-name').hardlink_to(f)
""", mirror)
    job = app.start(B, ['force','merge','get','40924',mirror]); app.ready(job)
    result = app.command(A, ['force','put',ip+':40924',mirror_source]); remote = app.wait(job)
    assert result['code'] != 0 and remote['code'] != 0, (result, remote)
    assert 'removing extra destination entries' in result['err'] and 'regular file has 2 hard links' in result['err'], result
    assert mirror+'/receiver-only' in remote['err'] and 'receiver-only' not in result['err'], (result, remote)
    app.record('mirror error names local entry and shares reason without sharing its name')
    # Regular-file special bits are not propagated.
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"script";p.chmod(0o6755)', source)
    special = BASE+'/special'
    app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()', special)
    app.transfer(A, B, source+'/script', special)
    assert modes(B, special)['script'] == 0o755
    app.record('setuid and setgid file bits excluded')
    # A readable file owned by another user needs no chmod when modes match.
    owned = BASE+'/other-owner'
    app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir();pathlib.Path(sys.argv[1]).chmod(0o777);pathlib.Path(sys.argv[2]).chmod(0o711)', owned, BASE)
    try:
        # UID 0 has no capabilities in this lab; permit this fixture creation
        # through ordinary directory access rather than adding privileges.
        lab.podman('exec', '--user', '0', B, 'python3', '-c',
                   'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"page";p.write_text("page");p.chmod(0o644)', owned)
    finally:
        app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o700);pathlib.Path(sys.argv[2]).chmod(0o700)', owned, BASE)
    app.execute(A, 'import pathlib,sys;(pathlib.Path(sys.argv[1])/"page").chmod(0o644)', source)
    app.transfer(A, B, source+'/page', owned)
    app.execute(B, 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"page";assert p.stat().st_uid==0 and p.stat().st_mode&0o777==0o644', owned)
    app.record('unchanged readable file owned by another user needs no chmod')
    app.execute(A, 'import pathlib,sys;(pathlib.Path(sys.argv[1])/"page").chmod(0o600)', source)
    job = app.start(B, ['force','get','40924',owned]); app.ready(job)
    result = app.command(A, ['force','put',ip+':40924',source+'/page']); remote = app.wait(job)
    assert result['code'] != 0 and remote['code'] != 0, (result, remote)
    assert '"page"' in result['err'] and 'setting destination permissions' in result['err'] and 'permission denied' in result['err'], result
    assert owned+'/page' in remote['err'] and 'applying file mode 0600' in remote['err'], remote
    assert modes(B, owned)['page'] == 0o644
    app.record('failed chmod names the file and desired mode without changing existing permissions')

    invalid_state = BASE+'/invalid-state'
    app.execute(B, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.mkdir();(p/".ssync-state").mkdir(mode=0o755)', invalid_state)
    job = app.start(B, ['force','get','40924',invalid_state]); app.ready(job)
    result = app.command(A, ['force','put',ip+':40924',source+'/page']); remote = app.wait(job)
    assert result['code'] != 0 and remote['code'] != 0, (result, remote)
    assert '"page"' in result['err'] and 'preparing private resume data' in result['err'] and 'unsafe ownership or permissions' in result['err'], result
    assert invalid_state+'/.ssync-state' in remote['err'] and 'mode 0755' in remote['err'], remote
    assert invalid_state not in result['err'], result
    app.record('unsafe resume directory distinguishes private-state permissions from file permissions')

    # Backup uses the same mode-aware transfer engine, including merge root.
    bay = BASE+'/bay'
    app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir(mode=0o700)', bay)
    client, server = BASE+'/client.ssync', BASE+'/server.ssync'
    for peer, path, text in [(A,client,'@'+ip+':40924\n'+app.PASSWORD+'='+source+'\n'),
                             (B,server,app.PASSWORD+'='+bay+'\n')]:
        app.execute(peer, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)',path,text)
    job = app.start(B, ['backup-server','40924',server]); app.ready(job)
    try:
        app.stats(app.command(A, ['backup-client',client]))
        expected = {p: m & 0o777 for p,m in modes(A, source).items()}
        assert modes(B, bay) == expected
        app.record('backup source file/directory/root permissions')
    finally:
        app.stop(job); app.wait(job)
    if args.previous:
        for old_peer in (A, B):
            for peer in (A, B): install(peer, args.previous if peer == old_peer else app.BINARY)
            olddest = BASE+'/legacy-'+old_peer
            app.execute(B, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir(mode=0o700)', olddest)
            for sends in (False, True):
                sender, receiver = (A, B) if sends else (B, A)
                job = app.start(sender, ['force', 'put' if sends else 'get', '40924', source if sends else olddest]); app.ready(job)
                ipserver = lab.owned('container', sender)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
                result = app.command(receiver, ['force', 'get' if sends else 'put', ipserver+':40924', olddest if sends else source]); remote = app.wait(job)
                assert result['code'] != 0 and remote['code'] != 0, (result, remote)
                assert modes(B, olddest) == {'':0o700}
                app.record('legacy peer refused before filesystem changes',old_peer=old_peer,server_sends=sends)


if __name__ == '__main__':
    try: main()
    finally: app.cleanup()
