#!/usr/bin/env python3
"""Shared directory defaults and independent local policies in isolated peers."""
import json
import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'


def ordinary(ip, source, dest, sender_strict=False, receiver_strict=False):
    receiver = ['sole-owned'] if receiver_strict else []
    sender = ['sole-owned'] if sender_strict else []
    job = app.start(B, ['force', 'merge', *receiver, 'get', '40920', dest])
    app.ready(job)
    result = app.command(A, ['force', *sender, 'put', ip+':40920', source])
    return result, app.wait(job)


def main():
    app.setup(app.BINARY)
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    source, dest = BASE+'/shared-source', BASE+'/shared-dest'
    for peer, path in [(A, source), (B, dest)]:
        app.execute(peer, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();p.chmod(0o777)
(p/'nested').mkdir();(p/'nested').chmod(0o775)
''', path)
    app.execute(A, "import pathlib,sys;(pathlib.Path(sys.argv[1])/'nested/file').write_bytes(b'shared data')", source)
    for sender, receiver in [(False, False), (True, False), (False, True)]:
        result, server = ordinary(ip, source, dest, sender, receiver)
        if sender or receiver:
            failure = result if sender else server
            assert result['code'] != 0 and server['code'] != 0, (result, server)
            assert 'writable by other users' in failure['err'], failure
            assert (source if sender else dest) in failure['err'], failure
        else:
            app.stats(result); app.stats(server)
            assert app.snapshot(A, source)['nested/file'][:3] == app.snapshot(B, dest)['nested/file'][:3]
        app.record('independent ordinary directory policy', sender_strict=sender, receiver_strict=receiver)
    # A peer's strict choice must not impose checks on the opposite peer.
    for sender, receiver in [(True, False), (False, True)]:
        for peer, path, strict in [(A, source, sender), (B, dest, receiver)]:
            app.execute(peer, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);mode=0o755 if sys.argv[2]=='True' else 0o777
p.chmod(mode);(p/'nested').chmod(mode)
''', path, strict)
        result, server = ordinary(ip, source, dest, sender, receiver)
        app.stats(result); app.stats(server)
        app.record('strict peer accepts shared opposite peer', sender_strict=sender, receiver_strict=receiver)
    # Root-only and nested-only permissions must both be enforced.
    for shared_part in ['', '/nested']:
        for peer, path in [(A, source), (B, dest)]:
            app.execute(peer, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.chmod(0o755);(p/'nested').chmod(0o755)
pathlib.Path(str(p)+sys.argv[2]).chmod(0o775)
''', path, shared_part)
        for sender, receiver in [(True, False), (False, True)]:
            result, server = ordinary(ip, source, dest, sender, receiver)
            failure = result if sender else server
            assert result['code'] != 0 and server['code'] != 0, (result, server)
            assert 'writable by other users' in failure['err'], failure
        app.record('strict root and nested permission checks', shared_part=shared_part)
    # Saved ordinary commands run from shared folders, with one warning.
    app.execute(A, 'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o775)', source)
    cfg = source+'/upload.ssync'
    command_text = 'force put '+ip+':40920 '+source+'/nested\n'
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)', cfg, command_text)
    job = app.start(B, ['force', 'get', '40920', dest]); app.ready(job)
    result = app.command(A, [cfg]); app.stats(result); app.stats(app.wait(job))
    assert result['err'].count('SSync warning:') == 1, result
    assert 'can replace the configuration' in result['err'], result
    app.record('shared ordinary config warns once and transfers successfully')
    result = app.command(A, ['sole-owned', cfg])
    assert result['code'] != 0 and 'writable by other users' in result['err'], result
    app.record('explicit strict config rejects shared parent')
    private_cfg = BASE+'/strict-transfer.ssync'
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)', private_cfg, command_text)
    job = app.start(B, ['force', 'get', '40920', dest]); app.ready(job)
    result = app.command(A, ['sole-owned', private_cfg]); server_result = app.wait(job)
    assert result['code'] != 0 and server_result['code'] != 0, (result, server_result)
    assert 'writable by other users' in result['err'], result
    app.record('strict config propagates policy to contained local transfers')
    app.execute(A, 'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o666)', cfg)
    result = app.command(A, [cfg])
    assert result['code'] != 0 and 'unsafe or oversized' in result['err'], result
    app.record('shared config directory retains file mode protection')
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.unlink();p.symlink_to(sys.argv[2])', cfg, private_cfg)
    result = app.command(A, [cfg])
    assert result['code'] != 0, result
    app.record('shared config directory rejects config symlink')
    app.execute(A, 'import pathlib,sys;pathlib.Path(sys.argv[1]).unlink()', cfg)
    client_cfg, server_cfg = BASE+'/client.ssync', BASE+'/server.ssync'
    for peer, path, text in [(A, client_cfg, '@'+ip+':40921\n'+app.PASSWORD+'='+source+'\n'),
                             (B, server_cfg, app.PASSWORD+'='+dest+'\n')]:
        app.execute(peer, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)', path, text)
    # Both roots and children are shared again.
    for peer, path in [(A, source), (B, dest)]:
        app.execute(peer, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.chmod(0o777);(p/'nested').chmod(0o777)", path)
    result = app.command(B, ['sole-owned', 'backup-server', '40921', server_cfg])
    assert result['code'] != 0 and 'writable by other users' in result['err'], result
    assert 'now accepting' not in result['out'], result
    app.record('strict backup bay fails preflight before listening')
    server = app.start(B, ['backup-server', '40921', server_cfg]); app.ready(server)
    result = app.command(A, ['backup-client', client_cfg]); app.stats(result)
    app.record('default backup accepts shared sources and bays')
    result = app.command(A, ['sole-owned', 'backup-client', client_cfg])
    assert result['code'] != 0 and 'writable by other users' in result['err'], result
    app.record('strict backup client rejects shared sources')
    app.stop(server)
    # The qualifier does not weaken private config requirements.
    app.execute(A, 'import pathlib,sys;pathlib.Path(sys.argv[1]).chmod(0o666)', client_cfg)
    result = app.command(A, ['backup-client', client_cfg])
    assert result['code'] != 0 and 'private' in result['err'], result
    app.record('default sharing retains private config checks')


if __name__ == '__main__':
    try:
        main()
    finally:
        app.cleanup()
