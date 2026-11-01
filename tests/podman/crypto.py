#!/usr/bin/env python3
"""Stage-specific crypto faults against real peers, only in the labelled Podman lab."""
import json
from pathlib import Path
import application as app
import security
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'
P = app.PASSWORD
Q = 'another-unrelated-password'


def main():
    app.setup(app.BINARY)
    lab.podman('cp', str(Path(__file__).with_name('proxy.py')), B + ':/app/proxy.py')
    source = BASE + '/crypto-source'
    app.fixture(A, source, 12345)
    dest = BASE + '/crypto-dest'
    other = BASE + '/crypto-other'
    app.execute(B, '''import pathlib,sys
for path in sys.argv[1:]:
 p=pathlib.Path(path);p.mkdir();(p/'canary').write_bytes(b'KEEP')
''', dest, other)
    conf = BASE + '/crypto-server.ssync'
    app.execute(B, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)
''', conf, f'{P}={dest}\n{Q}={other}\n')
    client_conf = BASE + '/crypto-client.ssync'
    app.execute(A, '''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)
''', client_conf, f'@{security.IP}:40402\n{P}={source}\n')
    # KE1, KE2, KE3, Noise initiator/responder, encrypted ready initiator/responder.
    cases = [f'stage-{i}-{operation}' for i in range(7) for operation in ('flip', 'drop')]
    cases += [f'stage-{i}-zero' for i in range(3)]
    cases += ['stage-0-oversize', 'role']
    for backup in (False, True):
        selected = cases + (['stage-1-count0', 'stage-1-count33', 'stage-1-swap', 'stage-2-index'] if backup else [])
        for mode in selected:
            before = [app.snapshot(B, p) for p in (dest, other)]
            args = ['backup-server', '40401', conf] if backup else ['force', 'merge', 'get', '40401', dest]
            job = app.start(B, args)
            try:
                app.ready(job)
                security.proxy(mode)
                args = ['force', 'backup-client', client_conf] if backup else ['force', 'put', f'{security.IP}:40402', source]
                result = app.command(A, args, timeout=90)
                assert result['code'] != 0, (backup, mode, result)
                assert all(secret not in result['out'] + result['err'] for secret in (P, Q)), result
                if backup:
                    # A failed unauthenticated session must not terminate the listener.
                    assert app.logs(job)['code'] == '', app.logs(job)
                else:
                    assert app.wait(job)['code'] != 0, (mode, app.logs(job))
                assert [app.snapshot(B, p) for p in (dest, other)] == before, (backup, mode)
                app.record('crypto handshake fault rejected', backup=backup, mode=mode, bays_unchanged=True)
            finally:
                app.stop(job)
                app.wait(job)
    # Baselines prove the harness can establish both protocols after negative tests.
    for backup, mode in [(False, 'capture'), (True, 'capture'), (True, 'stage-1-unused')]:
        job = app.start(B, ['backup-server', '40401', conf] if backup else ['force', 'merge', 'get', '40401', dest])
        try:
            app.ready(job)
            security.proxy(mode)
            result = app.command(A, ['force', 'backup-client', client_conf] if backup else ['force', 'put', f'{security.IP}:40402', source])
            assert result['code'] == 0, result
            assert app.snapshot(B, other)['canary'][2] == __import__('hashlib').sha256(b'KEEP').hexdigest()
            app.record('crypto valid baseline after fault matrix', backup=backup, mode=mode)
        finally:
            app.stop(job)
            app.wait(job)
    out = app.ROOT / 'target/crypto-audit-handshakes.json'
    out.write_text(json.dumps(app.RESULTS, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    finally:
        app.cleanup()
