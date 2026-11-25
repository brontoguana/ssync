#!/usr/bin/env python3
"""Exercise independently configured large transfers with the release executable."""

import application as app

A, B = app.lab.PEERS
BASE = '/work/app-tests'
SOURCE = f'{BASE}/oversized-source'
DESTINATION = f'{BASE}/oversized-destination'
PORT = '40900'


def upload(address, sender, receiver):
    job = app.start(B, [*receiver, 'merge', 'get', PORT, DESTINATION])
    app.ready(job)
    client = app.command(A, [*sender, 'force', 'put', address, SOURCE], timeout=120)
    return client, app.wait(job, timeout=120)


def main():
    app.setup(app.BINARY)
    ip = app.lab.owned('container', B)['NetworkSettings']['Networks'][app.lab.NETWORK]['IPAddress']
    address = f'{ip}:{PORT}'
    app.execute(A, '''import pathlib, sys
source = pathlib.Path(sys.argv[1])
source.mkdir(mode=0o700)
for index in range(10_001):
    (source / f'{index:05}').write_text(str(index))
''', SOURCE)
    app.execute(B, '''import pathlib, sys
destination = pathlib.Path(sys.argv[1])
destination.mkdir(mode=0o700)
(destination / 'stale').touch()
''', DESTINATION)

    client, server = upload(address, [], ['large-transfer'])
    assert client['code'] != 0 and 'too many entries' in client['err'], client
    assert server['code'] != 0, server
    assert list(app.snapshot(B, DESTINATION)) == ['stale']
    app.record('receiver opt-in alone leaves the sender directory limit in effect')

    client, server = upload(address, ['large-transfer'], [])
    assert client['code'] != 0, client
    assert server['code'] != 0 and 'manifest entry limit' in server['err'], server
    names = set(app.snapshot(B, DESTINATION))
    assert names == {'stale'} | {f'{index:05}' for index in range(9_999)}
    app.record('sender opt-in alone leaves the receiver limit and rejects before writing the excess entry')

    config = f'{BASE}/oversized.ssync'
    app.execute(A, '''import pathlib, sys
config = pathlib.Path(sys.argv[1])
config.write_text(f'large-transfer verify force put {sys.argv[2]} {sys.argv[3]}\\n')
config.chmod(0o600)
''', config, address, SOURCE)
    job = app.start(B, ['large-transfer', 'verify', 'merge', 'get', PORT, DESTINATION])
    app.ready(job)
    client = app.command(A, [config], timeout=120)
    server = app.wait(job, timeout=120)
    assert client['code'] == server['code'] == 0, (client, server)
    assert 'Directory Verification Hash' in client['out'], client
    assert 'Directory Verification Hash' in server['out'], server
    assert app.snapshot(A, SOURCE) == app.snapshot(B, DESTINATION)
    app.record('saved qualifier completes an oversized transfer, mirrors extras and verifies on both peers')

    server_config = f'{BASE}/oversized-server.ssync'
    client_config = f'{BASE}/oversized-client.ssync'
    app.execute(B, '''import pathlib, sys
config = pathlib.Path(sys.argv[1])
config.write_text(f'{sys.argv[2]}={sys.argv[3]}\\n')
config.chmod(0o600)
(pathlib.Path(sys.argv[3]) / 'backup-stale').touch()
''', server_config, app.PASSWORD, DESTINATION)
    app.execute(A, '''import pathlib, sys
config = pathlib.Path(sys.argv[1])
config.write_text(f'@{sys.argv[2]}\\n{sys.argv[3]}={sys.argv[4]}\\n')
config.chmod(0o600)
''', client_config, address, app.PASSWORD, SOURCE)
    job = app.start(B, ['large-transfer', 'backup-server', PORT, server_config])
    try:
        app.ready(job)
        client = app.command(A, ['large-transfer', 'verify', 'backup-client', client_config], timeout=120)
        assert client['code'] == 0, client
        assert app.snapshot(A, SOURCE) == app.snapshot(B, DESTINATION)
    finally:
        app.stop(job)
    app.record('backup client and server accept and mirror the same oversized tree')


if __name__ == '__main__':
    try:
        main()
    finally:
        app.cleanup()
