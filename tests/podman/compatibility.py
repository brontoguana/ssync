#!/usr/bin/env python3
"""Check whether a released peer can transfer with the candidate as expected."""
import argparse
import re
from pathlib import Path
import application as app
from application import lab


def check_ids(candidate, previous, shared):
    local_only = "ID appears in this peer's log only"
    if shared:
        pattern = r"Transfer ([A-Z2-9]{3}-[A-Z2-9]{3}-[A-Z2-9]{3}) authenticated"
        candidate_ids = re.findall(pattern, candidate['out'])
        previous_ids = re.findall(pattern, previous['out'])
        assert len(candidate_ids) == 1 and previous_ids == candidate_ids, (candidate, previous)
        assert local_only not in candidate['out'] and local_only not in previous['out']
    else:
        assert local_only in candidate['out'], candidate
        assert local_only not in previous['out'], previous


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--previous',required=True,type=Path)
    parser.add_argument('--backup-previous',type=Path)
    parser.add_argument('--compatible', action='store_true', help='expect successful transfers with 4.1.4 or later')
    parser.add_argument('--shared-diagnostics', action='store_true', help='expect shared IDs with 4.1.6 or later')
    args=parser.parse_args()
    if args.shared_diagnostics and not args.compatible:
        parser.error('--shared-diagnostics requires --compatible')
    app.setup(app.BINARY)
    a,b=lab.PEERS
    source='/work/app-tests/source'
    app.fixture(a,source,2_000_003)
    expected = app.snapshot(a,source)

    def check_contents(actual):
        assert actual.keys() == expected.keys(), (actual,expected)
        for name in expected:
            assert actual[name][:4] == expected[name][:4], (name,actual[name],expected[name])
    for old_peer in (a,b):
        for peer in (a,b):
            lab.podman('cp',str(args.previous if peer==old_peer else app.BINARY),peer+':/app/ssync')
            app.execute(peer,"import pathlib;pathlib.Path('/app/ssync').chmod(0o755)")
        for server_sends in (False,True):
            dest=f'/work/app-tests/compat-{old_peer}-{server_sends}'
            app.execute(b,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',dest)
            server,client=(a,b) if server_sends else (b,a)
            ip=lab.owned('container',server)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
            job=app.start(server,['force','put' if server_sends else 'get','40900',source if server_sends else dest]);app.ready(job)
            result=app.command(client,['force','get' if server_sends else 'put',ip+':40900',dest if server_sends else source])
            remote=app.wait(job)
            if args.compatible:
                assert result['code']==remote['code']==0,(result,remote)
                candidate, previous = (result, remote) if old_peer==server else (remote, result)
                check_ids(candidate, previous, args.shared_diagnostics)
                check_contents(app.snapshot(b,dest+'/source'))
                app.record('ordinary transfer succeeds with previous peer',old_peer=old_peer,server_sends=server_sends)
            else:
                assert result['code']!=0 and remote['code']!=0,(result,remote)
                assert app.snapshot(b,dest)=={}
                app.record('ordinary legacy peer refused before data changes',old_peer=old_peer,server_sends=server_sends)
    if args.backup_previous:
        ip=lab.owned('container',b)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
        for old_peer in (a,b):
            for peer in (a,b):
                lab.podman('cp',str(args.backup_previous if peer==old_peer else app.BINARY),peer+':/app/ssync')
                app.execute(peer,"import pathlib;pathlib.Path('/app/ssync').chmod(0o755)")
            bay=f'/work/app-tests/backup-compat-{old_peer}'
            other=bay+'-other';config=bay+'.ssync';client=bay+'-client.ssync'
            app.execute(b,'''import pathlib,sys
for name in sys.argv[1:3]:pathlib.Path(name).mkdir()
p=pathlib.Path(sys.argv[3]);p.write_text('unrelated-password='+sys.argv[2]+'\\n'+sys.argv[4]+'='+sys.argv[1]+'\\n');p.chmod(0o600)
''',bay,other,config,app.PASSWORD)
            app.execute(a,'''import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text('@'+sys.argv[2]+'\\n'+sys.argv[3]+'='+sys.argv[4]+'\\n');p.chmod(0o600)
''',client,f'{ip}:40900',app.PASSWORD,source)
            job=app.start(b,['backup-server','40900',config]);app.ready(job)
            try:
                result=app.command(a,['backup-client',client])
                assert app.snapshot(b,other)=={}
                if args.compatible:
                    assert result['code']==0,result
                    check_contents(app.snapshot(b,bay))
                    server = app.logs(job)
                    candidate, previous = (result, server) if old_peer==b else (server, result)
                    check_ids(candidate, previous, args.shared_diagnostics)
                    app.record('backup transfer succeeds with previous peer',old_peer=old_peer)
                else:
                    assert result['code']!=0,result
                    assert app.snapshot(b,bay)=={}
                    app.record('backup legacy peer refused before data changes',old_peer=old_peer)
            finally:app.stop(job);app.wait(job)


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
