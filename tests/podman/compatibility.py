#!/usr/bin/env python3
"""Mixed ordinary/backup versions refuse before changing transfer data."""
import argparse
from pathlib import Path
import application as app
from application import lab


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--previous',required=True,type=Path)
    parser.add_argument('--backup-previous',type=Path);args=parser.parse_args()
    app.setup(app.BINARY)
    a,b=lab.PEERS
    source='/work/app-tests/source'
    app.fixture(a,source,2_000_003)
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
                result=app.command(a,['backup-client',client]);assert result['code']!=0,result
                assert app.snapshot(b,bay)=={}
                assert app.snapshot(b,other)=={}
                app.record('backup legacy peer refused before data changes',old_peer=old_peer)
            finally:app.stop(job);app.wait(job)


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
