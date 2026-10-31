#!/usr/bin/env python3
"""Ordinary transfer interoperability with the previously published 4.0 binary."""
import argparse
from pathlib import Path
import application as app
from application import lab


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--previous',required=True,type=Path);args=parser.parse_args()
    app.setup(app.BINARY)
    a,b=lab.PEERS
    source='/work/app-tests/source'
    app.fixture(a,source,2_000_003)
    for old_peer in (a,b):
        for peer in (a,b):lab.podman('cp',str(args.previous if peer==old_peer else app.BINARY),peer+':/app/ssync')
        for server_sends in (False,True):
            dest=f'/work/app-tests/compat-{old_peer}-{server_sends}'
            app.execute(b,'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()',dest)
            measure,_,_=app.transfer(a,b,source,dest,server_sends=server_sends,port=40900)
            expected=app.snapshot(a,source);actual=app.snapshot(b,dest+'/source')
            assert {k:v[:3] for k,v in expected.items()}=={k:v[:3] for k,v in actual.items()}
            app.record('4.0/4.1 ordinary transfer interoperability',old_peer=old_peer,server_sends=server_sends,stats=measure)


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
