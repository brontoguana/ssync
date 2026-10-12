#!/usr/bin/env python3
"""Progressing encrypted transfer exceeding the 120s idle threshold, not total timeout."""
import time
import application as app
from application import lab
import security as sec


def main():
    lab.status()
    a,b=lab.PEERS
    lab.podman('cp',str(app.ROOT/'tests/podman/proxy.py'),b+':/app/proxy.py')
    source='/work/app-tests/long-source';destination='/work/app-tests/long-destination'
    app.execute(b,'import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);shutil.rmtree(p,ignore_errors=True);p.mkdir()',destination)
    app.fixture(a,source,2_400_000)
    server=sec.server(destination,quals=['merge']);sec.proxy('long')
    client=app.start(a,['force','put',f'{sec.IP}:40402',source]);started=time.monotonic()
    result=app.wait(client,timeout=240);measure=app.stats(result);assert app.wait(server)['code']==0
    elapsed=time.monotonic()-started
    assert elapsed>120 and measure['content_bytes']==2_400_009,(elapsed,measure)
    assert app.snapshot(a,source)['big.bin'][:3]==app.snapshot(b,destination)['big.bin'][:3]
    app.record('progressing transfer beyond 120s idle threshold',elapsed_seconds=elapsed,stats=measure,metrics=result['metrics'])


if __name__=='__main__':
    try:main()
    finally:app.cleanup()
