#!/usr/bin/env python3
"""Container-only fault proxy; uses synthetic traffic, bounded capture."""
import argparse
import json
import pathlib
import select
import socket
import time

p=argparse.ArgumentParser();p.add_argument('listen',type=int);p.add_argument('backend',type=int);p.add_argument('mode');p.add_argument('job');a=p.parse_args()
root=pathlib.Path(a.job)

def exact(s,n):
    b=bytearray()
    while len(b)<n:
        chunk=s.recv(n-len(b))
        if not chunk: raise EOFError()
        b.extend(chunk)
    return bytes(b)

def frame(s):
    header=exact(s,4);n=int.from_bytes(header,'big')
    if n>1_048_576:raise ValueError('oversize')
    return header+exact(s,n)

captures=[]
try:
    with socket.socket() as l:
        l.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);l.bind(('0.0.0.0',a.listen));l.listen(1)
        root.with_suffix('.ready').write_text('ready')
        c,_=l.accept()
        with c,socket.create_connection(('127.0.0.1',a.backend),timeout=20) as s:
            c.settimeout(20);s.settimeout(20)
            hello_c=exact(c,9);hello_s=exact(s,9)
            if a.mode=='role':hello_c=hello_c[:8]+bytes([hello_s[8]])
            s.sendall(hello_c);c.sendall(hello_s)
            # OPAQUE KE1 KE2 KE3, Noise handshake 1/2, ready connector/listener.
            for i in range(7):
                src,dst=(c,s) if i in (0,2,3,5) else (s,c)
                value=frame(src);captures.append(value.hex())
                if a.mode=='missing-final' and i==5:raise EOFError()
                if a.mode=='replay' and i==2:
                    saved=json.loads(pathlib.Path('/work/app-tests/captured-handshake.json').read_text());value=bytes.fromhex(saved[i])
                if a.mode=='tamper-handshake' and i==3:value=value[:-1]+bytes([value[-1]^1])
                dst.sendall(value)
            if a.mode=='capture':pathlib.Path('/work/app-tests/captured-handshake.json').write_text(json.dumps(captures))
            wire=bytearray(hello_c+hello_s)
            total=0
            while True:
                readable,_,_=select.select([c,s],[],[],20)
                if not readable:raise TimeoutError()
                for src in readable:
                    value=src.recv(60000)
                    if not value:raise EOFError()
                    dst=s if src is c else c
                    total+=len(value)
                    if len(wire)<4_000_000:wire.extend(value[:4_000_000-len(wire)])
                    if a.mode=='tamper' and src is c:
                        value=value[:-1]+bytes([value[-1]^1]);a.mode='forward'
                    elif a.mode=='duplicate' and src is c:
                        dst.sendall(value);a.mode='forward'
                    elif a.mode=='truncate' and src is c:
                        dst.sendall(value[:max(1,len(value)//2)]);raise EOFError()
                    elif a.mode in ('interrupt','slow','long') and src is c:
                        time.sleep(len(value)/20_000 if a.mode=='long' else .03)
                        if a.mode=='interrupt' and total>1_000_000:raise EOFError()
                    dst.sendall(value)
except (EOFError,OSError,ValueError,TimeoutError) as e:
    root.with_suffix('.result').write_text(type(e).__name__)
finally:
    root.with_suffix('.handshake').write_text(json.dumps(captures))
    if 'wire' in locals():root.with_suffix('.wire').write_bytes(wire)
