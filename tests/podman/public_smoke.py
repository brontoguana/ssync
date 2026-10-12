#!/usr/bin/env python3
"""After publication, verify public install/native update in existing rootless large peer."""
import argparse
import json
import subprocess
from pathlib import Path
import application as app
from application import lab

NETWORK='ssync-public-smoke-net'
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--tag',required=True);args=parser.parse_args()
status=lab.status();peer=lab.PEERS[1]
if lab.owned('container',peer)['Config']['Labels'].get('io.ssync.test-profile')!='large':raise SystemExit('Use bounded large profile for disposable /usr/local/bin tmpfs.')
if lab.exists('network',NETWORK):raise SystemExit('Public smoke network already exists; inspect before removing.')
connected=False
try:
    lab.podman('network','create','--label',f'{lab.LABEL}={lab.VALUE}',NETWORK)
    lab.podman('network','connect',NETWORK,peer);connected=True
    code='''import hashlib,json,pathlib,sys,urllib.request
repo='https://api.github.com/repos/brontoguana/ssync/releases/tags/'+sys.argv[1]
def get(url,limit):
 with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'ssync-public-smoke'}),timeout=60) as r:data=r.read(limit+1)
 assert len(data)<=limit
 return data
release=json.loads(get(repo,262144));assert not release['draft'] and not release['prerelease']
assets={a['name']:a['browser_download_url'] for a in release['assets']}
sums=get(assets['checksums.txt'],65536).decode().splitlines()
line=[s for s in sums if s.split()[1]=='ssync_linux_amd64'];assert len(line)==1
binary=get(assets['ssync_linux_amd64'],64*1024*1024)
assert hashlib.sha256(binary).hexdigest()==line[0].split()[0]
p=pathlib.Path('/app/public-ssync');p.write_bytes(binary);p.chmod(0o755)
print(json.dumps({'tag':release['tag_name'],'sha256':hashlib.sha256(binary).hexdigest(),'bytes':len(binary)}))
'''
    artifact=json.loads(app.execute(peer,code,args.tag,timeout=150))
    expected='SSync v'+args.tag.removeprefix('v')
    assert lab.podman('exec',peer,'/app/public-ssync','version')==expected
    installed=lab.podman('exec','--user','0',peer,'/app/public-ssync','install')
    # No SSYNC_TEST_* overrides: this is the real public GitHub updater.
    updated=lab.podman('exec','--user','0',peer,'/usr/local/bin/ssync','update',timeout=90)
    assert 'Current:' in updated and 'available:' in updated and 'up to date' in updated
    removed=lab.podman('exec','--user','0',peer,'/usr/local/bin/ssync','uninstall')
    result={'artifact':artifact,'install':installed,'update':updated,'uninstall':removed,'rootless':True,'host_mounts':[]}
    out=app.ROOT/'target/public-smoke.json';out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
finally:
    if connected:lab.podman('network','disconnect',NETWORK,peer)
    if lab.exists('network',NETWORK):lab.owned('network',NETWORK);lab.podman('network','rm',NETWORK)
