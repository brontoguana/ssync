#!/usr/bin/env python3
"""Build/check versioned static Linux release assets from committed native source."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--allow-dirty',action='store_true',help='development packaging only; never use for publication')
args=parser.parse_args()
status=subprocess.check_output(['git','status','--porcelain','--untracked-files=normal'],cwd=root,text=True)
if status and not args.allow_dirty:raise SystemExit('Commit reviewed source before building publishable release assets.')
version=tomllib.loads((root/'Cargo.toml').read_text())['package']['version']
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
subprocess.run(['cargo','build','--locked','--release','--target','x86_64-unknown-linux-musl','--bin','ssync'],cwd=root,check=True)
binary=root/'target/x86_64-unknown-linux-musl/release/ssync'
header=binary.read_bytes()[:64]
assert header[:6]==b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little')==62
# Verify readelf reports no dynamic interpreter: no glibc/language runtime installation.
elf=subprocess.check_output(['readelf','-l',str(binary)],text=True)
if 'INTERP' in elf:raise SystemExit('Release binary must be statically linked.')
dist=root/'dist';dist.mkdir(exist_ok=True)
raw=dist/'ssync_linux_amd64';shutil.copyfile(binary,raw);raw.chmod(0o755)
archive=dist/f'ssync_{version}_linux_amd64.tar.gz'
with tarfile.open(archive,'w:gz') as tar:
    tar.add(raw,arcname='ssync')
    for name in ['README.md','LICENSE','THIRD_PARTY_NOTICES.txt']:tar.add(root/name,arcname=name)
source=dist/f'ssync_{version}_source.tar.gz'
with source.open('wb') as f:subprocess.run(['git','archive','--format=tar.gz','HEAD'],cwd=root,stdout=f,check=True)
shutil.copyfile(root/'THIRD_PARTY_NOTICES.txt',dist/'THIRD_PARTY_NOTICES.txt')
assets=[raw,archive,source,dist/'THIRD_PARTY_NOTICES.txt']
def sha(p):return hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
manifest={'version':version,'source_commit':commit,'platform':'linux-amd64-musl','development_dirty':bool(status),'assets':{p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in assets}}
manifest_path=dist/'release-manifest.json';manifest_path.write_text(json.dumps(manifest,indent=2)+'\n');assets.append(manifest_path)
(dist/'checksums.txt').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in assets))
print(json.dumps(manifest,indent=2))
