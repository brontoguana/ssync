#!/usr/bin/env python3
"""Regenerate embedded/distributed dependency notices using locked Cargo metadata."""
import json
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[1]
meta=json.loads(subprocess.check_output(['cargo','metadata','--locked','--format-version','1','--filter-platform','x86_64-unknown-linux-musl'],cwd=root))
nodes={node['id']:node for node in meta['resolve']['nodes']}
reachable=set();pending=[meta['resolve']['root']]
while pending:
 node=pending.pop()
 if node in reachable:continue
 reachable.add(node)
 pending.extend(dep['pkg'] for dep in nodes[node]['deps'] if any(kind['kind']!='dev' for kind in dep['dep_kinds']))
packages=[p for p in meta['packages'] if p['id'] in reachable]
parts=['SSync 4 — third-party dependency notices\n\nThe native executable uses public Rust dependencies. This file includes notices for the locked Linux runtime/build dependency graph, not the proprietary local Java reference imports.\n\n']
for package in sorted(packages,key=lambda p:(p['name'],p['version'])):
    if package['name']=='ssync':continue
    folder=Path(package['manifest_path']).parent
    names=set()
    for pattern in ['LICENSE*','COPYING*','NOTICE*','UNLICENSE*']:
        names.update(p for p in folder.glob(pattern) if p.is_file())
    if package.get('license_file'):
        p=Path(package['license_file']);p=p if p.is_absolute() else folder/p
        if p.is_file():names.add(p)
    parts.append(f"\n{'='*72}\n{package['name']} {package['version']}\nSPDX: {package.get('license') or 'See upstream license'}\nRepository: {package.get('repository') or 'https://crates.io/crates/'+package['name']}\n")
    if not names:raise RuntimeError('License file missing for '+package['name'])
    for p in sorted(names):parts.append('\n--- '+p.name+' ---\n'+p.read_text(errors='replace')+'\n')
(root/'THIRD_PARTY_NOTICES.txt').write_text(''.join(parts))
print('Wrote THIRD_PARTY_NOTICES.txt for',len(packages)-1,'public Rust packages.')
