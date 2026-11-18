#!/usr/bin/env python3
"""Source link descriptions, collisions, chmod precedence and backup integration."""
import json
import application as app
from application import lab

A, B = lab.PEERS
BASE = '/work/app-tests'
PORT = 40925


def mkdir(peer, path):
    app.execute(peer, 'import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()', path)


def transfer(source, dest, sender=(), receiver=(), sends=False, success=True):
    server, client = (A, B) if sends else (B, A)
    server_args = sender if sends else receiver
    client_args = receiver if sends else sender
    job = app.start(server, ['force', *server_args, 'put' if sends else 'get', str(PORT), source if sends else dest])
    app.ready(job)
    ip = lab.owned('container', server)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    result = app.command(client, ['force', *client_args, 'get' if sends else 'put', f'{ip}:{PORT}', dest if sends else source])
    remote = app.wait(job)
    if success:
        app.stats(result); app.stats(remote)
    else:
        assert result['code'] != 0 and remote['code'] != 0, (result, remote)
    return result, remote


def main():
    app.setup(app.BINARY)
    source = BASE+'/source'
    app.execute(A, '''import pathlib,os,sys
p=pathlib.Path(sys.argv[1]);p.mkdir();p.chmod(0o750)
(p/'folder').mkdir();(p/'folder').chmod(0o755)
(p/'folder/page').write_text('page');(p/'folder/page').chmod(0o640)
(p/'hard-a').write_text('hard data');(p/'hard-a').chmod(0o644)
os.link(p/'hard-a',p/'hard-b')
os.link('/work/app-tests/outside/canary',p/'external-hard')
for name,target in [('relative','folder/page'),('absolute','/work/app-tests/outside/canary'),('broken','../missing'),('loop','loop'),('directory','folder'),('-flag',"../x ' ;$(touch INJECTED)\\nline")]: os.symlink(target,p/name)
os.symlink(b'bad-\\xff',os.fsencode(p/'raw-target'))
os.symlink('folder/page',p/'protected.SSYNC')
''', source)
    for sends in (False, True):
        dest = BASE+'/dest-'+str(sends); mkdir(B, dest)
        transfer(source, dest, sender=['verify'], sends=sends)
        app.execute(B, '''import pathlib,os,sys,json,subprocess
p=pathlib.Path(sys.argv[1])/'source'
for name,target in [('relative','folder/page'),('absolute','/work/app-tests/outside/canary'),('broken','../missing'),('loop','loop'),('directory','folder'),('-flag',"../x ' ;$(touch INJECTED)\\nline")]:
 f=p/(name+'.ssynclink');text=f.read_text();assert text.startswith('type: softlink\\n')
 assert json.loads(text.splitlines()[1][6:])==target
 assert not (p/name).exists() and not (p/name).is_symlink()
 assert f.stat().st_mode&0o777==0o600
 start=text.index('  ln -s -- ')
 command=text[start:text.index('\\n\\nSSync',start)].strip()
 subprocess.run(command,shell=True,check=True,cwd=p)
 assert os.readlink(p/name)==target
 (p/name).unlink()
for name,other in [('hard-a','hard-b'),('hard-b','hard-a')]:
 f=p/name;assert f.read_text()=='hard data' and f.stat().st_nlink==1
 text=(p/(name+'.ssynclink')).read_text()
 assert text.startswith('type: hardlink\\n')
 assert json.loads(text.splitlines()[1][6:])=='source/'+other
assert (p/'external-hard').read_bytes()==b'CANARY'
assert 'path: null' in (p/'external-hard.ssynclink').read_text()
assert 'path_hex: 6261642dff' in (p/'raw-target.ssynclink').read_text()
text=(p/'raw-target.ssynclink').read_text()
command=next(line.strip() for line in text.splitlines() if line.startswith('  python3 '))
subprocess.run(command,shell=True,check=True,cwd=p)
assert os.readlink(os.fsencode(p/'raw-target'))==b'bad-\\xff'
(p/'raw-target').unlink()
assert not (p/'protected.SSYNC').exists()
assert (p/'protected.SSYNCbak.ssynclink').read_text().startswith('type: softlink')
assert not (p/'INJECTED').exists()
''', dest)
        app.record('symlink descriptions, safe restoration and independent hardlink contents', server_sends=sends)
        before = app.snapshot(B, dest)
        result, _ = transfer(source, dest, sends=sends)
        assert before == app.snapshot(B, dest)
        assert app.stats(result)['content_bytes'] == 0
        app.record('repeat descriptions and hardlinks use unchanged-content comparison', server_sends=sends)
    # Selected links must authorize the projected sidecar, including a hardlink's
    # extra root, without giving the peer arbitrary layout scope.
    for name in ['relative', 'hard-a']:
        dest = BASE+'/single-'+name; mkdir(B, dest)
        transfer(source+'/'+name, dest)
        app.execute(B, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/(sys.argv[2]+".ssynclink")).is_file()', dest, name)
        app.record('individually selected source link', kind=name)
    for quals in [['skip:relative'], ['skip:.ssynclink']]:
        dest = BASE+'/filter-'+str(len(app.RESULTS)); mkdir(B, dest)
        transfer(source, dest, receiver=quals)
        app.execute(B, 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"source";assert not (p/"relative.ssynclink").exists();assert (p/"folder/page").read_text()=="page"', dest)
        app.record('original or description filter suppresses symlink output', qualifiers=quals)
    dest = BASE+'/dry'; mkdir(B, dest)
    before = app.snapshot(B, dest)
    transfer(source, dest, receiver=['dryrun','--chmod','755'])
    assert before == app.snapshot(B, dest)
    app.record('link descriptions and chmod dry run writes nothing')
    collision = BASE+'/collision'; mkdir(A, collision)
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);(p/"x").symlink_to("missing");(p/"x.ssynclink").write_text("REAL DATA")', collision)
    result, remote = transfer(collision, dest, success=False)
    assert 'conflicts with another source path' in result['err']+remote['err']
    assert before == app.snapshot(B, dest)
    app.record('description collision rejected before destination changes')
    # Override both replaced and identical contents; preserve directory modes.
    for mode in ['600', '755', '000', '644']:
        result, _ = transfer(source, BASE+'/dest-False', sender=['chmod:'+mode])
        app.execute(B, '''import pathlib,sys,os
p=pathlib.Path(sys.argv[1])/'source';wanted=int(sys.argv[2],8)
assert p.stat().st_mode&0o777==0o750
assert (p/'folder').stat().st_mode&0o777==0o755
for f in p.rglob('*'):
 if f.is_file():assert f.stat().st_mode&0o777==wanted,(str(f),oct(f.stat().st_mode),wanted)
''', BASE+'/dest-False', mode)
        app.record('file override applied including descriptions, directories retain source modes', mode=mode)
    for sends in (False, True):
        transfer(source, BASE+'/dest-False', sender=['chmod:600'], receiver=['permissions:755'], sends=sends)
        app.execute(B, 'import pathlib;assert pathlib.Path("/work/app-tests/dest-False/source/folder/page").stat().st_mode&0o777==0o755')
        app.record('receiver override wins independently of connection direction', server_sends=sends)
    # A symlink that becomes a normal file drops its stale descriptor on mirror.
    app.execute(A, 'import pathlib,sys;p=pathlib.Path(sys.argv[1])/"relative";p.unlink();p.write_text("ordinary")', source)
    transfer(source, BASE+'/dest-False', receiver=['nodelete'])
    app.execute(B, 'import pathlib;p=pathlib.Path("/work/app-tests/dest-False/source");assert (p/"relative").read_text()=="ordinary";assert (p/"relative.ssynclink").is_file()')
    app.record('nodelete retains old description alongside ordinary replacement')
    transfer(source, BASE+'/dest-False')
    app.execute(B, 'import pathlib;p=pathlib.Path("/work/app-tests/dest-False/source");assert (p/"relative").read_text()=="ordinary";assert not (p/"relative.ssynclink").exists()')
    app.record('mirror removes stale description after source link becomes regular')
    # Backups reuse the link and override engine, including merge-root paths.
    bay=BASE+'/bay'; mkdir(B,bay)
    ip = lab.owned('container', B)['NetworkSettings']['Networks'][lab.NETWORK]['IPAddress']
    client, server = BASE+'/client.ssync', BASE+'/server.ssync'
    for peer,path,text in [(A,client,'@'+ip+':40925\n'+app.PASSWORD+'='+source+'\n'),(B,server,app.PASSWORD+'='+bay+'\n')]:
        app.execute(peer, 'import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.write_text(sys.argv[2]);p.chmod(0o600)',path,text)
    job=app.start(B,['chmod:644','backup-server',str(PORT),server]); app.ready(job)
    try:
        app.stats(app.command(A,['chmod:600','backup-client',client]))
        app.execute(B, '''import pathlib,json,sys
p=pathlib.Path(sys.argv[1]);assert p.stat().st_mode&0o777==0o750
assert (p/'absolute.ssynclink').is_file() and not (p/'absolute').exists()
assert (p/'folder/page').stat().st_mode&0o777==0o644
assert (p/'absolute.ssynclink').stat().st_mode&0o777==0o644
assert json.loads((p/'hard-a.ssynclink').read_text().splitlines()[1][6:])=='hard-b'
''',bay)
        app.record('backup links and receiver override with merge-relative hardlink instructions')
    finally:
        app.stop(job)
    for peer in (A,B):
        app.execute(peer, 'import pathlib;assert pathlib.Path("/work/app-tests/outside/canary").read_bytes()==b"CANARY"')
    app.record('original outside-link canaries unchanged')


if __name__ == '__main__':
    try: main()
    finally: app.cleanup()
