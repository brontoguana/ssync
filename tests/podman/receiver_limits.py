"""Listener admission and disk-headroom regressions in labelled rootless peers."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import application as app

A, B = app.lab.PEERS
src = "/work/app-tests/listener-disk-source"
dest = "/tmp/listener-disk-dest-2"
filler = "/tmp/listener-disk-fill"

def make_headroom(blocks):
    return app.execute(B, r"""
import os,sys
path, requested_free = sys.argv[1], int(sys.argv[2])
with open(path, "wb") as stream:
    s = os.statvfs(path)
    assert s.f_bavail > requested_free
    os.posix_fallocate(stream.fileno(), 0, (s.f_bavail - requested_free) * s.f_frsize)
s = os.statvfs(path)
assert s.f_bavail == requested_free
print(s.f_bavail, s.f_blocks)
""", filler, blocks)

def local_health(ip, source, destination, port):
    listener = app.start(B, ["get", str(port), destination])
    app.ready(listener)
    result = app.command(A, ["force", "put", f"{ip}:{port}", source])
    return result, app.wait(listener)

def digest(peer, path):
    return app.execute(peer, """
import hashlib,pathlib,sys
print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
""", path)

def main():
    status = app.setup(app.BINARY)
    ip = status["peers"][1]["ip"]
    app.execute(B, r"""
import pathlib,shutil
for name in ["/tmp/listener-disk-dest-2", "/tmp/backup-low-space-bay-2"]:
 p=pathlib.Path(name)
 if p.exists(): shutil.rmtree(p)
""")
    app.execute(A, r"""
import os,pathlib,sys
root = pathlib.Path(sys.argv[1])
root.mkdir()
(root / "payload").write_bytes(os.urandom(1_000_000))
""", src)
    app.execute(B, r"""
import pathlib,sys
root = pathlib.Path(sys.argv[1])
root.mkdir(mode=0o700)
(root / "payload").write_bytes(b"existing")
""", dest)

    # Idle peers from A exhaust their per-IP budget, while a different source
    # (B's loopback) can authenticate and finish a real transfer.
    for action in ["accept", "backup-server"]:
        port = 42086 if action == "accept" else 42087
        if action == "accept":
            args = ["accept", str(port), dest]
        else:
            cfg = "/work/app-tests/admission-backup.ssync"
            app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.touch(mode=0o600);p.write_text(sys.argv[2])", cfg, f"{app.PASSWORD}={dest}\n")
            args = ["backup-server", str(port), cfg]
        job = app.start(B, args)
        app.ready(job)
        app.execute(A, r"""
import pathlib,socket,subprocess,sys,time
ready=pathlib.Path("/tmp/ssync-idle.ready");ready.unlink(missing_ok=True)
worker = 'import socket,sys,time,pathlib;s=[socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3) for _ in range(4)];assert all(len(x.recv(9,socket.MSG_WAITALL))==9 for x in s);pathlib.Path("/tmp/ssync-idle.ready").touch();time.sleep(30)'
p=subprocess.Popen([sys.executable,"-c",worker,sys.argv[1],sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pathlib.Path("/tmp/ssync-idle.pid").write_text(str(p.pid))
for _ in range(100):
 if ready.exists(): break
 assert p.poll() is None, "idle peer exited before admission"
 time.sleep(.05)
else: raise AssertionError("idle peer not admitted")
""", ip, port)
        try:
            app.execute(B, "import pathlib;p=pathlib.Path('/work/app-tests/healthy');p.mkdir(exist_ok=True);(p/'health').write_bytes(b'healthy')")
            if action == "accept":
                result = app.command(B, ["force", "put", f"127.0.0.1:{port}", "/work/app-tests/healthy/health"])
            else:
                cfg = "/work/app-tests/admission-client.ssync"
                app.execute(B, "import pathlib,sys;p=pathlib.Path(sys.argv[1]);p.touch(mode=0o600);p.write_text(sys.argv[2])", cfg, f"{app.PASSWORD}=/work/app-tests/healthy\n@127.0.0.1:{port}\n")
                result = app.command(B, ["backup-client", cfg])
            assert result["code"] == 0, (action,result,app.logs(job))
            app.execute(B, "import pathlib,sys;assert (pathlib.Path(sys.argv[1])/'health').read_bytes()==b'healthy'",dest)
            print(f"{action}: four idle unauthenticated sockets leave another source able to transfer")
        finally:
            app.execute(A, "import os,pathlib,signal;p=pathlib.Path('/tmp/ssync-idle.pid');os.kill(int(p.read_text()),signal.SIGTERM);p.unlink()")
            app.stop(job)
            app.execute(B, "import pathlib,sys;(pathlib.Path(sys.argv[1])/'health').unlink(missing_ok=True)",dest)
    # The successful backup mirrors its bay; restore the replacement canary.
    app.execute(B, "import pathlib,sys;(pathlib.Path(sys.argv[1])/'payload').write_bytes(b'existing')",dest)
    print("Near-capacity fixture available/total blocks:", make_headroom(110))
    sent, received = local_health(ip, f"{src}/payload", dest, 42081)
    assert sent["code"] and received["code"] and "99% usage" in received["err"], (sent, received)
    stage = app.execute(B, r"""
import pathlib,sys
root = pathlib.Path(sys.argv[1])
assert (root / "payload").read_bytes() == b"existing"
parts = list((root / ".ssync-state").iterdir())
assert len(parts) == 1 and 0 < parts[0].stat().st_size < 1_000_000
assert parts[0].stat().st_mode & 0o777 == 0o600
print(parts[0].stat().st_size)
""", dest)
    print("Mid-file refusal preserved existing target and private resume bytes:", stage)

    print("Above-cutoff fixture available/total blocks:", make_headroom(30))
    sent, received = local_health(ip, f"{src}/payload", dest, 42082)
    assert sent["code"] and received["code"] and "99% usage" in received["err"], (sent, received)
    print("File refused before staging above cutoff")

    app.execute(B, "import pathlib,sys; pathlib.Path(sys.argv[1]).unlink()", filler)
    sent, received = local_health(ip, f"{src}/payload", dest, 42083)
    stats = app.stats(sent)
    app.stats(received)
    assert stats["reused_bytes"] > 0 and digest(A, f"{src}/payload") == digest(B, f"{dest}/payload")
    print("After freeing space, verified content and resumed bytes:", stats["reused_bytes"])

    app.execute(B, r"""
import pathlib,sys
bay, password = sys.argv[1:]
pathlib.Path(bay).mkdir(mode=0o700)
config = pathlib.Path("/work/app-tests/backup-low-space.ssync")
config.touch(mode=0o600)
config.write_text(f"{password}={bay}\n")
""", "/tmp/backup-low-space-bay-2", app.PASSWORD)
    app.execute(A, r"""
import pathlib,sys
src, password, ip = sys.argv[1:]
config = pathlib.Path("/work/app-tests/backup-low-space.ssync")
config.touch(mode=0o600)
config.write_text(f"{password}={src}\n@{ip}:42084\n")
""", src, app.PASSWORD, ip)
    job = app.start(B, ["backup-server", "42084", "/work/app-tests/backup-low-space.ssync"])
    app.ready(job)
    print("Backup cutoff fixture available/total blocks:", make_headroom(30))
    denied = app.command(A, ["backup-client", "/work/app-tests/backup-low-space.ssync"])
    assert denied["code"] and "99% usage" in app.logs(job)["err"], (denied, app.logs(job))
    app.execute(B, r"""
import pathlib,sys
assert not list(pathlib.Path("/tmp/backup-low-space-bay-2").iterdir())
pathlib.Path(sys.argv[1]).unlink()
""", filler)
    completed = app.command(A, ["backup-client", "/work/app-tests/backup-low-space.ssync"])
    assert completed["code"] == 0 and digest(A, f"{src}/payload") == digest(B, "/tmp/backup-low-space-bay-2/payload"), completed
    app.stop(job)
    print("Backup listener refused above cutoff, then accepted upload when space was freed")

    # The backup client's normal four workers can reach distinct bays from one peer.
    cfg = "/work/app-tests/listener-disk-four.ssync"
    app.execute(B, r"""
import pathlib,sys
cfg = pathlib.Path(sys.argv[1])
cfg.touch(mode=0o600)
entries = []
for n in range(4):
    bay = pathlib.Path(f"/work/app-tests/listener-disk-bay-{n}")
    bay.mkdir(mode=0o700)
    entries.append(f"{sys.argv[2]}{n}={bay}\n")
cfg.write_text("".join(entries))
""", cfg, app.PASSWORD)
    app.execute(A, r"""
import pathlib,sys
cfg = pathlib.Path(sys.argv[1])
cfg.touch(mode=0o600)
entries = [f"@{sys.argv[3]}:42085\n"]
for n in range(4):
    src = pathlib.Path(f"/work/app-tests/listener-disk-src-{n}")
    src.mkdir()
    (src / "payload").write_bytes(bytes([n])*200000)
    entries.append(f"{sys.argv[2]}{n}={src}\n")
cfg.write_text("".join(entries))
""", cfg, app.PASSWORD, ip)
    job = app.start(B, ["backup-server", "42085", cfg])
    app.ready(job)
    completed = app.command(A, ["backup-client", cfg])
    assert completed["code"] == 0 and "4 succeeded, 0 failed" in completed["out"], (completed, app.logs(job))
    for n in range(4):
        assert digest(A, f"/work/app-tests/listener-disk-src-{n}/payload") == digest(B, f"/work/app-tests/listener-disk-bay-{n}/payload")
    app.stop(job)
    print("Four normal backup workers from one source completed across four bays")

if __name__ == "__main__":
    try:
        main()
    finally:
        app.execute(B, "import pathlib,sys;pathlib.Path(sys.argv[1]).unlink(missing_ok=True)", filler)
        app.cleanup()
