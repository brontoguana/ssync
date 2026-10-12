#!/usr/bin/env python3
"""Disposable two-peer SSync lab. Developer tooling, never shipped in SSync."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


IMAGE = "docker.io/library/python@sha256:4b849b43ef1de5e0005669100879e6fcd209b82d67665d94bf0746354ab326d9"
NETWORK = "ssync-lab-net"
PEERS = ("ssync-lab-a", "ssync-lab-b")
LABEL = "io.ssync.test-lab"
VALUE = "two-peer-v1"
REPORT = Path(__file__).resolve().parents[2] / "target/podman-lab/status.json"


def podman(*args, input=None, timeout=45):
    return subprocess.run(
        ["podman", *args], input=input, text=True, capture_output=True,
        check=True, timeout=timeout,
    ).stdout.strip()


def exists(kind, name):
    result = subprocess.run(
        ["podman", kind, "exists", name], capture_output=True, timeout=15,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.returncode == 0


def inspect(kind, name):
    return json.loads(podman(kind, "inspect", name))[0]


def owned(kind, name):
    data = inspect(kind, name)
    labels = data.get("labels", {}) if kind == "network" else data["Config"].get("Labels", {})
    if (labels or {}).get(LABEL) != VALUE:
        raise RuntimeError(f"Refusing to manage foreign {kind}: {name}")
    return data


def require_rootless():
    if podman("info", "--format", "{{.Host.Security.Rootless}}") != "true":
        raise RuntimeError("This lab requires rootless Podman; run without sudo.")


def up(profile="small"):
    require_rootless()
    for kind, name in [("network", NETWORK), *(("container", p) for p in PEERS)]:
        if exists(kind, name):
            raise RuntimeError(f"{name} already exists. Use status or down; no resource replaced.")
    # Image acquisition happens on the host; peers themselves have an internal-only network.
    if not exists("image", IMAGE):
        podman("pull", IMAGE, timeout=300)
    podman("network", "create", "--internal", "--disable-dns",
           "--label", f"{LABEL}={VALUE}", NETWORK)
    created = []
    try:
        for peer in PEERS:
            podman(
                "create", "--name", peer, "--hostname", peer,
                "--label", f"{LABEL}={VALUE}", "--label", f"io.ssync.test-profile={profile}", "--pull=never",
                "--network", NETWORK, "--no-hosts", "--user", "1000:1000",
                "--cap-drop=all", "--security-opt=no-new-privileges",
                "--read-only", "--read-only-tmpfs=false", "--image-volume=ignore",
                "--tmpfs", f"/work:rw,size={'6g' if profile=='large' else '256m'},mode=1777,nosuid,nodev,noexec",
                "--tmpfs", "/app:rw,size=32m,mode=1777,nosuid,nodev,exec",
                "--tmpfs", "/tmp:rw,size=16m,mode=1777,nosuid,nodev,noexec",
                *(["--tmpfs","/usr/local/bin:rw,size=32m,mode=755,nosuid,nodev,exec"] if profile=="large" else []),
                f"--memory={'7g' if profile=='large' else '512m'}", f"--memory-swap={'7g' if profile=='large' else '512m'}", "--cpus=1", "--pids-limit=128",
                "--env", "PYTHONDONTWRITEBYTECODE=1", "--workdir=/work",
                "--entrypoint=python3", IMAGE, "-c",
                "import os,time\nwhile True:\n try:\n  while os.waitpid(-1,os.WNOHANG)[0]:pass\n except ChildProcessError:pass\n time.sleep(.1)",
            )
            created.append(peer)
            podman("start", peer)
        status()
    except BaseException:
        for peer in reversed(created):
            podman("rm", "--force", peer)
        podman("network", "rm", NETWORK)
        raise


def status():
    require_rootless()
    network = owned("network", NETWORK)
    if not network["internal"]:
        raise RuntimeError("Lab network is no longer internal")
    peers = []
    for peer in PEERS:
        data = owned("container", peer)
        cfg, host = data["Config"], data["HostConfig"]
        if data["Mounts"] or host["Privileged"] or not host["ReadonlyRootfs"]:
            raise RuntimeError(f"Unexpected mount or privilege configuration: {peer}")
        if cfg["User"] != "1000:1000" or host["PortBindings"]:
            raise RuntimeError(f"Unexpected user or published ports: {peer}")
        if set(data["NetworkSettings"]["Networks"]) != {NETWORK}:
            raise RuntimeError(f"Unexpected extra network: {peer}")
        if data.get("EffectiveCaps") or host["Devices"]:
            raise RuntimeError(f"Unexpected capabilities or devices: {peer}")
        if "no-new-privileges" not in host["SecurityOpt"]:
            raise RuntimeError(f"Missing privilege restriction: {peer}")
        profile=cfg["Labels"].get("io.ssync.test-profile","small")
        if profile not in ("small","large"):raise RuntimeError("Unexpected resource profile")
        expected_memory=(7*1024 if profile=="large" else 512)*1024*1024
        if host["Memory"] != expected_memory or host["PidsLimit"] != 128:
            raise RuntimeError(f"Unexpected resource limits: {peer}")
        if host["NanoCpus"] != 1_000_000_000 or host["MemorySwap"] != host["Memory"]:
            raise RuntimeError(f"Unexpected CPU/swap limits: {peer}")
        if host["PidMode"] == "host" or host["IpcMode"] == "host":
            raise RuntimeError(f"Unexpected shared host namespace: {peer}")
        expected_tmpfs={"/work", "/app", "/tmp"} | ({"/usr/local/bin"} if profile=="large" else set())
        if set(host["Tmpfs"]) != expected_tmpfs:
            raise RuntimeError(f"Unexpected writable tmpfs: {peer}")
        if not data["State"]["Running"]:
            raise RuntimeError(f"Peer is not running: {peer}")
        peers.append({"name": peer, "id": data["Id"], "image_id": data["Image"],
                      "ip": data["NetworkSettings"]["Networks"][NETWORK]["IPAddress"],
                      "user": cfg["User"], "read_only_root": True,
                      "host_mounts": data["Mounts"], "published_ports": host["PortBindings"],
                      "security_opt": host["SecurityOpt"], "cap_drop": host["CapDrop"],
                      "tmpfs": host["Tmpfs"], "memory_bytes": host["Memory"],
                      "pids_limit": host["PidsLimit"]})
    report = {"image": IMAGE, "rootless": True, "network": NETWORK,
              "internal_network": True, "peers": peers}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return report


def smoke():
    report = status()
    isolation = '''import os, pathlib
assert os.getuid() == 1000
try:
    pathlib.Path('/host-write-test').write_text('must fail')
except OSError:
    pass
else:
    raise RuntimeError('root filesystem was writable')
status = pathlib.Path('/proc/self/status').read_text().splitlines()
fields = dict(line.split(':', 1) for line in status if ':' in line)
assert int(fields['CapEff'].strip(), 16) == 0
assert fields['NoNewPrivs'].strip() == '1'
root = pathlib.Path('/work')
for name in ['source', 'destination', 'outside-root']:
    (root / name).mkdir(exist_ok=True)
p = root / 'outside-root/canary.txt'
if not p.exists(): p.write_text('SSync must never modify this canary.\\n')
assert p.read_text() == 'SSync must never modify this canary.\\n'
print('PASS: unprivileged UID, zero effective capabilities, no-new-privileges, read-only root.')
'''
    for peer in PEERS:
        print(podman("exec", "-i", peer, "python3", "-", input=isolation))
    server = '''import hashlib, pathlib, socket
root = pathlib.Path('/work/connectivity-smoke')
root.mkdir(exist_ok=True)
(root / 'result.json').unlink(missing_ok=True)
with socket.socket() as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 39471)); s.listen(1); s.settimeout(30)
    c, _ = s.accept()
    with c, (root / 'received.bin').open('wb') as f:
        c.settimeout(15)
        while True:
            chunk = c.recv(65536)
            if not chunk: break
            f.write(chunk)
    data = (root / 'received.bin').read_bytes()
    (root / 'result.json').write_text(__import__('json').dumps(
        {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}))
'''
    podman("exec", "--detach", PEERS[1], "python3", "-c", server)
    client = '''import hashlib, json, os, pathlib, socket, sys, time
root = pathlib.Path('/work/connectivity-smoke')
root.mkdir(exist_ok=True)
data = os.urandom(2000003)
(root / 'source.bin').write_bytes(data)
for attempt in range(50):
    try:
        s = socket.create_connection((sys.argv[1], 39471), timeout=2)
        break
    except ConnectionRefusedError:
        time.sleep(.1)
else: raise RuntimeError('smoke listener did not start')
with s:
    s.settimeout(15); s.sendall(data); s.shutdown(socket.SHUT_WR)
    assert s.recv(1) == b''
print(json.dumps({'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}))
'''
    expected = json.loads(podman("exec", "-i", PEERS[0], "python3", "-",
                                report["peers"][1]["ip"], input=client))
    check = '''import json, pathlib, time
p = pathlib.Path('/work/connectivity-smoke/result.json')
for _ in range(100):
    if p.exists(): break
    time.sleep(.05)
else: raise RuntimeError('smoke result missing')
print(p.read_text())
'''
    actual = json.loads(podman("exec", "-i", PEERS[1], "python3", "-", input=check))
    if actual != expected:
        raise RuntimeError(f"Connectivity smoke mismatch: {actual} != {expected}")
    print("PASS: isolated TCP/file fixture, 2,000,003 bytes, SHA-256 match.")
    print("This checks the lab only. SSync encryption and transfer tests are not implemented yet.")


def down():
    require_rootless()
    # Validate all existing resources before deleting any of them.
    resources = [("container", p) for p in PEERS] + [("network", NETWORK)]
    present = [(k, n) for k, n in resources if exists(k, n)]
    for kind, name in present:
        owned(kind, name)
    for kind, name in present:
        if kind == "container":
            podman("rm", "--force", name)
        else:
            podman("network", "rm", name)
    REPORT.unlink(missing_ok=True)
    print("Removed labelled SSync lab peers/network. No other resources changed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("up", "status", "smoke", "down"))
    parser.add_argument("--profile",choices=("small","large"),default="small")
    args = parser.parse_args()
    try:
        {"up": lambda:up(args.profile), "status": status, "smoke": smoke, "down": down}[args.action]()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.strip(), file=sys.stderr)
        return 1
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
