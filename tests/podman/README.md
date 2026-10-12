# Disposable SSync test lab

Two independently running peers, `ssync-lab-a` and `ssync-lab-b`, communicate over `ssync-lab-net`. The network is internal and DNS is disabled; retrieve addresses with `status`. There are no published host ports. Each peer runs as container UID/GID 1000, under rootless Podman, without effective capabilities or new privileges. The image root is read-only. No host checkout, home directory, credentials, Podman socket, or other host directory is mounted. Images are pinned by digest. See [Podman run options](https://docs.podman.io/en/latest/markdown/podman-run.1.html).

Run from the SSync project folder, without sudo:

```bash
python3 tests/podman/lab.py up
python3 tests/podman/lab.py status
python3 tests/podman/lab.py smoke
python3 tests/podman/lab.py down
```

`up` refuses to replace existing resources. `down` removes only these exact names with matching ownership labels, after checking all labels. It can be run repeatedly. No container/image/volume pruning is used. A partial creation failure attempts to remove only resources created by that run. `status` verifies isolation settings and writes ignored `target/podman-lab/status.json`. No change to system Podman configuration is needed.

The first `up` may download the pinned Python test image if it is not cached. The lab's Python interpreter is developer tooling, independent of the future Rust executable's runtime. Each container is limited to 512 MiB RAM, no additional swap allocation, one CPU, and 128 processes. Its writable tmpfs areas are:

| Container path | Limit | Purpose |
|---|---:|---|
| `/work` | 256 MiB | Transfer fixtures, source/destination roots, partials, outside-root canaries; noexec |
| `/app` | 32 MiB | Explicitly copied native binary/test helpers; executable |
| `/tmp` | 16 MiB | Scratch state; noexec |

All test payloads are synthetic. Stop/restart or removal destroys tmpfs data; graceful SSync-process restart can test resume while the peer container remains running. Reboot/container-recreation persistence will need a separate test-only named-volume profile. Large-file tests within this profile use 20 MB fixtures to leave room for existing, partial, and staged copies; multi-GiB/sparse-file tests require a separately documented bounded storage profile. Do not relax isolation or mount real host trees to accommodate them.

## Native executable loading and test operation

Once a Linux executable exists, copy the artifact, not the working tree:

```bash
podman cp target/release/ssync ssync-lab-a:/app/ssync
podman cp target/release/ssync ssync-lab-b:/app/ssync
podman exec ssync-lab-a /app/ssync version
podman exec ssync-lab-b /app/ssync version
```

If `/app` is insufficient for a debug artifact, copy a stripped release build or explicitly document a bounded larger test profile. Verify copied executable ownership/mode and record its SHA-256 and reported version. Run payload generation and tests through `podman exec`; feed fixture/protocol-helper source over stdin or copy only the required test helper into `/app`. Never mount the project writable. Commands run by the lab are developer instrumentation; the SSync executable itself cannot launch scripts or processes.

The infrastructure smoke initializes `/work/source`, `/work/destination`, and `/work/outside-root/canary.txt` inside each peer. Adversarial path tests must assert that this outside-root canary and any unrelated destination files remain unchanged. Read-only-root and Unix capability checks supplement application containment tests; they do not substitute for them. Exercise containment entirely inside the sandbox, including link and race targets.

Use IPs from `status` and unprivileged ports (for example 39470). Generate synthetic test credentials inside the peers or via controlled stdin; never use a production password. Implement the native test harness's credential delivery after CLI input handling is defined; do not place real secrets in arguments, test commands, evidence, or repository fixtures. Capture peer stdout/stderr, exit codes, counters, fixture hashes, canary hashes, and fault settings under `target/podman-lab/`. Record exact commands/settings and raw summaries in ignored `DEBUGLOG.md`. Check the complete [test matrix](../TEST_MATRIX.md) before release.

Protocol fault tests can run a userspace TCP proxy inside either existing peer, introducing truncation, tampering, replay, delay, and disconnects without extra capabilities. Capture wire bytes in that proxy instead of enabling privileged packet capture. `podman exec` can terminate a test process or disconnect/reconnect a peer from the labelled network for failure tests, then restore it. Do not use `--privileged`, host networking, host PID namespaces, or container engine sockets.

## Current verification

On 2026-10-12 the lab was created on Linux with rootless Podman 4.9.3. Configuration checks confirmed no host mounts or published ports, internal network, read-only roots, unprivileged UID, dropped capabilities, and resource limits. The smoke transfers 2,000,003 random bytes from A to B over plain test TCP and verifies matching SHA-256 hashes. It also checks read-only-root enforcement, zero effective capabilities, and `NoNewPrivs` in each running peer. Repeated smoke runs, duplicate-creation refusal, idempotent teardown, and clean recreation passed. The two recreated peers are left running for native implementation testing.

This is an infrastructure test, not SSync transfer or encryption validation. Native application tests are implemented; see ../../docs/VALIDATION.md for current executed results and remaining release gates. Containers use the shared host kernel; tests here isolate file/network effects from real host data but do not claim virtual-machine isolation. Current IDs, IPs, and image identity are in `target/podman-lab/status.json`, rather than hard-coded into procedures.


## Actual application suites

After `lab.py up`, build the static musl main binary and test-only adversary, then run in order:

```bash
python3 tests/podman/application.py
python3 tests/podman/security.py
python3 tests/podman/lifecycle.py
python3 tests/podman/inputs.py
python3 tests/podman/advanced.py
python3 tests/podman/management.py
python3 tests/podman/large.py
python3 tests/podman/longrun.py
```

Application setup clears only `/work/app-tests` inside the labelled peers. Job status/logs are stored in separate `/tmp/ssync-jobs`, so filling `/work` cannot erase exit evidence. PID1 reaps adopted test helpers, preventing zombie exhaustion under the128-PID cap. Helpers use unique monotonic job paths, synthetic passwords and container-local canaries. Logs/JSON reports remain under ignored `target/podman-*` on the developer machine. The binary's `licenses` output is compared with the tracked dependency notice text. Developer Python/proxy helpers are not included in the shipped executable.

Management tests need a synthetic **4.0.1** executable, not a public release: copy `src/`, Cargo.toml/lock and THIRD_PARTY_NOTICES.txt under ignored `target/update-fixture-source`, change only that copy's package version to4.0.1, and build it with `CARGO_TARGET_DIR=target/update-fixture-build` for Linux musl. The fixture serves loopback HTTP through explicitly enabled `SSYNC_TEST_UPDATE=1`/`SSYNC_RELEASE_API_URL`; ordinary update mode uses this project's public GitHub API with HTTPS-only redirects. This checks native update behavior, not a public-release smoke. Once publication succeeds, separately verify the real public latest API/assets in a disposable egress-enabled peer.

## Large-file/system-install profile

`large.py` destroys/recreates only the two labelled test peers, with an explicit `large` profile:6GiB `/work` tmpfs and7GiB memory per peer,1CPU,128PIDs,32MiB `/app`,16MiB `/tmp`. It adds a32MiB executable `/usr/local/bin` tmpfs solely for root-owned default installation checks via `podman exec --user 0` inside the rootless namespace. No host directory, device, engine socket or port is exposed; both root filesystems stay read-only. This profile supports2.4GB logical files plus a separately verified staged replacement. Sparse source correctness is checked; physical sparse destination preservation is not promised. Bounds are intentional—do not use unlimited memory or writable host mounts to run larger tests.

Use `python3 tests/podman/lab.py down` and `... up` to restore the small profile. Existing-profile creation refuses to overwrite peers. `status` validates labelled profile limits and mounts. `longrun.py` delays container-only proxy chunks to keep a transfer progressing for over120seconds, proving socket idle deadlines are not total transfer deadlines. Test peers can be left running for follow-up work; teardown removes only labelled resources.
