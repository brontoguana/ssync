#!/usr/bin/env bash
# Bootstrap only; installed SSync manages subsequent updates through native APIs.
set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'SSync release binaries currently support Linux x86_64 (kernel 5.6+).' >&2
  exit 1
fi
for command in curl sha256sum mktemp; do
  command -v "$command" >/dev/null || { echo "Required command missing: $command" >&2; exit 1; }
done
ssync_tmp="$(mktemp -d)"
trap 'rm -rf "$ssync_tmp"' EXIT
ssync_url='https://github.com/brontoguana/ssync/releases/latest/download'
curl --proto '=https' --tlsv1.2 -fsSL "$ssync_url/ssync_linux_amd64" -o "$ssync_tmp/ssync_linux_amd64"
curl --proto '=https' --tlsv1.2 -fsSL "$ssync_url/checksums.txt" -o "$ssync_tmp/checksums.txt"
# Only the exact binary entry is checked; unrelated archive filenames are never interpreted.
ssync_sum="$(awk '$2 == "ssync_linux_amd64" { print $1 "  ssync_linux_amd64"; n++ } END { if (n != 1) exit 1 }' "$ssync_tmp/checksums.txt")"
if ! (cd "$ssync_tmp"; printf '%s\n' "$ssync_sum" | sha256sum --check --status -); then
  echo 'SSync download checksum failed; installation was not changed.' >&2
  exit 1
fi
chmod 0755 "$ssync_tmp/ssync_linux_amd64"
if [[ "$(id -u)" == 0 || -n "${SSYNC_INSTALL_DIR:-}" ]]; then
  "$ssync_tmp/ssync_linux_amd64" install
else
  sudo "$ssync_tmp/ssync_linux_amd64" install
fi
