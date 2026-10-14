#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for a GCP Intel TDX Confidential VM (Ubuntu 24.04): ask
# the kernel's configfs-tsm for a TDX quote with a caller nonce, twice with
# different nonces, and record what the guest sees of itself. Results go
# to the run's bucket as out/capture.tgz; DONE or FAILED marks the end.
set -u
exec > >(tee -a /root/capture.log) 2>&1
md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
token() { md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
gcs_put() { curl -sSf -X POST -H "Authorization: Bearer $(token)" -H "Content-Type: application/octet-stream" --data-binary @"$1" "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$(enc "$2")" > /dev/null; }
BUCKET=$(md attributes/vg-bucket); STAMP=$(md attributes/vg-stamp)
OUT=/root/out; mkdir -p "$OUT"; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/capture.log "$OUT/console.log" 2>/dev/null || true
  ( cd "$OUT" && sha256sum $(ls | grep -v '^sha256sums.txt$') > sha256sums.txt ) 2>/dev/null || true
  tar -C "$OUT" -czf /root/capture.tgz . && gcs_put /root/capture.tgz out/capture.tgz
  echo "$1" > /root/marker; gcs_put /root/marker "out/$1"
}
trap 'finish FAILED' ERR
set -eE

step "the guest"
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "captured=$STAMP"; } > "$OUT/metadata.txt"
uname -a > "$OUT/kernel.txt"
{ grep -m1 'model name' /proc/cpuinfo; grep -o -w 'tdx_guest' /proc/cpuinfo | head -1; } > "$OUT/cpu.txt" 2>&1 || true
dmesg | grep -i -E 'tdx|tsm|confidential' | head -30 > "$OUT/dmesg-tdx.txt" 2>&1 || true
ls -la /dev/tdx_guest > "$OUT/tdx-device.txt" 2>&1 || echo "no /dev/tdx_guest" > "$OUT/tdx-device.txt"

step "configfs-tsm"
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
ls -la /sys/kernel/config/tsm/report > "$OUT/tsm.txt" 2>&1

quote() { # quote <name> <nonce-hex-64>: one report entry, inblob = nonce, outblob = quote
  local entry=/sys/kernel/config/tsm/report/$1
  mkdir "$entry"
  cat "$entry/provider" > "$OUT/$1.provider.txt"
  local before; before=$(cat "$entry/generation")
  python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' "$2" > "$entry/inblob"
  cat "$entry/outblob" > "$OUT/$1.quote.bin"
  local after; after=$(cat "$entry/generation")
  { echo "nonce_hex=$2"; echo "generation_before=$before"; echo "generation_after=$after"; echo "outblob_bytes=$(stat -c %s "$OUT/$1.quote.bin")"; echo "auxblob_bytes=$(cat "$entry/auxblob" 2>/dev/null | wc -c)"; } > "$OUT/$1.meta.txt"
  rmdir "$entry"
}
step "quote 1: REPORTDATA = the caller's 64 bytes (a SHA-256 of a challenge, then 32 zero bytes)"
NONCE1=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(("vault-genome tdx capture " + sys.argv[1] + " challenge 1").encode()).hexdigest() + "00"*32)' "$STAMP")
quote q1 "$NONCE1"
step "quote 2: another challenge, the same guest"
NONCE2=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(("vault-genome tdx capture " + sys.argv[1] + " challenge 2").encode()).hexdigest() + "00"*32)' "$STAMP")
quote q2 "$NONCE2"
step "a quote of the same shape, parsed only by offsets, for the record"
python3 - "$OUT/q1.quote.bin" > "$OUT/q1.layout.txt" <<'PY'
import struct, sys
b = open(sys.argv[1], "rb").read()
ver, akt, tee = struct.unpack_from("<HHI", b, 0)
print(f"bytes={len(b)} version={ver} att_key_type={akt} tee_type={tee:#x} qe_svn={struct.unpack_from('<H',b,8)[0]} pce_svn={struct.unpack_from('<H',b,10)[0]} qe_vendor_id={b[12:28].hex()} user_data={b[28:48].hex()}")
body = b[48:632]  # TDREPORT body: TEE_TCB_SVN 16, MRSEAM 48, MRSIGNERSEAM 48, SEAMATTRIBUTES 8, TDATTRIBUTES 8, XFAM 8, MRTD 48, MRCONFIGID 48, MROWNER 48, MROWNERCONFIG 48, RTMR0-3, REPORTDATA 64
print(f"tee_tcb_svn={body[0:16].hex()} mrseam={body[16:64].hex()} mrsignerseam={body[64:112].hex()}")
print(f"seamattributes={body[112:120].hex()} tdattributes={body[120:128].hex()} xfam={body[128:136].hex()}")
print(f"mrtd={body[136:184].hex()} mrconfigid={body[184:232].hex()} mrowner={body[232:280].hex()} mrownerconfig={body[280:328].hex()}")
for i in range(4): print(f"rtmr{i}={body[328+48*i:376+48*i].hex()}")
print(f"reportdata={body[520:584].hex()}")
print(f"signature_data_len={struct.unpack_from('<I', b, 632)[0]}")
PY
cat "$OUT/q1.layout.txt"

trap - ERR
finish DONE
