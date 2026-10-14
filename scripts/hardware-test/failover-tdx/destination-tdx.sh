#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for the STANDBY, a GCP Intel TDX Trust Domain (c3): the
# DESTINATION of the failover drill — acp-bootstrap attesting as gcp-tdx
# (a TDX quote per challenge through configfs-tsm, signed by the host's
# Quoting Enclave), listening for the authority over mTLS on the VPC,
# restoring the genome whose key is released to it and gating it through
# the door on this VM's CPUs. It takes the authority's TLS material and
# token from the run's private bucket, publishes its own identity there
# (endpoint, TDX measurement), pulls the primary's outbox replica itself,
# and when the authority is done packs its receipts and logs into
# out/destination.tgz. No sealer on a TDX host: it receives, it does not
# escrow.
set -u
exec > >(tee -a /root/destination.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; REPLICA=/root/replica; mkdir -p "$OUT" "$REPLICA" /root/restored /opt/worker /root/dest; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  [ -f /root/acp-bootstrap.pid ] && kill -TERM "$(cat /root/acp-bootstrap.pid)" 2>/dev/null; sleep 2
  cp /root/destination.log "$OUT/console.log" 2>/dev/null || true
  cp /root/acp-bootstrap.log "$OUT/acp-bootstrap.log" 2>/dev/null || true
  ls -la /root/restored > "$OUT/restored-ls.txt" 2>/dev/null || true
  for r in /root/restored/*.receipt.json; do [ -f "$r" ] && cp "$r" "$OUT/"; done
  for d in /root/restored/*/; do [ -d "$d" ] && { echo "$(basename "$d")"; ls "$d"; head -c 200 "$d/adapter/adapter_model.safetensors" 2>/dev/null | sha256sum; } >> "$OUT/restored-tree.txt"; done
  ls "$REPLICA" > "$OUT/replica-ls.txt" 2>/dev/null || true
  curl -s http://127.0.0.1:8444/metrics > "$OUT/acp-bootstrap-metrics.txt" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/destination.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/destination/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
for b in acp-bootstrap acpctl; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
INTERNAL_IP=$(md network-interfaces/0/ip)
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "internal_ip=$INTERNAL_IP"; } > "$OUT/metadata.txt"
{ uname -a; lscpu | head -20; } > "$OUT/system.txt" 2>&1
sha256sum /usr/local/bin/acp-bootstrap /usr/local/bin/acpctl /root/worker.tgz > "$OUT/inputs.sha256"

step "the Trust Domain: configfs-tsm (tdx_guest)"
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/tdx_guest 2>&1; grep -m1 'model name' /proc/cpuinfo; dmesg | grep -i -E "tdx|tsm" | head -20; } > "$OUT/tsm.txt" 2>&1

step "the vTPM (tpm2-tools): acp-bootstrap seals its TLS key and token to it (ADR 0022, 0023)"
# apt at boot: cloud-init and unattended-upgrades may hold the lock, and
# the lists may be stale — update, then retry until tpm2-tools are there.
export DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 12); do
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq tpm2-tools >/dev/null 2>&1 && break
  sleep 10
done
command -v tpm2_createprimary >/dev/null || { echo "tpm2-tools did not install"; false; }
{ ls -la /dev/tpm0 /dev/tpmrm0 2>&1; tpm2_getcap properties-fixed 2>&1 | grep -A1 -E "TPM2_PT_MANUFACTURER|TPM2_PT_VENDOR_STRING_1" | head -4; } > "$OUT/vtpm.txt" 2>&1

step "python runtime (CPU) and the base model the genome names — the gate runs the model here"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "the authority's TLS material, token and public key (through the private bucket)"
for i in $(seq 1 240); do gcs_get handoff/dest/xcc_token /root/dest/xcc_token 2>/dev/null && gcs_get handoff/authority.pem /root/dest/authority.pem 2>/dev/null && break; sleep 10; done
[ -s /root/dest/xcc_token ] && [ -s /root/dest/authority.pem ] || { echo "no hand-off from the authority after 40 minutes"; false; }
for f in server.crt server.key ca.crt; do gcs_get "handoff/dest/$f" "/root/dest/$f"; done
chmod 600 /root/dest/server.key /root/dest/xcc_token

step "acp-bootstrap as gcp-tdx: the destination of a key release, the door on this VM's CPUs"
python3 - <<'PY'
import json
c = {
 "http": {"listen_address": "0.0.0.0:8443", "bearer_token_file": "/root/dest/xcc_token",
          "tls": {"enabled": True, "server_cert": "/root/dest/server.crt", "server_key": "/root/dest/server.key", "client_cas": "/root/dest/ca.crt"}},
 "tee": {"provider": "gcp-tdx", "workload_descriptor": "acp-bootstrap-tdx-standby-v1"},
 "source_authority": {"kid": "sagvd-authority-demo", "public_key_path": "/root/dest/authority.pem"},
 "genome": {"bundle_dir": "/root/replica", "restore_dir": "/root/restored", "rescan_seconds": 2,
            "gate": {"command": ["/opt/vg/bin/python", "-m", "vg_genome", "door", "--genome", "{genome}", "--base", "/opt/base", "--device", "cpu"],
                     "env": ["PYTHONPATH=/opt/worker", "TOKENIZERS_PARALLELISM=false"], "atol": 0.01, "rtol": 0.001, "timeout_seconds": 600, "required": True}},
 "health": {"listen_address": "127.0.0.1:8444"}, "log": {"level": "info", "format": "json"}}
json.dump(c, open("/root/dest.json", "w"), indent=2)
PY
acp-bootstrap seal-keys -config /root/dest.json > "$OUT/dest-seal-keys.json" 2> "$OUT/dest-seal-keys.err"
echo "acp-bootstrap seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/dest-seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
acp-bootstrap identity -config /root/dest.json > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
echo "acp-bootstrap identity exit=$?" >> "$OUT/steps.txt"
nohup acp-bootstrap -config /root/dest.json > /root/acp-bootstrap.log 2>&1 &
echo $! > /root/acp-bootstrap.pid
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "acp-bootstrap ready after ${n}s" >> "$OUT/steps.txt"

step "publish this destination's identity: endpoint on the VPC, TDX measurement"
python3 - "$INTERNAL_IP" <<'PY'
import json, sys
d = json.load(open("/root/out/destination-identity.json"))
out = {"endpoint": f"https://{sys.argv[1]}:8443", "measurement_hex": d["measurement_hex"], "tee_provider": d.get("tee_provider") or d.get("provider"), "tdx": d.get("tdx")}
json.dump(out, open("/root/destination.json", "w"), indent=1); print(out)
PY
cp /root/destination.json "$OUT/destination-handoff.json"
gcs_put /root/destination.json handoff/destination.json

step "pull the primary's outbox replica until the authority is done"
for i in $(seq 1 900); do
  pull_outbox "$REPLICA"
  for m in DONE FAILED; do gcs_get "out/authority/$m" /root/authority-marker 2>/dev/null && { echo "authority: $m" >> "$OUT/steps.txt"; break 2; }; done
  sleep 4
done
sleep 5
echo "== COLLECTED" >> "$OUT/steps.txt"

trap - ERR
finish DONE
