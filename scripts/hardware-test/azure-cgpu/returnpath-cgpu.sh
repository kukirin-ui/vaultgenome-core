#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# On the confidential GPU VM, after cgpu-capture.sh: the Return Path with
# both daemons attesting as azure-cgpu — sagvd and acp-compute each carry
# the vTPM-bound SEV-SNP report and NVIDIA's tokens for the handshake's
# challenge, each pins the other's launch measurement (one guest, one
# measurement), the 7B genome trained here is sealed for sagvd, and a
# gate job goes over the Return Path to a door on the H100 in
# confidential-computing mode. A worker with a simulated TEE is refused
# and recorded. Inputs: sagvd, acp-compute, acpctl, keygen in $HOME
# (uploaded), the trained genome directory, /opt/base, /opt/vg, and the
# capture's cert-chain.pem (the Genoa ASK+ARK chain from Azure's THIM).
# Output: out/<stamp>-returnpath.tgz — logs, identities, job view, audit.
set -u
STAMP="${VG_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
HOME_DIR="$(pwd)"
W="$HOME_DIR/rp"; OUT="$HOME_DIR/out/$STAMP-returnpath"; mkdir -p "$OUT" "$W"; cd "$W"
exec > >(tee -a "$OUT/console.log") 2>&1
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
GPU_TOKEN=/usr/local/lib/local_gpu_verifier/.venv/bin/python
CHAIN="$HOME_DIR/out/${VG_CAPTURE_STAMP:?VG_CAPTURE_STAMP}/cert-chain.pem"

step "inputs"
for b in sagvd acp-compute acpctl keygen; do install -m 0755 "$HOME_DIR/$b" "$W/$b"; done
./sagvd version > "$OUT/versions.txt"; ./acp-compute version >> "$OUT/versions.txt"
cp "$CHAIN" "$W/amd-genoa-cert_chain.pem"; cp "$HOME_DIR/gpu-token.py" "$W/gpu-token.py"
openssl x509 -in "$W/amd-genoa-cert_chain.pem" -noout -subject 2>/dev/null | head -1 > "$OUT/amd-chain-subject.txt"
sha256sum sagvd acp-compute acpctl keygen amd-genoa-cert_chain.pem gpu-token.py > "$OUT/inputs.sha256"

step "provision (keygen); the pins start as placeholders"
./keygen -out secrets -quiet
S=$W/secrets
mkdir -p genomes audit vcek-cache nras-cache rim-cache
head -c 48 /dev/zero > peer-vault.meas; head -c 48 /dev/zero > peer-worker.meas
write_configs() { # $1 = vault measurement hex, $2 = worker measurement hex
  python3 - "$1" "$2" "$W" "$GPU_TOKEN" <<'PY'
import json, sys, binascii
vault_meas, worker_meas, W, py = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
S = W + "/secrets"
open(W + "/peer-vault.meas", "wb").write(binascii.unhexlify(vault_meas))
open(W + "/peer-worker.meas", "wb").write(binascii.unhexlify(worker_meas))
gpu_cmd = [py, W + "/gpu-token.py"]
peer = lambda meas: {"provider": "azure-cgpu", "measurement_path": meas, "amd_cert_chain_path": W + "/amd-genoa-cert_chain.pem",
                     "vcek_cache_dir": W + "/vcek-cache", "nras_cache_dir": W + "/nras-cache",
                     # both: NVIDIA's tokens and this verifier's own evaluation of the GPU's report (ADR 0021),
                     # the manifests fetched from NVIDIA's RIM service into rim-cache/
                     "gpu_policy": {"hw_models": ["GH100"], "evaluation": "both", "rim_cache_dir": W + "/rim-cache"}}
sagvd = {
  "vault": {"listen_address": "127.0.0.1:9443",
    "tls": {"enabled": True, "server_cert": S + "/sagvd/tls/server.crt", "server_key": S + "/sagvd/tls/server.key", "client_cas": S + "/shared/tls/ca.crt"}},
  "http_api": {"listen_address": "127.0.0.1:9080", "bearer_token_file": S + "/sagvd/api_token"},
  "tee": {"provider": "azure-cgpu", "workload_descriptor": "sagvd-returnpath-cgpu-v1", "gpu_attest_command": gpu_cmd, "peer": peer(W + "/peer-worker.meas")},
  "keys": {"authority_signing": {"kid": "sagvd-authority-e2e", "seed_path": S + "/sagvd/authority_signing_seed"},
           "audit_signing": {"kid": "sagvd-audit-e2e", "seed_path": S + "/sagvd/audit_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "workers": {"registry_path": S + "/shared/workers.json"},
  "genome": {"bundle_dir": W + "/genomes", "gate": {"atol": 1e-2, "rtol": 1e-3, "max_non_critical_outliers": 0}},
  "audit": {"log_path": W + "/audit/returnpath-audit.db"},
  "runtime": {"job_timeout_seconds": 900, "handshake_timeout_seconds": 120, "queue_poll_ms": 50,
    "http_read_header_timeout_seconds": 5, "http_write_timeout_seconds": 30, "default_job_deadline_seconds": 900, "max_payload_bytes": 268435456},
  "health": {"listen_address": "127.0.0.1:9081"},
  "log": {"level": "info", "format": "json"}}
worker = {
  "vault": {"address": "127.0.0.1:9443",
    "tls": {"enabled": True, "client_cert": S + "/acp-compute/tls/client.crt", "client_key": S + "/acp-compute/tls/client.key", "ca_bundle": S + "/shared/tls/ca.crt", "server_name": "localhost"}},
  "tee": {"provider": "azure-cgpu", "workload_descriptor": "acp-compute-returnpath-cgpu-v1", "gpu_attest_command": gpu_cmd, "peer": peer(W + "/peer-vault.meas")},
  "keys": {"worker_signing": {"kid": "acp-compute-worker-demo", "seed_path": S + "/acp-compute/worker_signing_seed"},
           "session_sealing": {"kid": "session-sealing-e2e", "material_path": S + "/shared/sealing.key"}},
  "genome": {"door": {"command": ["/opt/vg/bin/python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", "/opt/base", "--device", "cuda"],
                      "env": ["PYTHONPATH=/opt/worker", "TOKENIZERS_PARALLELISM=false"], "timeout_seconds": 600}},
  "runtime": {"job_timeout_seconds": 900, "handshake_timeout_seconds": 120, "dial_backoff_initial_ms": 500, "dial_backoff_max_ms": 5000, "idle_between_jobs_ms": 200},
  "health": {"listen_address": "127.0.0.1:9082"},
  "log": {"level": "info", "format": "json"}}
json.dump(sagvd, open(W + "/sagvd.json", "w"), indent=2)
json.dump(worker, open(W + "/worker.json", "w"), indent=2)
PY
}
ZEROS=$(printf '%096d' 0)
write_configs "$ZEROS" "$ZEROS"

step "the key files sealed to the vTPM (ADR 0023): sagvd's and acp-compute's seeds and the session sealing key, in place"
TOKEN=$(cat "$S/sagvd/api_token")   # read before sagvd seals the file (ADR 0023)
./sagvd seal-keys -config sagvd.json > "$OUT/seal-keys-sagvd.json" 2> "$OUT/seal-keys-sagvd.err"
echo "sagvd seal-keys exit=$?" >> "$OUT/steps.txt"
# The rogue of the negative check below is an impostor with the worker's TLS
# identity and keys of its own: its copy of the bare client key is taken
# before the worker seals its files (the sealed ones open for no other
# identity — which is the point, and what left the rogue unable to start in
# runs 5-7, its "refused after 90s" a timeout, not a refusal).
cp "$S/acp-compute/tls/client.key" "$W/rogue-client.key" && chmod 600 "$W/rogue-client.key"
head -c 32 /dev/urandom > "$W/rogue-signing.seed"; head -c 32 /dev/urandom > "$W/rogue-sealing.key"; chmod 600 "$W/rogue-signing.seed" "$W/rogue-sealing.key"
./acp-compute seal-keys -config worker.json > "$OUT/seal-keys-worker.json" 2> "$OUT/seal-keys-worker.err"
echo "acp-compute seal-keys exit=$?" >> "$OUT/steps.txt"

step "identities: each daemon reads the launch measurement from the vTPM's HCL report"
mark identity_start
./sagvd identity -config sagvd.json > "$OUT/sagvd-identity.json" 2> "$OUT/sagvd-identity.err"; echo "sagvd identity exit=$?" >> "$OUT/steps.txt"
./acp-compute identity -config worker.json > "$OUT/acp-compute-identity.json" 2> "$OUT/acp-compute-identity.err"; echo "acp-compute identity exit=$?" >> "$OUT/steps.txt"
mark identity_end
VMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/sagvd-identity.json" 2>/dev/null)
WMEAS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' "$OUT/acp-compute-identity.json" 2>/dev/null)
echo "vault_measurement=$VMEAS" >> "$OUT/steps.txt"; echo "worker_measurement=$WMEAS" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["audit_public_key_pem"], end="")' "$OUT/sagvd-identity.json" > audit.pem
write_configs "$VMEAS" "$WMEAS"

step "the escrow key sealed to the guest's vTPM (ADR 0022): made in sagvd's process, sealed under this boot's PCR policy, opened once to prove it, re-sealed through the recovery ceremony"
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14 > "$OUT/vtpm-pcrs.txt" 2>&1 || true
./acpctl escrow recovery-keygen --out recovery.seed --pub recovery.pem > "$OUT/recovery-keygen.txt"
./sagvd escrow-provision -config sagvd.json -out escrow.sealed -pub escrow.pem -recovery-to recovery.pem -recovery-out escrow.recovery.json > "$OUT/escrow-provision.json" 2> "$OUT/escrow-provision.err"
echo "escrow-provision exit=$? tee=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("tee"))' "$OUT/escrow-provision.json" 2>/dev/null)" >> "$OUT/steps.txt"
python3 - > "$OUT/escrow-sealed-shape.txt" 2>&1 <<SHAPE
import json,base64
d=json.load(open("escrow.sealed")); inner=json.loads(base64.b64decode(d["sealed"]))
print({"tee":d.get("tee"),"schema":inner.get("schema"),"pcrs":inner.get("pcrs"),"public_bytes":len(base64.b64decode(inner["public"])),"private_bytes":len(base64.b64decode(inner["private"])),"box_bytes":len(base64.b64decode(inner["box"]))})
SHAPE
./acpctl escrow recover --in escrow.recovery.json --key recovery.seed 2> "$OUT/escrow-recover.err" \
  | ./sagvd escrow-provision -config sagvd.json -out escrow-2.sealed -pub escrow-2.pem -stdin > "$OUT/escrow-reprovision.json" 2> "$OUT/escrow-reprovision.err"
echo "escrow re-provision exit=$? re-provisioned escrow_key=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-reprovision.json" 2>/dev/null) source=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source"])' "$OUT/escrow-reprovision.json" 2>/dev/null) (want $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-provision.json" 2>/dev/null))" >> "$OUT/steps.txt"
rm -f recovery.seed

step "the genome trained here, sealed for sagvd"
./acpctl genome seal --content-dir "$HOME_DIR/genome" --output genomes/gen-0.genome --key-out genomes/gen-0.key --json > "$OUT/seal.json" 2> "$OUT/seal.err"
echo "seal exit=$?" >> "$OUT/steps.txt"

step "sagvd on the confidential GPU VM"
./sagvd -config sagvd.json > "$OUT/sagvd.log" 2>&1 &
SAGVD=$!
n=0; until curl -sf http://127.0.0.1:9081/readyz >/dev/null || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
echo "sagvd ready after ${n}s" >> "$OUT/steps.txt"

step "a worker that is not the pinned identity: refused at the Return Path handshake, on the record"
head -c 32 /dev/urandom > rogue.seed; chmod 600 rogue.seed
python3 - "$W" <<'PY'
import json, sys
W = sys.argv[1]
c = json.load(open(W + "/worker.json"))
c["tee"] = {"provider": "simulated", "workload_descriptor": "rogue-worker-v1", "seed_path": W + "/rogue.seed", "insecure_simulation": True, "peer": c["tee"]["peer"]}
c["keys"] = {"worker_signing": {"kid": "rogue-worker", "seed_path": W + "/rogue-signing.seed"},
             "session_sealing": {"kid": "rogue-sealing", "material_path": W + "/rogue-sealing.key"}}
c["vault"]["tls"]["client_key"] = W + "/rogue-client.key"
c["health"] = {"listen_address": "127.0.0.1:9083"}
c["runtime"]["dial_backoff_initial_ms"] = 2000
c["runtime"]["dial_backoff_max_ms"] = 2000
json.dump(c, open(W + "/rogue.json", "w"), indent=2)
PY
./acp-compute -config rogue.json > "$OUT/rogue-worker.log" 2>&1 &
ROGUE=$!
n=0; until grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log" || [ $n -ge 90 ]; do sleep 1; n=$((n+1)); done
if grep -q "sagvd return-path handshake failed" "$OUT/sagvd.log"; then echo "rogue refused after ${n}s" >> "$OUT/steps.txt"; else echo "rogue NOT refused within ${n}s (it did not reach the handshake: $(tail -c 300 "$OUT/rogue-worker.log" | tr -d '\n' | cut -c1-200))" >> "$OUT/steps.txt"; false; fi
kill -TERM $ROGUE; wait $ROGUE 2>/dev/null

step "acp-compute on the confidential GPU VM, the door on the H100"
mark worker_start
./acp-compute -config worker.json > "$OUT/acp-compute.log" 2>&1 &
WORKER=$!
n=0; until curl -sf http://127.0.0.1:9082/healthz >/dev/null || [ $n -ge 120 ]; do sleep 1; n=$((n+1)); done
n=0; until grep -q "sagvd session opened" "$OUT/sagvd.log" || [ $n -ge 180 ]; do sleep 1; n=$((n+1)); done
echo "session opened after ${n}s" >> "$OUT/steps.txt"
mark session_opened

step "the gate job over the Return Path: the genome restored on the H100"
mark job_submit
curl -s -o "$OUT/job-submit.json" -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"genome":{"bundle":"gen-0.genome","key_file":"gen-0.key"},"deadline_seconds_from_now":900}' http://127.0.0.1:9080/v1/jobs > "$OUT/job-submit.status"
JOB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/job-submit.json" 2>/dev/null)
echo "job_id=$JOB" >> "$OUT/steps.txt"
for i in $(seq 1 900); do
  sleep 1
  curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9080/v1/jobs/$JOB" > "$OUT/job.json"
  ST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/job.json" 2>/dev/null)
  [ "$ST" = succeeded ] || [ "$ST" = failed ] && break
done
mark job_done
echo "job status=$ST after ${i}s" >> "$OUT/steps.txt"
python3 - "$OUT/job.json" "$OUT/steps.txt" <<'PY'
import json, sys
j = json.load(open(sys.argv[1])); g = j.get("gate") or {}; v = (g.get("signed_verdict") or {}).get("verdict") or {}
with open(sys.argv[2], "a") as f:
    f.write("gate_level=%s door=%s rung=%s fixtures=%s n_exact=%s max_abs_err=%s signer=%s\n" % (
        g.get("level"), g.get("door"), g.get("rung"), g.get("fixtures"), v.get("n_exact"), v.get("max_abs_err"), g.get("signer_key_id")))
PY
unset TOKEN

step "the manifests the verifiers fetched (rim-cache: the RIM service's responses, public)"
for f in rim-cache/*.json; do [ -f "$f" ] && cp "$f" "$OUT/cache-rim-$(basename "$f")"; done
ls -la rim-cache > "$OUT/rim-cache-ls.txt" 2>&1 || true

step "metrics; stop both; verify the audit log with the published key"
curl -s http://127.0.0.1:9081/metrics | grep -E "^(sagvd|rp|vg_tee)_" > "$OUT/sagvd-metrics.txt"
curl -s http://127.0.0.1:9082/metrics | grep -E "^(acp_compute|rp|vg_tee)_" > "$OUT/acp-compute-metrics.txt"
kill -TERM $WORKER; wait $WORKER 2>/dev/null
kill -TERM $SAGVD; wait $SAGVD 2>/dev/null
./acpctl audit verify --audit audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-e2e --json > "$OUT/audit-verify.json" 2> "$OUT/audit-verify.err"
echo "audit verify exit=$?" >> "$OUT/steps.txt"
./acpctl audit query --audit audit/returnpath-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2> "$OUT/audit-query.err"
cp audit.pem "$OUT/audit-public-key.pem"
for f in vcek-cache/* nras-cache/*; do [ -f "$f" ] && cp "$f" "$OUT/cache-$(basename "$f")"; done
echo "== RETURNPATH DONE" >> "$OUT/steps.txt"
( cd "$OUT" && sha256sum $(ls | grep -v '^sha256sums.txt$') > sha256sums.txt )
( cd "$HOME_DIR/out" && tar czf "$STAMP-returnpath.tgz" "$STAMP-returnpath" )
chown "$(stat -c %U "$HOME_DIR")" "$HOME_DIR/out/$STAMP-returnpath.tgz" 2>/dev/null || true
echo "RETURNPATH DONE $STAMP"
