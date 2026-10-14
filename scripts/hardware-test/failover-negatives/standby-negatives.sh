#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The negatives drill's STANDBY: an AMD SEV-SNP Confidential VM hosting
# the release authority (sagvd failover, escrow key sealed to this chip)
# and the destination (acp-bootstrap) on loopback TLS, as in the failover
# drill. It pulls the primary's outbox replica, arms, and — once the
# primary's sentinel has reported the attack with the chip's report on the
# record — asks the authority eight times, each under a different
# operator-signed policy, and checks each answer:
#
#   1  a policy that stood 45 s and expired while the authority watched
#      -> declined on the record ("expired")
#   2  a policy allowing at most 1 s of lost state -> declined ("at most 1s")
#   3  a policy quarantining a day -> declined (no genome checks out)
#   4  a good policy under an operator stop -> the handshake runs, the
#      chip verifies, the release is DENIED on the record ("operator stop")
#   5  a policy pinning another machine as the standby -> DENIED ("releases
#      only to its standby")
#   6  a good policy, with the newest bundle corrupted in the replica ->
#      the move: generation 1 set aside on the record ("hashes to"),
#      generation 0 restored and gated
#   7  the spent policy again -> refused at the door ("already carried out")
#   8  a policy signed by a stranger -> refused at the door
#
# Every answer of 1-6 is a signed event on one audit log, verified offline
# at the end. Reports go to out/standby/.
set -u
exec > >(tee -a /root/standby.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; REPLICA=/root/replica; WORK=/root; mkdir -p "$OUT" /opt/worker "$REPLICA"; cd "$WORK"
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/standby.log "$OUT/console.log" 2>/dev/null || true
  cp /root/acp-bootstrap.log "$OUT/acp-bootstrap.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/standby.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/standby/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
for b in sagvd acp-bootstrap acpctl keygen; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
gcs_get in/amd-milan-cert_chain.pem /root/amd-milan-cert_chain.pem
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; } > "$OUT/system.txt" 2>&1

step "provision (keygen), the operator's stop key and recovery key, stop list serial 1 (nothing stopped)"
keygen -out /root/secrets -quiet
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN" > /root/secrets/xcc_token; chmod 600 /root/secrets/xcc_token
acpctl stop keygen --out /root/operator.seed --pub /root/operator.pem > /dev/null
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 1 --out /root/stop.json > /dev/null
cp /root/stop.json "$OUT/stop-1.json"
acpctl escrow recovery-keygen --out /root/recovery.seed --pub /root/recovery.pem > "$OUT/recovery-keygen.txt"

S=/root/secrets
step "python runtime (CPU) and base model — the gate runs the model here"
python_runtime https://download.pytorch.org/whl/cpu
base_model

step "configfs-tsm (real SEV-SNP reports)"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail; } > "$OUT/tsm.txt" 2>&1

step "sagvd on SEV-SNP: identity from the chip"
head -c 48 /dev/zero > /root/peer.meas
python3 - <<PY
import json
S="$S"
c={
 "vault":{"listen_address":"127.0.0.1:9443","tls":{"enabled":True,"server_cert":S+"/sagvd/tls/server.crt","server_key":S+"/sagvd/tls/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "http_api":{"listen_address":"127.0.0.1:9080","bearer_token_file":S+"/sagvd/api_token"},
 "tee":{"provider":"gcp-sev-snp","workload_descriptor":"sagvd-failover-authority-v1",
        "peer":{"provider":"gcp-sev-snp","measurement_path":"/root/peer.meas","amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}},
 "keys":{"authority_signing":{"kid":"sagvd-authority-demo","seed_path":S+"/sagvd/authority_signing_seed"},
         "audit_signing":{"kid":"sagvd-audit-demo","seed_path":S+"/sagvd/audit_signing_seed"},
         "session_sealing":{"kid":"session-sealing-demo","material_path":S+"/shared/sealing.key"}},
 "workers":{"registry_path":S+"/shared/workers.json"},
 "runtime":{"job_timeout_seconds":60,"handshake_timeout_seconds":10,"queue_poll_ms":50,"http_read_header_timeout_seconds":5,"http_write_timeout_seconds":30,"default_job_deadline_seconds":60,"max_payload_bytes":4194304},
 "health":{"listen_address":"127.0.0.1:9081"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/sagvd-base.json","w"),indent=2)
PY
# The key files the config names — the authority's signing seed, the audit
# seed, the session sealing key — sealed to this host's TEE in place (ADR
# 0023); every sagvd from here on reads them sealed.
# The destination (acp-bootstrap, on this host too) gets its own copies of the
# TLS pair and the token before sagvd seals its files: each daemon seals
# what it reads, under its own name (ADR 0023).
mkdir -p "$S/dest" && cp "$S/sagvd/tls/server.crt" "$S/sagvd/tls/server.key" "$S/xcc_token" "$S/dest/" && chmod 600 "$S/dest/server.key" "$S/dest/xcc_token"
sagvd seal-keys -config /root/sagvd-base.json > "$OUT/seal-keys.json" 2> "$OUT/seal-keys.err"
echo "seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
sagvd identity -config /root/sagvd-base.json > /root/authority-identity-base.json 2> "$OUT/authority-identity.err"
echo "sagvd identity (base) exit=$?" >> "$OUT/steps.txt"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["authority_public_key_pem"],end="")' /root/authority-identity-base.json > /root/authority.pem
AMEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["tee_measurement_hex"])' /root/authority-identity-base.json)
echo "authority measurement=$AMEAS" >> "$OUT/steps.txt"
python3 -c 'import binascii,sys; open("/root/peer.meas","wb").write(binascii.unhexlify(sys.argv[1]))' "$AMEAS"

step "the escrow key: made in the authority's process, sealed to this chip, wrapped to the recovery key"
sagvd escrow-provision -config /root/sagvd-base.json -out /root/escrow.sealed -pub /root/escrow-local.pem \
  -recovery-to /root/recovery.pem -recovery-out /root/escrow.recovery > "$OUT/escrow-provision.json" 2> "$OUT/escrow-provision.err"
echo "escrow-provision exit=$?" >> "$OUT/steps.txt"
gcs_put /root/escrow-local.pem handoff/escrow.pem

step "acp-bootstrap on SEV-SNP (destination + gate)"
python3 - <<PY
import json
S="$S"
c={
 "http":{"listen_address":"127.0.0.1:8443","bearer_token_file":S+"/dest/xcc_token",
         "tls":{"enabled":True,"server_cert":S+"/dest/server.crt","server_key":S+"/dest/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "tee":{"provider":"gcp-sev-snp","workload_descriptor":"acp-bootstrap-standby-v1"},
 "source_authority":{"kid":"sagvd-authority-demo","public_key_path":"/root/authority.pem"},
 "genome":{"bundle_dir":"$REPLICA","restore_dir":"/root/restored","rescan_seconds":2,
           "gate":{"command":["/opt/vg/bin/python","-m","vg_genome","door","--genome","{genome}","--base","/opt/base","--device","cpu"],
                   "env":["PYTHONPATH=/opt/worker","TOKENIZERS_PARALLELISM=false"],"atol":0.01,"rtol":0.001,"timeout_seconds":300,"required":True}},
 "health":{"listen_address":"127.0.0.1:8444"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/dest.json","w"),indent=2)
PY
acp-bootstrap seal-keys -config /root/dest.json > "$OUT/dest-seal-keys.json" 2> "$OUT/dest-seal-keys.err"
echo "acp-bootstrap seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/dest-seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
acp-bootstrap identity -config /root/dest.json > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
acp-bootstrap -config /root/dest.json > /root/acp-bootstrap.log 2>&1 &
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 30 ]; do sleep 1; n=$((n+1)); done
MEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' "$OUT/destination-identity.json")
echo "standby measurement=$MEAS" >> "$OUT/steps.txt"

step "sagvd failover config: verifier registry, allow-list, operator stop, the sealed escrow key"
python3 - <<PY
import json
S="$S"; MEAS="$MEAS"
json.dump({"verifiers":[{"provider":"gcp-sev-snp","expected_measurement_hex":MEAS,"amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}]},open("/root/verifiers.json","w"))
json.dump({"version":"failover-policy-v1","allowed":{"gcp-sev-snp":[MEAS]}},open("/root/allow.json","w"))
c=json.load(open("/root/sagvd-base.json"))
c["crosscloud"]={"enabled":True,"policy_version":"failover-policy-v1","audit_log_path":"/root/xcc-audit.db",
 "operator_stop":{"kid":"operator-1","public_key_path":"/root/operator.pem","list_path":"/root/stop.json"},
 "key_escrow_path":"/root/escrow.sealed",
 "policy_allow_list_path":"/root/allow.json","verifier_registry_path":"/root/verifiers.json",
 "transport_bearer_token":open(S+"/xcc_token").read().strip(),"request_timeout_seconds":30,
 "transport_tls":{"enabled":True,"client_cert":S+"/acp-compute/tls/client.crt","client_key":S+"/acp-compute/tls/client.key","ca_bundle":S+"/shared/tls/ca.crt"}}
json.dump(c,open("/root/sagvd.json","w"),indent=2)
PY
# The failover config names the cross-cloud transport's client key: sealed
# now, in place (seal-keys skips what the base config's run sealed).
sagvd seal-keys -config /root/sagvd.json > "$OUT/seal-keys-2.json" 2> "$OUT/seal-keys-2.err"
echo "seal-keys (failover config) exit=$? sealed=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(",".join(e["name"] for e in d["sealed"]))' "$OUT/seal-keys-2.json" 2>/dev/null) already=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d.get("already_sealed",[])))' "$OUT/seal-keys-2.json" 2>/dev/null)" >> "$OUT/steps.txt"
cp /root/verifiers.json /root/allow.json "$OUT/"
sagvd identity -config /root/sagvd.json > "$OUT/authority-identity.json" 2>> "$OUT/authority-identity.err"
echo "sagvd identity exit=$? key_escrow_storage=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("key_escrow_storage"))' "$OUT/authority-identity.json")" >> "$OUT/steps.txt"

step "wait for the primary's sentinel key and chip identity (the operator pins both)"
for i in $(seq 1 480); do gcs_get handoff/sentinel-identity.json /root/sentinel-identity.json 2>/dev/null && gcs_get handoff/sentinel.pem /root/sentinel.pem 2>/dev/null && break; sleep 5; done
[ -s /root/sentinel.pem ] && [ -s /root/sentinel-identity.json ] || { echo "no sentinel identity after 40 minutes"; false; }
cp /root/sentinel-identity.json "$OUT/primary-identity.json"
PMEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' /root/sentinel-identity.json)
echo "primary measurement=$PMEAS" >> "$OUT/steps.txt"

# issue <serial> <standby measurement> <reason> [flags...]: an operator-signed
# policy pinning the primary's sentinel key and chip; verified and kept.
issue() {
  local serial="$1" smeas="$2" reason="$3"; shift 3
  acpctl failover issue --key /root/operator.seed --kid operator-1 --serial "$serial" \
    --sentinel-pub /root/sentinel.pem --primary-kind gcp-sev-snp --primary-measurement "$PMEAS" \
    --standby-kind gcp-sev-snp --standby-endpoint https://127.0.0.1:8443 --standby-measurement "$smeas" \
    --require-gate EQUIVALENT --reason "$reason" --out "/root/policy-$serial.json" "$@" > "$OUT/policy-$serial-issue.txt"
  acpctl failover verify --in "/root/policy-$serial.json" --pubkey /root/operator.pem --kid operator-1 > "$OUT/policy-$serial-verify.txt"
  cp "/root/policy-$serial.json" "$OUT/policy-$serial.json"
}
# outcome <report>: status and the reason or error, for steps.txt.
outcome() { python3 -c 'import json,sys
try:
    r=json.load(open(sys.argv[1])); print(r.get("status","?"), "|", ((r.get("decision") or {}).get("reason") or r.get("error") or "")[:160])
except Exception: print("no report")' "$1" 2>/dev/null; }
# run <n> <serial> <confirm-wait>: one executor run; CODE is its exit code.
# The || list keeps the expected non-zero exits from the ERR trap.
run() {
  local n="$1" serial="$2" wait="$3"
  CODE=0
  sagvd failover -config /root/sagvd.json -policy "/root/policy-$serial.json" -outbox "$REPLICA" \
    -poll 2s -confirm-wait "$wait" -report "$OUT/report-$n.json" > "$OUT/failover-$n.log" 2>&1 || CODE=$?
  echo "run $n (policy serial $serial): sagvd failover exit=$CODE; $(outcome "$OUT/report-$n.json")" >> "$OUT/steps.txt"
}
expect() { grep -q -- "$2" "$1" || { echo "run $3: expected '$2' in $1"; false; }; }
code() { [ "$CODE" = "$2" ] || { echo "run $1: sagvd failover exited $CODE, want $2"; false; }; }

step "pull the primary's outbox replica, continuously"
( trap - ERR; set +e; while true; do pull_outbox "$REPLICA"; sleep 3; done ) &
PULL=$!

step "1/8 arm under a policy that stands 45 s: it will have expired when the attack comes, and the trigger must be declined on the record"
issue 1 "$MEAS" "negatives drill 1/8: a policy that expires while the authority watches" --heartbeat-timeout 120s --stopped-grace 60s --valid-for 45s
sagvd failover -config /root/sagvd.json -policy /root/policy-1.json -outbox "$REPLICA" \
  -poll 2s -confirm-wait 5m -report "$OUT/report-1.json" > "$OUT/failover-1.log" 2>&1 &
N1=$!
n=0; until grep -q '"state":"watching"' "$OUT/failover-1.log" || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "run 1 watching after ${n}s; policy 1 expires at $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["not_after"])' /root/policy-1.json)" >> "$OUT/steps.txt"
gcs_put_str handoff/armed "armed at $(date -u +%H:%M:%SZ)"
CODE=0; wait "$N1" || CODE=$?
echo "run 1 (policy serial 1): sagvd failover exit=$CODE; $(outcome "$OUT/report-1.json")" >> "$OUT/steps.txt"
code 1 3; expect "$OUT/report-1.json" "expired" 1

step "the primary's last word: wait for it to finish, take the final replica, stop pulling"
for i in $(seq 1 60); do gcs_get out/primary/DONE /root/primary.done 2>/dev/null && break; gcs_get out/primary/FAILED /root/primary.failed 2>/dev/null && break; sleep 5; done
pull_outbox "$REPLICA" || true
kill "$PULL" 2>/dev/null || true
ls -la "$REPLICA" > "$OUT/replica-ls.txt"
(cd "$REPLICA" && sha256sum -- * 2>/dev/null) > "$OUT/replica-sha256.txt" || true

step "2/8 a policy allowing at most 1 s of lost state: declined on the record"
issue 2 "$MEAS" "negatives drill 2/8: at most 1 s of lost state" --max-rpo 1s
run 2 2 2m; code 2 3; expect "$OUT/report-2.json" "at most 1s" 2

step "3/8 a policy quarantining a day: no genome checks out, declined on the record"
issue 3 "$MEAS" "negatives drill 3/8: a day's quarantine" --quarantine 24h
run 3 3 2m; code 3 3; expect "$OUT/report-3.json" "no genome in the verified chain" 3

step "4/8 a good policy under an operator stop (stop list serial 2, everything): the chip verifies, the release is denied on the record"
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 2 --all --reason "incident review" --out /root/stop.json > /dev/null
cp /root/stop.json "$OUT/stop-2.json"
issue 4 "$MEAS" "negatives drill 4/8: a good policy under an operator stop"
run 4 4 2m; code 4 1; expect "$OUT/report-4.json" "operator stop" 4
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 3 --reason "incident closed" --out /root/stop.json > /dev/null
cp /root/stop.json "$OUT/stop-3.json"

step "5/8 a policy pinning another machine as the standby (the primary's measurement): the chip verifies, the release is denied on the record"
issue 5 "$PMEAS" "negatives drill 5/8: the standby pinned is another machine"
run 5 5 2m; code 5 1; expect "$OUT/report-5.json" "releases only to its standby" 5

step "6/8 a good policy, the newest bundle corrupted in the replica: generation 1 set aside on the record, generation 0 restored"
cp "$REPLICA/gen-000001.genome" /root/gen-000001.genome.orig
python3 - <<PY
p="$REPLICA/gen-000001.genome"
b=bytearray(open(p,"rb").read()); i=len(b)//2; b[i]^=0x01; open(p,"wb").write(b)
PY
{ echo "before: $(sha256sum /root/gen-000001.genome.orig | cut -d' ' -f1)"; echo "after:  $(sha256sum "$REPLICA/gen-000001.genome" | cut -d' ' -f1)"; echo "one byte, at the middle of the bundle, flipped"; } > "$OUT/tamper.txt"
issue 6 "$MEAS" "negatives drill 6/8: the move, with the newest bundle corrupted in the replica"
run 6 6 15m; code 6 0; expect "$OUT/report-6.json" '"status": "restored"' 6; expect "$OUT/report-6.json" "hashes to" 6
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); g=r["genome"]["generation"]; assert g==0, g; print("restored generation", g, "gate", r["restore"]["gate"]["level"])' "$OUT/report-6.json" >> "$OUT/steps.txt"
KID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["genome"]["key_id"])' "$OUT/report-6.json")
head -c 200 "/root/restored/$KID/adapter/adapter_model.safetensors" > "$OUT/restored-adapter-head.txt" 2>/dev/null || true
ls -la /root/restored/"$KID" > "$OUT/restored-ls.txt" 2>/dev/null || true

step "7/8 the spent policy again: refused at the door"
run 7 6 2m; code 7 1; expect "$OUT/failover-7.log" "already carried out a failover" 7

step "8/8 a policy signed by a stranger: refused at the door"
acpctl stop keygen --out /root/stranger.seed --pub /root/stranger.pem > /dev/null
acpctl failover issue --key /root/stranger.seed --kid operator-1 --serial 7 \
  --sentinel-pub /root/sentinel.pem --primary-kind gcp-sev-snp --primary-measurement "$PMEAS" \
  --standby-kind gcp-sev-snp --standby-endpoint https://127.0.0.1:8443 --standby-measurement "$MEAS" \
  --require-gate EQUIVALENT --reason "negatives drill 8/8: a stranger's signature" --out /root/policy-7.json > "$OUT/policy-7-issue.txt"
cp /root/policy-7.json "$OUT/policy-7.json"
acpctl failover verify --in /root/policy-7.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/policy-7-verify.txt" 2>&1 || echo "(verify under the operator's key refuses it, as it should: exit $?)" >> "$OUT/policy-7-verify.txt"
run 8 7 2m; code 8 1
rm -f /root/stranger.seed

step "audit log verify (offline, as an auditor would), and every event"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["audit_public_key_pem"],end="")' "$OUT/authority-identity.json" > /root/audit.pem
acpctl audit verify --audit /root/xcc-audit.db --audit-pubkey /root/audit.pem --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2>&1 || true
acpctl audit query --audit /root/xcc-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2>/dev/null || true
for f in /root/vcek-cache/*; do [ -f "$f" ] && cp "$f" "$OUT/cache-vcek-$(basename "$f")"; done
/opt/vg/bin/pip freeze > "$OUT/pip-freeze.txt" 2>/dev/null || true

trap - ERR
finish DONE
