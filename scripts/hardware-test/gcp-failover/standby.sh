#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The failover drill's STANDBY: an AMD SEV-SNP Confidential VM that hosts
# both the release authority (sagvd failover, attesting with this chip) and
# the destination (acp-bootstrap), on loopback TLS. The authority makes its
# escrow key inside its own process and writes it only sealed to this
# chip (sagvd escrow-provision, ADR 0016), wraps it to the operator's
# recovery key, and hands the public half to the primary. It pulls the
# primary's outbox replica from a bucket, and — under an operator-signed
# failover policy that pins the primary's SEV-SNP measurement (ADR 0017) —
# waits. When the primary's sentinel reports a compromise, with its chip's
# report on the record, the authority releases the last trustworthy
# genome's escrowed key to acp-bootstrap (attested with this chip), which
# restores it, proves the model works and signs a receipt; the authority
# confirms it. Then the negative check: a rogue sentinel with the stolen
# seed, attesting with the wrong chip, moves nothing. Reports go to
# out/standby/.
set -u
exec > >(tee -a /root/standby.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; REPLICA=/root/replica; WORK=/root; mkdir -p "$OUT" /opt/worker "$REPLICA"; cd "$WORK"
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/standby.log "$OUT/console.log" 2>/dev/null || true
  cp /root/acp-bootstrap.log "$OUT/acp-bootstrap.log" 2>/dev/null || true
  cp /root/failover.log "$OUT/failover.log" 2>/dev/null || true
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

step "provision (keygen), operator stop key, operator recovery key"
keygen -out /root/secrets -quiet
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN" > /root/secrets/xcc_token; chmod 600 /root/secrets/xcc_token
acpctl stop keygen --out /root/operator.seed --pub /root/operator.pem > /dev/null
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 1 --out /root/stop.json > /dev/null
# The operator's recovery key: in production it lives off the release
# host; the drill keeps it here to exercise the ceremony end to end.
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
# The authority attests with this chip. It has no worker here; the peer
# pin the config requires is filled with this guest's own measurement once
# the chip has been read.
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
ESCROW_TAG=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-provision.json")
echo "escrow_key=$ESCROW_TAG sealed to $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["tee"])' "$OUT/escrow-provision.json")" >> "$OUT/steps.txt"
# The file on disk is a sealed blob, not a key: its shape, without its bytes.
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print({k:(v if k!="sealed" else "<%d bytes>"%len(v)) for k,v in d.items() if k!="public_key_pem"})' /root/escrow.sealed > "$OUT/escrow-sealed-shape.txt"
gcs_put /root/escrow-local.pem handoff/escrow.pem

step "the recovery ceremony: the envelope opened with the recovery key, the key re-sealed on this chip"
acpctl escrow recover --in /root/escrow.recovery --key /root/recovery.seed 2> "$OUT/escrow-recover.err" \
  | sagvd escrow-provision -config /root/sagvd-base.json -out /root/escrow-2.sealed -pub /root/escrow-2.pem -stdin > "$OUT/escrow-reprovision.json" 2> "$OUT/escrow-reprovision.err"
echo "escrow re-provision exit=$?" >> "$OUT/steps.txt"
echo "re-provisioned escrow_key=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-reprovision.json") source=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source"])' "$OUT/escrow-reprovision.json") (want $ESCROW_TAG)" >> "$OUT/steps.txt"

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
sagvd identity -config /root/sagvd.json > "$OUT/authority-identity.json" 2>> "$OUT/authority-identity.err"
echo "sagvd identity exit=$? key_escrow_storage=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("key_escrow_storage"))' "$OUT/authority-identity.json")" >> "$OUT/steps.txt"

step "wait for the primary's sentinel key and chip identity, then sign the failover policy pinning both"
for i in $(seq 1 480); do gcs_get handoff/sentinel-identity.json /root/sentinel-identity.json 2>/dev/null && gcs_get handoff/sentinel.pem /root/sentinel.pem 2>/dev/null && break; sleep 5; done
[ -s /root/sentinel.pem ] && [ -s /root/sentinel-identity.json ] || { echo "no sentinel identity after 40 minutes"; false; }
cp /root/sentinel-identity.json "$OUT/primary-identity.json"
PMEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' /root/sentinel-identity.json)
echo "primary measurement=$PMEAS" >> "$OUT/steps.txt"
acpctl failover issue --key /root/operator.seed --kid operator-1 --serial 1 \
  --sentinel-pub /root/sentinel.pem --primary-kind gcp-sev-snp --primary-measurement "$PMEAS" \
  --standby-kind gcp-sev-snp --standby-endpoint https://127.0.0.1:8443 \
  --standby-measurement "$MEAS" --heartbeat-timeout 120s --stopped-grace 60s --require-gate EQUIVALENT \
  --reason "hardware failover drill" --out /root/failover.json > "$OUT/failover-issue.txt"
acpctl failover verify --in /root/failover.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/failover-verify.txt"

step "pull the primary's outbox replica, continuously"
( while true; do pull_outbox "$REPLICA"; sleep 3; done ) &
PULL=$!

step "arm: sagvd failover watches the replica"
gcs_put_str handoff/armed "armed at $(date -u +%H:%M:%SZ)"
set +e
sagvd failover -config /root/sagvd.json -policy /root/failover.json -outbox "$REPLICA" \
  -poll 2s -confirm-wait 15m -report "$OUT/report.json" > /root/failover.log 2>&1
FCODE=$?
set -e
echo "sagvd failover exit=$FCODE" >> "$OUT/steps.txt"
kill "$PULL" 2>/dev/null || true

step "audit log verify (offline, as an auditor would)"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["audit_public_key_pem"],end="")' "$OUT/authority-identity.json" > /root/audit.pem
acpctl audit verify --audit /root/xcc-audit.db --audit-pubkey /root/audit.pem --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2>&1 || true

# The restored adapter, to show it is the clean generation and not the
# planted one (its bytes only; nothing secret).
KID=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["genome"]["key_id"])
except Exception: print("")' "$OUT/report.json" 2>/dev/null)
[ -n "$KID" ] && head -c 200 "/root/restored/$KID/adapter/adapter_model.safetensors" > "$OUT/restored-adapter-head.txt" 2>/dev/null || true
[ "$FCODE" = 0 ] || { echo "sagvd failover exited $FCODE"; false; }

step "NEGATIVE: the sentinel seed stolen, off the primary's chip"
# The thief copies the outbox to a machine of their own — this one — drops
# the compromise report, and runs a sentinel there with the stolen seed,
# attesting with this chip: real SEV-SNP reports, from the wrong machine.
# A second policy pins the primary as before, acts on lost heartbeats only
# and quarantines a day, and watches the thief's outbox: the rogue's
# records must be ignored, the silence after the primary's last genuine
# word must be the trigger, nothing past that word trusted, and the
# decision declined on the record. No key moves.
gcs_get handoff/sentinel.seed /root/stolen.seed && chmod 600 /root/stolen.seed
rm -rf /root/rogue-outbox && mkdir -p /root/rogue-outbox
cp "$REPLICA"/* /root/rogue-outbox/ 2>/dev/null || true
rm -f /root/rogue-outbox/compromise.json /root/rogue-outbox/.*.tmp
acpctl failover issue --key /root/operator.seed --kid operator-1 --serial 2 \
  --sentinel-pub /root/sentinel.pem --primary-kind gcp-sev-snp --primary-measurement "$PMEAS" \
  --standby-kind gcp-sev-snp --standby-endpoint https://127.0.0.1:8443 \
  --standby-measurement "$MEAS" --no-compromise-trigger --heartbeat-timeout 30s --quarantine 24h --require-gate EQUIVALENT \
  --reason "negative check: a stolen seed off the pinned chip" --out /root/failover-2.json > "$OUT/failover-2-issue.txt"
acpctl failover verify --in /root/failover-2.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/failover-2-verify.txt"
set +e
sagvd failover -config /root/sagvd.json -policy /root/failover-2.json -outbox /root/rogue-outbox \
  -poll 2s -confirm-wait 2m -report "$OUT/rogue-report.json" > /root/rogue-failover.log 2>&1 &
SECOND=$!
n=0; until grep -q '"state":"watching"' /root/rogue-failover.log || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "second executor watching the genuine heartbeat after ${n}s" >> "$OUT/steps.txt"
# The thief's state: the restored model, one file changed, sealed as a
# generation 2 of the stolen chain.
rm -rf /root/thief && cp -r "/root/restored/$KID" /root/thief && echo "weights of the thief" >> /root/thief/adapter/adapter_model.safetensors
acpctl sentinel watch --content-dir /root/thief --outbox /root/rogue-outbox \
  --escrow-to /root/escrow-local.pem --key /root/stolen.seed --tee gcp-sev-snp \
  --interval 3s --settle 0s > "$OUT/rogue-sentinel.json" 2> "$OUT/rogue-sentinel.log" &
ROGUE=$!
RCODE=0; wait "$SECOND" || RCODE=$?   # a || list: the expected exit 3 must not fire the ERR trap
set -e
kill "$ROGUE" 2>/dev/null || true; wait "$ROGUE" 2>/dev/null || true
cp /root/rogue-failover.log "$OUT/rogue-failover.log" 2>/dev/null || true
ls /root/rogue-outbox > "$OUT/rogue-outbox.txt" 2>/dev/null || true
echo "rogue: sagvd failover exit=$RCODE (want 3: declined) status=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$OUT/rogue-report.json" 2>/dev/null)" >> "$OUT/steps.txt"
rm -f /root/stolen.seed
[ "$RCODE" = 3 ] || { echo "the rogue outbox was not declined (exit $RCODE)"; false; }

step "NEGATIVE: the sentinel's sealed seed file, off the primary's chip"
# The file the sentinel actually runs from is sealed to the primary's chip
# (acpctl sentinel seal-key, ADR 0023). Here — a real SEV-SNP chip, the
# wrong one — it does not open: the thief who takes the file takes nothing.
gcs_get handoff/sentinel.sealed /root/stolen.sealed && chmod 600 /root/stolen.sealed
SCODE=0; acpctl sentinel identity --tee gcp-sev-snp --key /root/stolen.sealed > "$OUT/stolen-sealed-identity.json" 2> "$OUT/stolen-sealed-identity.err" || SCODE=$?   # a || list: the ERR trap must not fire
echo "stolen sealed seed: acpctl sentinel identity exit=$SCODE (want 2: does not open off the primary's chip): $(tr -d '\n' < "$OUT/stolen-sealed-identity.err" | cut -c1-220)" >> "$OUT/steps.txt"
rm -f /root/stolen.sealed
[ "$SCODE" = 2 ] || { echo "the sealed seed opened off the primary's chip (exit $SCODE)"; false; }

trap - ERR
finish DONE
