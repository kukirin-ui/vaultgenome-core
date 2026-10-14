#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for the AUTHORITY, a GCP AMD SEV-SNP Confidential VM: the
# release authority of the failover drill (sagvd failover, attesting with
# this chip, its escrow key sealed to this chip), whose one standby is an
# Intel TDX Trust Domain — acp-bootstrap on a GCP c3 TDX VM, attesting as
# gcp-tdx, reached over the VPC with mTLS. It publishes its escrow key for
# the primary's sentinel and its TLS material for the destination, waits
# for the primary's identity and the destination's identity, signs a
# policy pinning both, arms, and when the primary reports its compromise
# it releases the last trustworthy genome's key to the attested Trust
# Domain. Reports and logs go to out/authority/; keys stay here.
set -u
exec > >(tee -a /root/authority.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; REPLICA=/root/replica; mkdir -p "$OUT" "$REPLICA" /root/vcek-cache /root/pcs-cache; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
finish() {
  cp /root/authority.log "$OUT/console.log" 2>/dev/null || true
  cp /root/failover.log "$OUT/failover.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out/authority.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/authority/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
for b in sagvd acpctl keygen; do gcs_get "in/$b" "/usr/local/bin/$b" && chmod +x "/usr/local/bin/$b"; done
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; echo "external_ip=$(md network-interfaces/0/access-configs/0/external-ip)"; } > "$OUT/metadata.txt"
{ uname -a; lscpu | head -20; } > "$OUT/system.txt" 2>&1

step "provision (keygen), operator stop key, operator recovery key"
keygen -out /root/secrets -quiet
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'); printf '%s\n' "$TOKEN" > /root/secrets/xcc_token; chmod 600 /root/secrets/xcc_token
acpctl stop keygen --out /root/operator.seed --pub /root/operator.pem > /dev/null
acpctl stop issue --key /root/operator.seed --kid operator-1 --serial 1 --out /root/stop.json > /dev/null
acpctl escrow recovery-keygen --out /root/recovery.seed --pub /root/recovery.pem > "$OUT/recovery-keygen.txt"
S=/root/secrets

step "configfs-tsm (real SEV-SNP reports)"
modprobe sev-guest 2>/dev/null || {
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
  modprobe sev-guest 2>/dev/null || true
}
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/sev-guest 2>&1; dmesg | grep -i -E "sev|snp|tsm" | tail; } > "$OUT/tsm.txt" 2>&1

step "sagvd on SEV-SNP: identity from the chip; the escrow key sealed to it"
head -c 48 /dev/zero > /root/peer.meas
python3 - <<PY
import json
S="$S"
c={"vault":{"listen_address":"127.0.0.1:9443","tls":{"enabled":True,"server_cert":S+"/sagvd/tls/server.crt","server_key":S+"/sagvd/tls/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "http_api":{"listen_address":"127.0.0.1:9080","bearer_token_file":S+"/sagvd/api_token"},
 "tee":{"provider":"gcp-sev-snp","workload_descriptor":"sagvd-failover-authority-v1",
        "peer":{"provider":"gcp-sev-snp","measurement_path":"/root/peer.meas","amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}},
 "keys":{"authority_signing":{"kid":"sagvd-authority-demo","seed_path":S+"/sagvd/authority_signing_seed"},
         "audit_signing":{"kid":"sagvd-audit-demo","seed_path":S+"/sagvd/audit_signing_seed"},
         "session_sealing":{"kid":"session-sealing-demo","material_path":S+"/shared/sealing.key"}},
 "workers":{"registry_path":S+"/shared/workers.json"},
 "health":{"listen_address":"127.0.0.1:9081"},"log":{"level":"info","format":"json"}}
json.dump(c,open("/root/sagvd-base.json","w"),indent=2)
PY
gcs_get in/amd-milan-cert_chain.pem /root/amd-milan-cert_chain.pem
# The key files the config names — the authority's signing seed, the audit
# seed, the session sealing key — sealed to this host's TEE in place (ADR
# 0023); every sagvd from here on reads them sealed.
# The destination's copies of the TLS pair, the CA and the token are taken
# before sagvd seals its own files (ADR 0023); the destination seals them there.
mkdir -p "$S/dest" && cp "$S/sagvd/tls/server.crt" "$S/sagvd/tls/server.key" "$S/shared/tls/ca.crt" "$S/xcc_token" "$S/dest/"
sagvd seal-keys -config /root/sagvd-base.json > "$OUT/seal-keys.json" 2> "$OUT/seal-keys.err"
echo "seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
sagvd identity -config /root/sagvd-base.json > /root/identity-0.json 2> "$OUT/identity-0.err"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); open("/root/peer.meas","wb").write(bytes.fromhex(d["tee_measurement_hex"]))' /root/identity-0.json
sagvd escrow-provision -config /root/sagvd-base.json -out /root/escrow.sealed -pub /root/escrow.pem -recovery-to /root/recovery.pem -recovery-out /root/escrow.recovery.json > "$OUT/escrow-provision.json" 2> "$OUT/escrow-provision.err"
echo "escrow-provision exit=$?" >> "$OUT/steps.txt"
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authority_public_key_pem"], end="")' /root/identity-0.json > /root/authority.pem

step "hand the primary the escrow key, and the destination its TLS material and token (through the private bucket)"
gcs_put /root/escrow.pem handoff/escrow.pem
gcs_put /root/authority.pem handoff/authority.pem
for f in server.crt server.key ca.crt xcc_token; do gcs_put "$S/dest/$f" "handoff/dest/$f"; done

step "wait for the destination's identity (published by the Trust Domain itself): endpoint, TDX measurement"
for i in $(seq 1 240); do gcs_get handoff/destination.json /root/destination.json 2>/dev/null && break; sleep 10; done
[ -s /root/destination.json ] || { echo "no destination hand-off after 40 minutes"; false; }
cp /root/destination.json "$OUT/destination-handoff.json"
DEST_ENDPOINT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["endpoint"])' /root/destination.json)
DMEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' /root/destination.json)
echo "destination endpoint=$DEST_ENDPOINT measurement=$DMEAS" >> "$OUT/steps.txt"

step "wait for the primary's sentinel key and chip identity (the operator pins both)"
for i in $(seq 1 480); do gcs_get handoff/sentinel-identity.json /root/sentinel-identity.json 2>/dev/null && gcs_get handoff/sentinel.pem /root/sentinel.pem 2>/dev/null && break; sleep 5; done
[ -s /root/sentinel.pem ] && [ -s /root/sentinel-identity.json ] || { echo "no sentinel identity after 40 minutes"; false; }
cp /root/sentinel-identity.json "$OUT/primary-identity.json"
PMEAS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measurement_hex"])' /root/sentinel-identity.json)
echo "primary measurement=$PMEAS" >> "$OUT/steps.txt"
step "sagvd failover config: the gcp-tdx destination in the registry (Intel PCS for the TCB and QE identity, the pinned Intel root) and the primary's SEV-SNP anchors, the allow-list, the operator stop, the sealed escrow key, mTLS to the destination"
python3 - <<PY
import json
S="$S"; DMEAS="$DMEAS"; PMEAS="$PMEAS"
entry={"provider":"gcp-tdx","expected_measurement_hex":DMEAS,"pcs_cache_dir":"/root/pcs-cache"}
# the primary's anchors: the executor verifies the primary's SEV-SNP reports (ADR 0017) with the registry's gcp-sev-snp entry,
# the policy's pinned measurements replacing this expected one
primary={"provider":"gcp-sev-snp","expected_measurement_hex":PMEAS,"amd_cert_chain_path":"/root/amd-milan-cert_chain.pem","vcek_cache_dir":"/root/vcek-cache"}
json.dump({"verifiers":[entry,primary]},open("/root/verifiers.json","w"),indent=2)
json.dump({"version":"failover-policy-v1","allowed":{"gcp-tdx":[DMEAS]}},open("/root/allow.json","w"))
c=json.load(open("/root/sagvd-base.json"))
c["crosscloud"]={"enabled":True,"policy_version":"failover-policy-v1","audit_log_path":"/root/xcc-audit.db",
 "operator_stop":{"kid":"operator-1","public_key_path":"/root/operator.pem","list_path":"/root/stop.json"},
 "key_escrow_path":"/root/escrow.sealed",
 "policy_allow_list_path":"/root/allow.json","verifier_registry_path":"/root/verifiers.json",
 "transport_bearer_token":open(S+"/xcc_token").read().strip(),"request_timeout_seconds":120,
 "transport_tls":{"enabled":True,"client_cert":S+"/acp-compute/tls/client.crt","client_key":S+"/acp-compute/tls/client.key","ca_bundle":S+"/shared/tls/ca.crt","server_name":"localhost"}}
json.dump(c,open("/root/sagvd.json","w"),indent=2)
PY
# The failover config names the cross-cloud transport's client key: sealed
# now, in place (seal-keys skips what the base config's run sealed).
sagvd seal-keys -config /root/sagvd.json > "$OUT/seal-keys-2.json" 2> "$OUT/seal-keys-2.err"
echo "seal-keys (failover config) exit=$? sealed=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(",".join(e["name"] for e in d["sealed"]))' "$OUT/seal-keys-2.json" 2>/dev/null) already=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d.get("already_sealed",[])))' "$OUT/seal-keys-2.json" 2>/dev/null)" >> "$OUT/steps.txt"
cp /root/verifiers.json "$OUT/verifiers.json"; cp /root/allow.json "$OUT/allow.json"
sagvd identity -config /root/sagvd.json > "$OUT/authority-identity.json" 2>> "$OUT/authority-identity.err"
echo "sagvd identity exit=$? key_escrow_storage=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("key_escrow_storage"))' "$OUT/authority-identity.json")" >> "$OUT/steps.txt"

step "sign the failover policy pinning the primary's chip and the TDX standby"
acpctl failover issue --key /root/operator.seed --kid operator-1 --serial 1 \
  --sentinel-pub /root/sentinel.pem --primary-kind gcp-sev-snp --primary-measurement "$PMEAS" \
  --standby-kind gcp-tdx --standby-endpoint "$DEST_ENDPOINT" \
  --standby-measurement "$DMEAS" --heartbeat-timeout 120s --stopped-grace 60s --require-gate EQUIVALENT \
  --reason "failover drill: a SEV-SNP primary on GCP fails over to an attested Intel TDX Trust Domain" --out /root/failover.json > "$OUT/failover-issue.txt"
acpctl failover verify --in /root/failover.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/failover-verify.txt"
cp /root/failover.json "$OUT/failover-policy.json"

step "pull the primary's outbox replica, continuously"
( while true; do pull_outbox "$REPLICA"; sleep 3; done ) &
PULL=$!

step "arm: sagvd failover watches the replica; the standby is the Trust Domain across the VPC"
gcs_put_str handoff/armed "armed at $(date -u +%H:%M:%SZ)"
mark armed
set +e
sagvd failover -config /root/sagvd.json -policy /root/failover.json -outbox "$REPLICA" \
  -poll 2s -confirm-wait 20m -report "$OUT/report.json" > /root/failover.log 2>&1
FCODE=$?
set -e
mark failover_exit
echo "sagvd failover exit=$FCODE" >> "$OUT/steps.txt"
kill "$PULL" 2>/dev/null || true

step "audit log verify (offline, as an auditor would)"
python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["audit_public_key_pem"],end="")' "$OUT/authority-identity.json" > /root/audit.pem
acpctl audit verify --audit /root/xcc-audit.db --audit-pubkey /root/audit.pem --audit-kid sagvd-audit-demo --json > "$OUT/audit-verify.json" 2>&1 || true
acpctl audit query --audit /root/xcc-audit.db --limit 0 --json > "$OUT/audit-events.jsonl" 2>/dev/null || true
for f in /root/vcek-cache/*; do [ -f "$f" ] && cp "$f" "$OUT/cache-vcek-$(basename "$f")"; done
for f in /root/pcs-cache/*; do [ -f "$f" ] && cp "$f" "$OUT/cache-pcs-$(basename "$f")"; done
[ "$FCODE" = 0 ] || { echo "sagvd failover exited $FCODE"; false; }

trap - ERR
finish DONE
