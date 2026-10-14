#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The TDX-authority drill's AUTHORITY: an Intel TDX Trust Domain that runs
# sagvd failover attesting as gcp-tdx. TDX gives a guest no sealing key,
# so the escrow key — made inside sagvd's process — is sealed to the
# guest's vTPM under a policy only this boot's PCRs satisfy (ADR 0022),
# and the operator's recovery ceremony re-seals it once to prove the way
# back. The rest is the TDX drill's authority: the primary's SEV-SNP
# anchors and the TDX standby in the registry, a signed policy pinning
# both, the failover across the VPC, the audit log verified offline.
# Reports and logs go to out/authority/; keys stay here.
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

step "the Trust Domain: configfs-tsm (tdx_guest), and its vTPM (tpm2-tools)"
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
n=0; while [ ! -d /sys/kernel/config/tsm/report ] && [ $n -lt 30 ]; do sleep 1; n=$((n+1)); done
{ ls -la /sys/kernel/config/tsm/report 2>&1; ls -la /dev/tdx_guest 2>&1; grep -m1 'model name' /proc/cpuinfo; dmesg | grep -i -E "tdx|tsm" | head -20; } > "$OUT/tsm.txt" 2>&1
# apt at boot: cloud-init and unattended-upgrades may hold the lock, and
# the lists may be stale — update, then retry until tpm2-tools are there.
export DEBIAN_FRONTEND=noninteractive
for i in $(seq 1 12); do
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq tpm2-tools >/dev/null 2>&1 && break
  sleep 15
done
command -v tpm2_createprimary >/dev/null || { echo "tpm2-tools did not install"; false; }
{ ls -la /dev/tpm0 /dev/tpmrm0 2>&1; dmesg | grep -iE "tpm" | head -5; tpm2_getcap properties-fixed 2>&1 | grep -A1 -E "TPM2_PT_MANUFACTURER|TPM2_PT_VENDOR_STRING_1|TPM2_PT_FIRMWARE_VERSION_1" | head -8; } > "$OUT/vtpm.txt" 2>&1
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14 > "$OUT/vtpm-pcrs.txt" 2>&1 || true

step "sagvd on TDX: identity from the Trust Domain; the escrow key sealed to the guest's vTPM"
head -c 48 /dev/zero > /root/peer.meas
python3 - <<PY
import json
S="$S"
c={"vault":{"listen_address":"127.0.0.1:9443","tls":{"enabled":True,"server_cert":S+"/sagvd/tls/server.crt","server_key":S+"/sagvd/tls/server.key","client_cas":S+"/shared/tls/ca.crt"}},
 "http_api":{"listen_address":"127.0.0.1:9080","bearer_token_file":S+"/sagvd/api_token"},
 "tee":{"provider":"gcp-tdx","workload_descriptor":"sagvd-failover-authority-v1",
        "peer":{"provider":"gcp-tdx","measurement_path":"/root/peer.meas","pcs_cache_dir":"/root/pcs-cache"}},
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
# The file on disk is a vTPM-sealed blob, not a key: its shape, without its bytes.
python3 - > "$OUT/escrow-sealed-shape.txt" 2>&1 <<SHAPE
import json,base64
d=json.load(open("/root/escrow.sealed")); inner=json.loads(base64.b64decode(d["sealed"]))
print({"tee":d.get("tee"),"schema":inner.get("schema"),"pcrs":inner.get("pcrs"),"public_bytes":len(base64.b64decode(inner["public"])),"private_bytes":len(base64.b64decode(inner["private"])),"box_bytes":len(base64.b64decode(inner["box"]))})
SHAPE

step "the recovery ceremony on TDX: the envelope opened with the recovery key, the key re-sealed to this vTPM"
acpctl escrow recover --in /root/escrow.recovery.json --key /root/recovery.seed 2> "$OUT/escrow-recover.err" \
  | sagvd escrow-provision -config /root/sagvd-base.json -out /root/escrow-2.sealed -pub /root/escrow-2.pem -stdin > "$OUT/escrow-reprovision.json" 2> "$OUT/escrow-reprovision.err"
echo "escrow re-provision exit=$? re-provisioned escrow_key=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-reprovision.json") source=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["source"])' "$OUT/escrow-reprovision.json") (want $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["escrow_key"])' "$OUT/escrow-provision.json"))" >> "$OUT/steps.txt"

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
  --reason "TDX-authority drill: an authority on Intel TDX, its key in its vTPM, moves a SEV-SNP primary model to a Trust Domain" --out /root/failover.json > "$OUT/failover-issue.txt"
acpctl failover verify --in /root/failover.json --pubkey /root/operator.pem --kid operator-1 > "$OUT/failover-verify.txt"
cp /root/failover.json "$OUT/failover-policy.json"

step "pull the primary's outbox replica, continuously"
( while true; do pull_outbox "$REPLICA"; sleep 3; done ) &
PULL=$!

step "arm: sagvd failover (on TDX, its escrow key unsealed from the vTPM) watches the replica; the standby is the Trust Domain across the VPC"
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
