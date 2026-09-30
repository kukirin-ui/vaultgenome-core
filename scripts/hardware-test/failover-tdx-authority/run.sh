#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The continuity drill with an Intel TDX Trust Domain as the RELEASE
# AUTHORITY: the escrow key made in sagvd's process and sealed to the
# guest's vTPM under a policy only this boot's PCRs satisfy (ADR 0022),
# the primary an AMD SEV-SNP VM, the standby another Trust Domain. A TDX
# host holds the key that moves the model.
#
#   PRIMARY    GCP n2d SEV-SNP (scripts/hardware-test/gcp-failover/primary.sh):
#              fine-tunes Qwen2.5-0.5B, the sentinel seals each generation
#              with its key escrowed to the authority and attests every
#              record with the chip; then it is attacked and reports.
#   AUTHORITY  GCP c3 TDX (authority-tdx.sh): sagvd failover attesting as
#              gcp-tdx, its escrow key sealed to the guest's vTPM (a PCR
#              policy of this boot), re-provisioned once through the
#              operator's recovery ceremony; a policy pinning the primary's
#              chip and the TDX standby; releases the last trustworthy
#              genome's key to the standby over mTLS across the VPC.
#   STANDBY    GCP c3 TDX (destination-tdx.sh): acp-bootstrap as gcp-tdx —
#              a TDX quote per challenge, verified by the authority to
#              Intel's root with Intel's TCB word — restores the genome and
#              gates it through the door on its CPUs; its receipt is
#              signed with that evidence.
#
# Every hand-off goes through the run's private bucket: the authority's
# escrow key to the primary, its TLS material and token to the standby, the
# standby's identity back, the primary's outbox to both. This script
# builds, uploads, boots the three machines, waits, collects every side's
# results and deletes everything. Usage: run.sh <gcp-project> [n2d-zone] [tdx-zone]
set -euo pipefail
PROJECT="${1:?usage: run.sh <gcp-project> [n2d-zone] [tdx-zone]}"
ZONE="${2:-europe-west4-a}"
TDX_ZONE="${3:-us-central1-a}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FAILOVER="$ROOT/scripts/hardware-test/gcp-failover"
TDX="$ROOT/scripts/hardware-test/failover-tdx"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
PRIMARY="vg-fota-primary-$LOW"
AUTHORITY="vg-fota-authority-$LOW"
STANDBY="vg-fota-tdx-$LOW"
BUCKET="$PROJECT-vg-fota-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
CREATED=0

cleanup() {
  # A machine that never booted has no zone file: run every step, whatever the one before returned.
  set +e
  if [ "$CREATED" = 1 ]; then
    echo "cleanup: deleting $PRIMARY, $AUTHORITY, $STANDBY and gs://$BUCKET"
    for n in "$PRIMARY" "$AUTHORITY" "$STANDBY"; do z="$(cat "$BUILD/zone.$n" 2>/dev/null)"; [ -n "$z" ] && gcloud compute instances delete "$n" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true; done
    gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  fi
  rm -rf "$BUILD"
}
trap cleanup EXIT
wait_marker() { # wait_marker <leg> <minutes>
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do gcloud storage ls "gs://$BUCKET/out/$1/$m" --project "$PROJECT" >/dev/null 2>&1 && { echo "$m"; return; }; done
    sleep 20
  done
  echo TIMEOUT
}

echo "build sagvd, acp-bootstrap, acpctl, keygen (linux/amd64); pack workers/genome"
( cd "$ROOT" && for b in sagvd acp-bootstrap acpctl; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples

echo "bucket gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/keygen" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null
gcloud storage cp "$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem" "gs://$BUCKET/in/amd-milan-cert_chain.pem" --project "$PROJECT" >/dev/null

# n2d Milan capacity comes and goes by the zone: try them in rounds.
N2D_ZONES=("$ZONE" europe-west4-a europe-west4-b europe-west4-c us-central1-c us-central1-a us-central1-b us-east4-c)
TDX_ZONES=("$TDX_ZONE" us-central1-a us-central1-b us-central1-c europe-west4-a europe-west4-b)
zone_of() { cat "$BUILD/zone.$1" 2>/dev/null; }
boot() { # boot <name> <machine-type> <confidential type> <min cpu platform> <startup script> <zones...>
  local name="$1" mt="$2" cc="$3" cpu="$4" script="$5"; shift 5
  local z round
  for round in $(seq 1 20); do
    for z in "$@"; do
      if gcloud compute instances create "$name" --project "$PROJECT" --zone "$z" --machine-type "$mt" ${cpu:+--min-cpu-platform "$cpu"} \
          --confidential-compute-type "$cc" --maintenance-policy TERMINATE --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
          --boot-disk-size 40GB --scopes storage-rw --metadata "vg-bucket=$BUCKET" --metadata-from-file "vg-common=$FAILOVER/common.sh,startup-script=$script" >/dev/null 2>"$BUILD/boot.err"; then
        echo "$z" > "$BUILD/zone.$name"; echo "$name in $z (round $round)"; return 0
      fi
      grep -q 'ZONE_RESOURCE_POOL_EXHAUSTED\|currently unavailable\|does not have enough resources' "$BUILD/boot.err" || { cat "$BUILD/boot.err"; return 1; }
      gcloud compute instances delete "$name" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true
    done
    echo "round $round: no capacity for $name in any zone; waiting 90 s"; sleep 90
  done
  echo "no capacity for $name after 20 rounds"; return 1
}
echo "boot the AUTHORITY $AUTHORITY (TDX, escrow key in its vTPM), the PRIMARY $PRIMARY (SEV-SNP) and the STANDBY $STANDBY (TDX)"
boot "$AUTHORITY" c3-standard-4 TDX "" "$HERE/authority-tdx.sh" "${TDX_ZONES[@]}"; CREATED=1
boot "$PRIMARY" n2d-standard-8 SEV_SNP "AMD Milan" "$FAILOVER/primary.sh" "${N2D_ZONES[@]}"
boot "$STANDBY" c3-standard-4 TDX "" "$TDX/destination-tdx.sh" "${TDX_ZONES[@]}"

echo "waiting for the primary (up to 45 min), the authority's failover (up to 30 min) and the standby's collection (up to 10 min)"
PRIMARY_RESULT=$(wait_marker primary 45); echo "primary: $PRIMARY_RESULT"
AUTHORITY_RESULT=$(wait_marker authority 30); echo "authority: $AUTHORITY_RESULT"
DEST_RESULT=$(wait_marker destination 10); echo "destination: $DEST_RESULT"

echo "collect"
mkdir -p "$EVIDENCE/primary" "$EVIDENCE/authority" "$EVIDENCE/destination"
for leg in primary authority destination; do
  gcloud storage cp "gs://$BUCKET/out/$leg.tgz" "$BUILD/$leg.tgz" --project "$PROJECT" >/dev/null 2>&1 && tar -C "$EVIDENCE/$leg" -xzf "$BUILD/$leg.tgz" || echo "no $leg.tgz"
done
ls "$EVIDENCE"/*
[ "$PRIMARY_RESULT" = DONE ] || { echo "the primary did not finish cleanly"; exit 1; }
[ "$AUTHORITY_RESULT" = DONE ] || { echo "the authority did not finish the failover"; exit 1; }
[ "$DEST_RESULT" = DONE ] || { echo "the destination did not finish its collection"; exit 1; }
echo "evidence: $EVIDENCE"
