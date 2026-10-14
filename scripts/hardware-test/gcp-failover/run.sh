#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Continuity Drill's failover leg, on real hardware, across two AMD
# SEV-SNP Confidential VMs:
#
#   1. builds sagvd, acp-bootstrap, acpctl and keygen for linux/amd64, and
#      packs workers/genome;
#   2. boots the STANDBY (standby.sh): the release authority and the
#      destination, on loopback TLS. It publishes its escrow key, and under
#      an operator-signed failover policy it waits, watching a replica of
#      the primary's outbox;
#   3. boots the PRIMARY (primary.sh): it fine-tunes a real model, the
#      sentinel seals each state with its key escrowed to the authority, and
#      the outbox is replicated to a bucket. Then the machine is attacked —
#      a tripwire fires, the sentinel reports the compromise and exits;
#   4. the authority fails the last trustworthy genome over to the standby,
#      which restores it, proves the model works (its gate) and signs a
#      receipt the authority confirms;
#   5. brings the reports back to evidence/<stamp>/ and deletes both VMs and
#      the bucket — always, also on failure.
#
# Both machines are confidential VMs and attest with their own chip; the
# genome key crosses only as an escrow envelope opened by the authority and
# re-wrapped to the standby's attested per-handshake key (ADR 0009, 0011,
# 0012). Cost: an n2d-standard-8 and an n2d-standard-4 SEV-SNP VM for about
# half an hour.
#
# Usage: run.sh <project> [zone]
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-c}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
PRIMARY="vg-failover-primary-$LOW"
STANDBY="vg-failover-standby-$LOW"
BUCKET="$PROJECT-vg-failover-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
CHAIN="$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem"

cleanup() {
  echo "cleanup: deleting $PRIMARY, $STANDBY and gs://$BUCKET"
  gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud compute instances delete "$STANDBY" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

# wait_for <leg> <minutes>: DONE, FAILED or TIMEOUT.
wait_for() {
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do
      if gcloud storage ls "gs://$BUCKET/out/$1/$m" --project "$PROJECT" >/dev/null 2>&1; then echo "$m"; return; fi
    done
    sleep 20
  done
  echo TIMEOUT
}

collect() {
  mkdir -p "$EVIDENCE/$1"
  if gcloud storage cp "gs://$BUCKET/out/$1.tgz" "$BUILD/$1.tgz" --project "$PROJECT" >/dev/null 2>&1; then
    tar -C "$EVIDENCE/$1" -xzf "$BUILD/$1.tgz" || true
  fi
  ls "$EVIDENCE/$1" 2>/dev/null || true
}

echo "build sagvd, acp-bootstrap, acpctl, keygen (linux/amd64) and pack workers/genome"
( cd "$ROOT" && for b in sagvd acp-bootstrap acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
cp "$CHAIN" "$BUILD/amd-milan-cert_chain.pem"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/sagvd" "$BUILD/acp-bootstrap" "$BUILD/acpctl" "$BUILD/keygen" \
  "$BUILD/amd-milan-cert_chain.pem" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

boot() { # boot <name> <machine-type> <startup script>
  gcloud compute instances create "$1" --project "$PROJECT" --zone "$ZONE" \
    --machine-type "$2" --min-cpu-platform "AMD Milan" \
    --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
    --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 40GB \
    --scopes storage-rw --metadata "vg-bucket=$BUCKET" \
    --metadata-from-file "vg-common=$HERE/common.sh,startup-script=$3" >/dev/null
}

echo "boot $STANDBY (SEV-SNP authority + destination, $ZONE)"
boot "$STANDBY" n2d-standard-4 "$HERE/standby.sh"
echo "boot $PRIMARY (SEV-SNP workload + sentinel, $ZONE)"
boot "$PRIMARY" n2d-standard-8 "$HERE/primary.sh"

echo "waiting for the primary (up to 45 min)"
PRIMARY_RESULT=$(wait_for primary 45)
echo "primary: $PRIMARY_RESULT"
collect primary
gcloud compute instances delete "$PRIMARY" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true

echo "waiting for the standby's failover (up to 20 min)"
STANDBY_RESULT=$(wait_for standby 20)
echo "standby: $STANDBY_RESULT"
collect standby

[ "$PRIMARY_RESULT" = DONE ] || { echo "the primary did not finish cleanly"; exit 1; }
[ "$STANDBY_RESULT" = DONE ] || { echo "the standby did not finish the failover"; exit 1; }
echo "evidence: $EVIDENCE"
