#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The negatives drill: the failover drill's two machines, and an authority
# that is asked eight times and says no seven times — every refusal for a
# different reason, every one that the policy engine decides on the audit
# record — and moves the model once, to the newest state whose bytes match
# the sentinel's signed word.
#
#   PRIMARY  GCP n2d SEV-SNP (scripts/hardware-test/gcp-failover/primary.sh,
#            unchanged): fine-tunes Qwen2.5-0.5B, the sentinel seals two
#            generations with the chip's report on every record, then it
#            is attacked and reports.
#   STANDBY  GCP n2d SEV-SNP (standby-negatives.sh): the release authority
#            (sagvd failover, escrow key sealed to its chip) and the
#            destination (acp-bootstrap) on loopback TLS. Against the one
#            compromise report it runs, in order: a policy that expired
#            while it watched; a policy whose RPO bound the genome misses;
#            a policy whose quarantine covers every genome; a good policy
#            under an operator stop; a policy pinning another machine as
#            the standby; a good policy with the newest bundle corrupted in
#            the replica — the one move, to the generation before; the
#            spent policy again; a policy signed by a stranger.
#
# Usage: run.sh <gcp-project> [zone]. Builds, uploads, boots the two
# Confidential VMs, waits, collects both sides' results into
# evidence/<stamp>/ and deletes everything, on success or failure.
set -euo pipefail
PROJECT="${1:?usage: run.sh <gcp-project> [zone]}"
ZONE="${2:-europe-west4-a}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
FAILOVER="$ROOT/scripts/hardware-test/gcp-failover"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
PRIMARY="vg-neg-primary-$LOW"
STANDBY="vg-neg-standby-$LOW"
BUCKET="$PROJECT-vg-neg-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
CREATED=0

cleanup() {
  if [ "$CREATED" = 1 ]; then
    echo "cleanup: deleting $PRIMARY, $STANDBY and gs://$BUCKET"
    for n in "$PRIMARY" "$STANDBY"; do z="$(cat "$BUILD/zone.$n" 2>/dev/null)"; [ -n "$z" ] && gcloud compute instances delete "$n" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true; done
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
collect() { # collect <leg>
  mkdir -p "$EVIDENCE/$1"
  gcloud storage cp "gs://$BUCKET/out/$1.tgz" "$BUILD/$1.tgz" --project "$PROJECT" >/dev/null 2>&1 && tar -C "$EVIDENCE/$1" -xzf "$BUILD/$1.tgz" || echo "no $1.tgz"
  ls "$EVIDENCE/$1" 2>/dev/null || true
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
ZONES=("$ZONE" europe-west4-a europe-west4-b europe-west4-c us-central1-c us-central1-a us-central1-b us-east4-c)
boot() { # boot <name> <machine-type> <startup script> <zones...>
  local name="$1" mt="$2" script="$3"; shift 3
  local z round
  for round in $(seq 1 20); do
    for z in "$@"; do
      if gcloud compute instances create "$name" --project "$PROJECT" --zone "$z" --machine-type "$mt" --min-cpu-platform "AMD Milan" \
          --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
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
echo "boot the STANDBY $STANDBY (SEV-SNP authority + destination) and the PRIMARY $PRIMARY (SEV-SNP workload + sentinel)"
boot "$STANDBY" n2d-standard-4 "$HERE/standby-negatives.sh" "${ZONES[@]}"; CREATED=1
boot "$PRIMARY" n2d-standard-8 "$FAILOVER/primary.sh" "${ZONES[@]}"

echo "waiting for the primary (up to 45 min) and the standby's eight runs (up to 30 min)"
PRIMARY_RESULT=$(wait_marker primary 45); echo "primary: $PRIMARY_RESULT"
STANDBY_RESULT=$(wait_marker standby 30); echo "standby: $STANDBY_RESULT"

echo "collect"
collect primary
collect standby
[ "$PRIMARY_RESULT" = DONE ] || { echo "the primary did not finish cleanly"; exit 1; }
[ "$STANDBY_RESULT" = DONE ] || { echo "the standby did not finish its runs"; exit 1; }
echo "evidence: $EVIDENCE"
