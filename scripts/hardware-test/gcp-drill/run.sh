#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Continuity Drill's measurement leg on real hardware, CPU to GPU:
#
#   1. builds acpctl for linux/amd64 and packs workers/genome;
#   2. boots an AMD SEV-SNP Confidential VM (n2d, 8 vCPU) that fine-tunes
#      Qwen2.5-0.5B-Instruct deterministically inside the guest, seals the
#      genome, restores and gates it there, and hands the bundle and key
#      on through a private bucket (cvm-train.sh);
#   3. boots, first, a VM with an NVIDIA L4 (or a T4 where no L4 is free),
#      which prepares its runtime, waits for the hand-off, restores the
#      genome and measures it: the gate on the GPU and on its Intel CPU,
#      fidelity token by token, the recipe replayed on the GPU
#      (gpu-restore.sh);
#   4. brings the reports back to evidence/<stamp>/ and deletes the VMs and
#      the bucket — always, also on failure.
#
# The bundle's key crosses the bucket here: this leg measures fidelity,
# not key release (the attested release is keyrelease-e2e). The GPU VM is
# not a confidential VM; attested GPU destinations need H100 confidential
# computing. Cost: one n2d-standard-8 and one g2-standard-4 (or
# n1-standard-4 + T4) for about half an hour together.
#
# Usage: run.sh <project> [cpu-zone]
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [cpu-zone]}"
CPU_ZONE="${2:-us-central1-c}"
GPU_ZONE=""
GPU_KIND=""
# GPU capacity comes and goes by zone: try an L4 in every zone that has
# one (and GPU quota in this project), then a T4. The bucket stays in
# us-central1; a GPU VM in another region reads it just the same.
GPU_CANDIDATES=()
for z in us-east4-a us-east4-c us-east1-b us-east1-c us-east1-d us-west1-a us-west1-b us-west1-c \
         us-west4-a us-west4-c us-central1-a us-central1-b us-central1-c europe-west4-a europe-west4-b europe-west4-c; do
  GPU_CANDIDATES+=("l4 $z")
done
for z in us-east4-a us-east4-b us-east4-c us-east1-b us-east1-c us-east1-d us-west1-a us-west1-b \
         us-west4-a us-west4-b us-central1-a us-central1-b us-central1-c us-central1-f europe-west4-a europe-west4-b europe-west4-c; do
  GPU_CANDIDATES+=("t4 $z")
done
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
SRC="vg-drill-src-$LOW"
GPU="vg-drill-gpu-$LOW"
BUCKET="$PROJECT-vg-drill-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"

cleanup() {
  echo "cleanup: deleting $SRC, $GPU and gs://$BUCKET"
  gcloud compute instances delete "$SRC" --project "$PROJECT" --zone "$CPU_ZONE" --quiet >/dev/null 2>&1 || true
  [ -z "$GPU_ZONE" ] || gcloud compute instances delete "$GPU" --project "$PROJECT" --zone "$GPU_ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

# wait_for <object prefix> <minutes>: DONE, FAILED or timeout.
wait_for() {
  local deadline=$(( $(date +%s) + $2 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do
      if gcloud storage ls "gs://$BUCKET/$1/$m" --project "$PROJECT" >/dev/null 2>&1; then echo "$m"; return; fi
    done
    sleep 20
  done
  echo TIMEOUT
}

collect() { # collect <leg>
  mkdir -p "$EVIDENCE/$1"
  gcloud storage cp "gs://$BUCKET/out/$1/*" "$EVIDENCE/$1/" --project "$PROJECT" >/dev/null 2>&1 || true
  ls "$EVIDENCE/$1"
}

echo "build acpctl (linux/amd64) and pack workers/genome"
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/acpctl" ./cmd/acpctl )
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/acpctl" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

# The GPU first: it prepares its runtime while the source trains, and a
# run with no GPU capacity anywhere stops before the source is paid for.
for c in "${GPU_CANDIDATES[@]}"; do
  set -- $c
  if [ "$1" = l4 ]; then
    shape=(--machine-type g2-standard-4)
  else
    shape=(--machine-type n1-standard-4 --accelerator type=nvidia-tesla-t4,count=1)
  fi
  echo "boot $GPU ($1, $2)"
  if gcloud compute instances create "$GPU" --project "$PROJECT" --zone "$2" "${shape[@]}" \
      --maintenance-policy TERMINATE \
      --image-family common-cu129-ubuntu-2404-nvidia-580 --image-project deeplearning-platform-release \
      --boot-disk-size 100GB --scopes storage-rw \
      --metadata "vg-bucket=$BUCKET,install-nvidia-driver=True" \
      --metadata-from-file "vg-common=$HERE/common.sh,startup-script=$HERE/gpu-restore.sh" >/dev/null 2>"$BUILD/gpu-create.err"; then
    GPU_ZONE="$2"; GPU_KIND="$1"; break
  fi
  grep -oE "ZONE_RESOURCE_POOL_EXHAUSTED[A-Z_]*|QUOTA_EXCEEDED|currently unavailable|[A-Z_]*quota[a-z ]*" "$BUILD/gpu-create.err" | head -1 || true
  # A create that failed after it started can leave a stopped instance behind.
  gcloud compute instances delete "$GPU" --project "$PROJECT" --zone "$2" --quiet >/dev/null 2>&1 || true
done
[ -n "$GPU_ZONE" ] || { echo "no GPU capacity in any candidate zone"; cat "$BUILD/gpu-create.err"; exit 1; }
echo "gpu: $GPU_KIND in $GPU_ZONE"

echo "boot $SRC (SEV-SNP, n2d-standard-8, $CPU_ZONE)"
gcloud compute instances create "$SRC" --project "$PROJECT" --zone "$CPU_ZONE" \
  --machine-type n2d-standard-8 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 40GB \
  --scopes storage-rw --metadata "vg-bucket=$BUCKET" \
  --metadata-from-file "vg-common=$HERE/common.sh,startup-script=$HERE/cvm-train.sh" >/dev/null

echo "waiting for the source (up to 40 min)"
SRC_RESULT=$(wait_for out/source 40)
echo "source: $SRC_RESULT"
collect source
gcloud compute instances delete "$SRC" --project "$PROJECT" --zone "$CPU_ZONE" --quiet >/dev/null 2>&1 || true
[ "$SRC_RESULT" = DONE ] || { echo "the source did not finish"; exit 1; }

echo "waiting for the GPU leg (up to 45 min)"
GPU_RESULT=$(wait_for out/gpu 45)
echo "gpu: $GPU_RESULT"
collect gpu
[ "$GPU_RESULT" = DONE ] || { echo "the GPU leg did not finish"; exit 1; }
echo "evidence: $EVIDENCE"
