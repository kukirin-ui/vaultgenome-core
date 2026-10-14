#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The EXACT-door research probe on one NVIDIA GPU VM (not confidential; this
# measures determinism, not key release). It packs workers/genome (for the
# fixture prompts and pinned requirements) and exact_probe.py, boots one GPU
# VM (an L4 where free, else a T4), runs the probe, brings out/ back to
# evidence/<stamp>/ and deletes the VM and bucket — always, also on failure.
#
# Usage: run.sh <project>
set -euo pipefail

PROJECT="${1:?usage: run.sh <project>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
GPU="vg-exact-$LOW"
BUCKET="$PROJECT-vg-exact-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
GPU_ZONE=""
GPU_CANDIDATES=(
  "l4 us-east4-a" "l4 us-east4-c" "l4 us-east1-b" "l4 us-east1-c" "l4 us-west1-a" "l4 us-west1-b" \
  "l4 us-central1-a" "l4 us-central1-b" "l4 us-central1-c" "l4 europe-west4-a" \
  "t4 us-east4-a" "t4 us-east1-c" "t4 us-central1-a" "t4 us-central1-b"
)

cleanup() {
  echo "cleanup: deleting $GPU and gs://$BUCKET"
  [ -z "$GPU_ZONE" ] || gcloud compute instances delete "$GPU" --project "$PROJECT" --zone "$GPU_ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "pack workers/genome and the probe"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples
cp "$HERE/exact_probe.py" "$BUILD/exact_probe.py"

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/worker.tgz" "$BUILD/exact_probe.py" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

for c in "${GPU_CANDIDATES[@]}"; do
  set -- $c
  if [ "$1" = l4 ]; then shape=(--machine-type g2-standard-4); else shape=(--machine-type n1-standard-4 --accelerator type=nvidia-tesla-t4,count=1); fi
  echo "boot $GPU ($1, $2)"
  if gcloud compute instances create "$GPU" --project "$PROJECT" --zone "$2" "${shape[@]}" \
      --maintenance-policy TERMINATE \
      --image-family common-cu129-ubuntu-2404-nvidia-580 --image-project deeplearning-platform-release \
      --boot-disk-size 100GB --scopes storage-rw \
      --metadata "vg-bucket=$BUCKET,install-nvidia-driver=True" \
      --metadata-from-file "vg-common=$HERE/common.sh,startup-script=$HERE/probe.sh" >/dev/null 2>"$BUILD/create.err"; then
    GPU_ZONE="$2"; echo "gpu: $1 in $2"; break
  fi
  grep -oE "ZONE_RESOURCE_POOL_EXHAUSTED[A-Z_]*|QUOTA_EXCEEDED|currently unavailable" "$BUILD/create.err" | head -1 || true
  gcloud compute instances delete "$GPU" --project "$PROJECT" --zone "$2" --quiet >/dev/null 2>&1 || true
done
[ -n "$GPU_ZONE" ] || { echo "no GPU capacity in any candidate zone"; cat "$BUILD/create.err"; exit 1; }

echo "waiting for the probe (up to 40 min)"
deadline=$(( $(date +%s) + 40*60 )); RESULT=TIMEOUT
while [ "$(date +%s)" -lt "$deadline" ]; do
  for m in DONE FAILED; do
    if gcloud storage ls "gs://$BUCKET/out/$m" --project "$PROJECT" >/dev/null 2>&1; then RESULT="$m"; break 2; fi
  done
  sleep 20
done
echo "probe: $RESULT"
mkdir -p "$EVIDENCE"
if gcloud storage cp "gs://$BUCKET/out.tgz" "$BUILD/out.tgz" --project "$PROJECT" >/dev/null 2>&1; then
  tar -C "$EVIDENCE" -xzf "$BUILD/out.tgz" || true
fi
ls "$EVIDENCE" 2>/dev/null || true
[ "$RESULT" = DONE ] || { echo "the probe did not finish"; exit 1; }
echo "evidence: $EVIDENCE"; cat "$EVIDENCE/probe.json" 2>/dev/null || true
