#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The integer door across the CPU/GPU boundary, on real hardware: one
# NVIDIA L4 VM runs l4-integer.sh — a 0.5B genome fine-tuned on the CPU
# whose integer references the L4 must reproduce byte for byte, and a 7B
# genome fine-tuned on the L4 in bfloat16 whose integer references the
# CPU must reproduce — with the gate's three doors run at zero tolerance
# on the GPU: the float doors fail across devices (VERIFIABLE-CLAIMS C6),
# the integer door opens EXACT.
#
# One VM: g2-standard-8 (1 x L4, 24 GB; 8 vCPU, 32 GB) from the Deep
# Learning VM image with the NVIDIA driver, in the first zone with L4
# capacity (the default quota is one L4 per region, so every L4 region
# is tried). Deleted at the end, on success or failure; the bucket too.
# What comes back: genome.json and fixtures.json of both genomes (public:
# hyper-parameters, losses, prompts, reference logits — float and
# integer), the measurements, the gate verdicts, nvidia-smi and pip
# freeze. The adapters — the secret part — never leave the VM.
#
# Usage: run.sh <gcp-project>        (about an hour, roughly a dollar)
set -euo pipefail
PROJECT="${1:?usage: run.sh <project>}"
ZONES=(us-central1-a us-central1-b us-central1-c us-east1-b us-east1-c us-east1-d us-east4-a us-east4-b us-east4-c us-west1-a us-west1-b us-west1-c europe-west4-a europe-west4-b europe-west4-c)
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
GPU="vg-int-l4-$LOW"
BUCKET="$PROJECT-vg-int-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
GPU_ZONE=""

cleanup() {
  echo "cleanup: deleting $GPU and gs://$BUCKET"
  [ -z "$GPU_ZONE" ] || gcloud compute instances delete "$GPU" --project "$PROJECT" --zone "$GPU_ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

wait_for() { # wait_for <minutes>
  local deadline=$(( $(date +%s) + $1 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for m in DONE FAILED; do
      if gcloud storage ls "gs://$BUCKET/out/gpu/$m" --project "$PROJECT" >/dev/null 2>&1; then echo "$m"; return; fi
    done
    sleep 30
  done
  echo TIMEOUT
}

echo "build acpctl (linux/amd64) and pack workers/genome"
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/acpctl" ./cmd/acpctl )
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD/acpctl" "$BUILD/worker.tgz" "gs://$BUCKET/in/" --project "$PROJECT" >/dev/null

# L4 capacity comes and goes by the minute: try the zones in rounds, a
# minute apart, for up to half an hour.
for round in $(seq 1 30); do
  for z in "${ZONES[@]}"; do
    echo "boot $GPU (g2-standard-8, L4, $z, round $round)"
    if gcloud compute instances create "$GPU" --project "$PROJECT" --zone "$z" \
        --machine-type g2-standard-8 --maintenance-policy TERMINATE \
        --image-family common-cu129-ubuntu-2404-nvidia-580 --image-project deeplearning-platform-release \
        --boot-disk-size 150GB --scopes storage-rw \
        --metadata "vg-bucket=$BUCKET,install-nvidia-driver=True" \
        --metadata-from-file "vg-common=$HERE/common.sh,startup-script=$HERE/l4-integer.sh" >/dev/null 2>"$BUILD/gpu-create.err"; then
      GPU_ZONE="$z"; break 2
    fi
    grep -oE "ZONE_RESOURCE_POOL_EXHAUSTED[A-Z_]*|QUOTA_EXCEEDED|currently unavailable|[A-Z_]*quota[a-z ]*" "$BUILD/gpu-create.err" | head -1 || true
    grep -q "QUOTA_EXCEEDED\|quota" "$BUILD/gpu-create.err" && { echo "quota, not capacity:"; cat "$BUILD/gpu-create.err"; exit 1; }
    gcloud compute instances delete "$GPU" --project "$PROJECT" --zone "$z" --quiet >/dev/null 2>&1 || true
  done
  sleep 60
done
[ -n "$GPU_ZONE" ] || { echo "no L4 capacity in any zone after 30 rounds"; cat "$BUILD/gpu-create.err"; exit 1; }

echo "waiting for the run (up to 110 min)"
RESULT=$(wait_for 110)
echo "gpu: $RESULT"
mkdir -p "$EVIDENCE"
gcloud storage cp "gs://$BUCKET/out/gpu/*" "$EVIDENCE/" --project "$PROJECT" >/dev/null 2>&1 || true
rm -f "$EVIDENCE/DONE" "$EVIDENCE/FAILED"
ls "$EVIDENCE"
[ "$RESULT" = DONE ] || { echo "the run did not finish cleanly"; exit 1; }
echo "evidence: $EVIDENCE"
