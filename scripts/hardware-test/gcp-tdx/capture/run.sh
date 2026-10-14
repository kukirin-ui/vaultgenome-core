#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Capture a genuine Intel TDX quote from a Google Cloud Confidential VM
# (c3, Intel TDX) through the kernel's configfs-tsm interface, with a
# caller nonce bound into REPORTDATA — the raw material the TDX producer
# and verifier are built and tested against (step 6a of the production
# program). Also captures what the guest sees of itself (kernel, dmesg,
# /dev/tdx_guest, cpu flags) and the Intel PCS artifacts the verifier needs
# offline (TCB info for the quote's FMSPC, QE identity, root CA and CRLs).
#
# Everything captured is public by construction: a quote is a signed
# statement about the guest, the PCK chain and PCS documents are Intel's
# published certificates. No key, seed or token is produced or kept.
#
# Usage: run.sh <project> [zone]   (c3-standard-4 for a few minutes)
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-a}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
VM="vg-tdx-capture-$LOW"
BUCKET="$PROJECT-vg-tdx-$LOW"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"

cleanup() {
  echo "cleanup: deleting $VM and gs://$BUCKET"
  gcloud compute instances delete "$VM" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "bucket gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null

echo "boot $VM (c3-standard-4, Intel TDX, $ZONE)"
gcloud compute instances create "$VM" --project "$PROJECT" --zone "$ZONE" \
  --machine-type c3-standard-4 --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --boot-disk-size 20GB \
  --scopes storage-rw --metadata "vg-bucket=$BUCKET,vg-stamp=$STAMP" \
  --metadata-from-file "startup-script=$HERE/cvm-tdx-capture.sh" >/dev/null

echo "waiting for the guest (up to 15 min)"
RESULT=TIMEOUT
for i in $(seq 1 45); do
  for m in DONE FAILED; do
    if gcloud storage ls "gs://$BUCKET/out/$m" --project "$PROJECT" >/dev/null 2>&1; then RESULT=$m; break 2; fi
  done
  sleep 20
done
echo "guest: $RESULT"
mkdir -p "$EVIDENCE"
gcloud storage cp "gs://$BUCKET/out/capture.tgz" "$BUILD/capture.tgz" --project "$PROJECT" >/dev/null 2>&1 && tar -C "$EVIDENCE" -xzf "$BUILD/capture.tgz" || true
ls "$EVIDENCE" || true
[ "$RESULT" = DONE ] || { echo "the capture did not finish cleanly"; exit 1; }

echo "Intel PCS artifacts for the quote (public): TCB info, QE identity, root CA, CRLs"
python3 "$HERE/pcs_fetch.py" "$EVIDENCE" || { echo "PCS fetch failed"; exit 1; }
echo "evidence: $EVIDENCE"
