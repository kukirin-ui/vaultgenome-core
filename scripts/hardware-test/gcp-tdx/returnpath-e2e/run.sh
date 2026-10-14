#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Return Path on a real Intel TDX guest: builds sagvd, acp-compute,
# acpctl and keygen for linux/amd64, packs the vg_genome worker, boots a
# GCP c3 Confidential VM with Intel TDX (Ubuntu 24.04) whose startup script
# runs the whole flow (cvm-returnpath-tdx.sh), collects the results from
# the serial console and deletes the VM. What the guest prints is the
# results tarball only: reports, identities, job views, logs, the public
# Intel PCS documents the verifier fetched; keys, seeds, tokens and configs
# stay on the VM and die with it.
#
# Usage: run.sh <gcp-project> [zone]     (c3-standard-4, ~10 minutes)
set -euo pipefail
PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-a}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
NAME="vg-tdx-rp-$LOW"
BUCKET="$PROJECT-vg-tdxrp-$LOW"
BUILD="$(mktemp -d)"
DECODE="$ROOT/scripts/hardware-test/gcp-sev-snp/returnpath-e2e/decode-results.sh"

cleanup() {
  echo "cleanup: deleting $NAME and gs://$BUCKET"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "build (linux/amd64)"
( cd "$ROOT" && for b in sagvd acp-compute acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
( cd "$ROOT/workers" && COPYFILE_DISABLE=1 tar czf "$BUILD/genome-worker.tgz" --no-xattrs --exclude '__pycache__' --exclude '.pytest_cache' genome )

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "boot $NAME (c3-standard-4, Intel TDX, $ZONE)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type c3-standard-4 --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --boot-disk-size 20GB \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET" \
  --metadata-from-file "startup-script=$HERE/cvm-returnpath-tdx.sh" >/dev/null

echo "waiting for results on the serial console (up to 25 min)"
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/tdx-returnpath-e2e}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
for i in $(seq 1 150); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 25 minutes"; tail -40 "$SERIAL"; exit 1; }
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"
"$DECODE" "$SERIAL" "$HERE/evidence"
