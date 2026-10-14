#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs the SEV-SNP key-release and genome-restore end-to-end test on a fresh GCP Confidential
# VM and brings the results back:
#
#   1. builds sagvd, acp-bootstrap, acpctl and keygen for linux/amd64 from this tree;
#   2. uploads them (with the AMD Milan cert chain) to a new private bucket;
#   3. boots an n2d SEV-SNP VM whose startup script is cvm-keyrelease.sh;
#   4. waits for the results on the serial console, decodes and checks them;
#   5. deletes the VM and the bucket — always, also on failure.
#
# Cost: one n2d-standard-2 for about ten minutes. Requires gcloud logged in
# to a project with the Compute and Storage APIs enabled.
#
# Usage: run.sh <project> [zone]   (default zone us-central1-b)
set -euo pipefail

PROJECT="${1:?usage: run.sh <project> [zone]}"
ZONE="${2:-us-central1-b}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="vg-keyrelease-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUCKET="$PROJECT-vg-e2e-$(echo "$STAMP" | tr 'A-Z' 'a-z')"
BUILD="$(mktemp -d)"
CHAIN="$ROOT/scripts/hardware-test/gcp-sev-snp/keybind-evidence/20260913T222343Z/kds-vcek-cert_chain.pem"

cleanup() {
  echo "cleanup: deleting $NAME and gs://$BUCKET"
  gcloud compute instances delete "$NAME" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null 2>&1 || true
  gcloud storage rm -r "gs://$BUCKET" --project "$PROJECT" >/dev/null 2>&1 || true
  rm -rf "$BUILD"
}
trap cleanup EXIT

echo "build (linux/amd64)"
( cd "$ROOT" && for b in sagvd acp-bootstrap acpctl; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
cp "$CHAIN" "$BUILD/amd-milan-cert_chain.pem"

echo "upload to gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" --project "$PROJECT" --location us-central1 --uniform-bucket-level-access >/dev/null
gcloud storage cp "$BUILD"/* "gs://$BUCKET/e2e/" --project "$PROJECT" >/dev/null

echo "boot $NAME (SEV-SNP, $ZONE)"
gcloud compute instances create "$NAME" --project "$PROJECT" --zone "$ZONE" \
  --machine-type n2d-standard-2 --min-cpu-platform "AMD Milan" \
  --confidential-compute-type SEV_SNP --maintenance-policy TERMINATE \
  --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
  --scopes storage-ro --metadata "vg-bucket=$BUCKET" \
  --metadata-from-file "startup-script=$HERE/cvm-keyrelease.sh" >/dev/null

echo "waiting for results on the serial console (up to 15 min)"
# The raw console capture (the whole boot log) is saved before anything is
# deleted, so a decoding failure never loses a run. It stays outside the
# repository; the decoded results under evidence/ are what gets committed.
RAW_DIR="${VG_E2E_RAW_DIR:-$HOME/.cache/vaultgenome/keyrelease-e2e}"
mkdir -p "$RAW_DIR"
SERIAL="$RAW_DIR/serial-$STAMP.txt"
for i in $(seq 1 90); do
  sleep 10
  gcloud compute instances get-serial-port-output "$NAME" --project "$PROJECT" --zone "$ZONE" > "$SERIAL" 2>/dev/null || true
  grep -q "===E2E-END===" "$SERIAL" && break
done
grep -q "===E2E-END===" "$SERIAL" || { echo "no results after 15 minutes"; tail -40 "$SERIAL"; exit 1; }
echo "serial capture: $SERIAL ($(shasum -a 256 "$SERIAL" | cut -d' ' -f1))"

"$HERE/decode-results.sh" "$SERIAL" "$HERE/evidence"
