#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 04-demo2-chain.sh — Demo 2 chain operations on the parent EC2 host.
# Same semantics as the GCP version: 6 generations sealed in a chain,
# parent linkage validated, lineage walked, mid-chain rewind.

set -euo pipefail

ACPCTL="${ACPCTL:-./acpctl}"
NUM_GENS="${NUM_GENS:-6}"
EVIDENCE_DIR="$HOME/vg/attestation-validation/$(hostname)"

cd ~/vg
mkdir -p "$EVIDENCE_DIR"

if [ -d generations ] && [ "$(ls -A generations/*.genome 2>/dev/null | wc -l)" -ge 1 ]; then
  echo "=== using existing chain bundles in ./generations/ ==="
  ls -lh generations/
else
  echo "=== no chain bundles found — sealing $NUM_GENS fresh ones ==="
  mkdir -p generations test-payloads keys
  for i in $(seq 0 $((NUM_GENS - 1))); do
    mkdir -p "test-payloads/cycle-$i"
    echo "generation $i" >"test-payloads/cycle-$i/marker.txt"
    echo "epoch $(date +%s%N)" >>"test-payloads/cycle-$i/marker.txt"
  done

  PARENT_FLAG=""
  for i in $(seq 0 $((NUM_GENS - 1))); do
    BUNDLE="generations/gen-$i.genome"
    "$ACPCTL" genome seal \
      --content-dir="test-payloads/cycle-$i" \
      $PARENT_FLAG \
      --output="$BUNDLE" \
      --key-out="keys/gen-$i.key" \
      --force
    PARENT_FLAG="--parent=$BUNDLE"
  done
fi

echo
echo "=== chain validation ==="
"$ACPCTL" genome chain --dir=generations | tee "$EVIDENCE_DIR/demo2-chain.txt"

echo
echo "=== lineage walk from latest generation back to genesis ==="
LATEST=$(ls -1 generations/gen-*.genome | tail -1)
"$ACPCTL" genome lineage --bundle="$LATEST" --dir=generations \
  | tee "$EVIDENCE_DIR/demo2-lineage.txt"

echo
echo "=== rewind to a middle generation ==="
# Pick gen-(N/2) deterministically, e.g. for N=6 → gen-2.
GEN_COUNT=$(ls -1 generations/gen-*.genome | wc -l | tr -d ' ')
MID_INDEX=$(( GEN_COUNT / 2 ))
MID_BUNDLE="generations/gen-${MID_INDEX}.genome"
echo "  picking middle bundle: $MID_BUNDLE  (out of $GEN_COUNT generations)"
"$ACPCTL" genome rewind \
  --bundle="$MID_BUNDLE" \
  --key-file="keys/$(basename "$MID_BUNDLE" .genome).key" \
  --target=/tmp/demo2-rewind \
  | tee "$EVIDENCE_DIR/demo2-rewind.txt"

echo
echo "=== Demo 2 complete ==="
echo "Next: ./scripts/05-inference-test.sh (optional)"
