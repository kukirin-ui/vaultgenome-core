#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 03-demo1-single-bundle.sh — Demo 1 round-trip on real Azure SEV-SNP
# hardware. Pulls a model via Ollama, seals it, restores to a different
# path, verifies every blob digest matches the envelope, runs a tamper test.

set -euo pipefail

MODEL="${MODEL:-llama3.2:3b}"
ACPCTL="${ACPCTL:-./acpctl}"

cd ~/vg

if [ ! -x "$ACPCTL" ]; then
  echo "ERROR: acpctl binary not found at $ACPCTL"
  echo "       Either build it from the Vault Genome repo or copy it here."
  exit 1
fi

echo "=== ensure ollama daemon dir is readable ==="
sudo chown -R ollama:ollama /usr/share/ollama 2>/dev/null || true
sudo chmod -R u=rwX,go=rX /usr/share/ollama 2>/dev/null || true

echo
echo "=== pull the model the demo uses ==="
ollama pull "$MODEL"

echo
echo "=== ensure perms still readable after ollama recreated files ==="
sudo chmod -R u=rwX,go=rX /usr/share/ollama 2>/dev/null || true

echo
echo "=== seal ==="
"$ACPCTL" genome seal \
  --model="$MODEL" \
  --ollama-home=/usr/share/ollama/.ollama \
  --output=demo1-bundle.genome \
  --key-out=demo1-bundle.key \
  --force \
  | tee evidence/demo1-seal.txt

echo
echo "=== inspect ==="
"$ACPCTL" genome inspect --bundle=demo1-bundle.genome \
  | tee evidence/demo1-inspect.txt

echo
echo "=== open into /tmp/demo1-restored ==="
rm -rf /tmp/demo1-restored
"$ACPCTL" genome open \
  --bundle=demo1-bundle.genome \
  --key-file=demo1-bundle.key \
  --target=/tmp/demo1-restored \
  | tee evidence/demo1-open.txt

echo
echo "=== verify (re-hash every blob in restored tree) ==="
"$ACPCTL" genome verify \
  --bundle=demo1-bundle.genome \
  --key-file=demo1-bundle.key \
  --restored=/tmp/demo1-restored \
  | tee evidence/demo1-verify.txt

echo
echo "=== tamper test: flip one byte at offset 1 MiB inside the sealed bundle ==="
cp demo1-bundle.genome /tmp/tampered.genome
printf '\xff' | dd of=/tmp/tampered.genome bs=1 seek=1048576 count=1 conv=notrunc 2>/dev/null
echo "1 byte flipped at offset 1 MiB"

set +e
"$ACPCTL" genome rewind \
  --bundle=/tmp/tampered.genome \
  --key-file=demo1-bundle.key \
  --target=/tmp/should-not-exist \
  > evidence/demo1-tamper.txt 2>&1
TAMPER_EXIT=$?
set -e

echo "tamper test exit code: $TAMPER_EXIT (non-zero == the edited segment failed authentication, expected)"
cat evidence/demo1-tamper.txt
rm -f /tmp/tampered.genome

echo
echo "=== Demo 1 complete ==="
echo "Next: ./scripts/04-demo2-chain.sh"
