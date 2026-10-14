#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 03-demo1-single-bundle.sh — Demo 1 round-trip on the parent EC2 host.
# Pulls a model via Ollama, seals it via acpctl, restores to a different
# path, verifies every blob digest matches the envelope, runs a tamper
# test. This runs on the PARENT EC2 (not inside the enclave) — Vault
# Genome's seal/restore is a host-level operation; the enclave's job is
# attestation, not bulk file processing.
#
# Same workflow as GCP version, just with AWS-specific identity probe.

set -euo pipefail

MODEL="${MODEL:-llama3.2:3b}"
ACPCTL="${ACPCTL:-./acpctl}"
EVIDENCE_DIR="$HOME/vg/attestation-validation/$(hostname)"

cd ~/vg
mkdir -p "$EVIDENCE_DIR"

# Install Ollama if missing
if ! command -v ollama >/dev/null 2>&1; then
  echo "=== installing Ollama ==="
  # Pinned, not piped: the installer is checked before it runs, like the Go
  # tarball in 01-bootstrap-vm.sh. Recorded 2026-10-14 with:
  #   curl -fsSL https://ollama.com/install.sh -o install.sh && sha256sum install.sh
  # When ollama.com updates the script, review it and re-record hash and date.
  OLLAMA_INSTALL_SHA256="25f64b810b947145095956533e1bdf56eacea2673c55a7e586be4515fc882c9f"  # ollama.com/install.sh, 2026-10-14
  OLLAMA_INSTALLER="$(mktemp)"
  trap 'rm -f "$OLLAMA_INSTALLER"' EXIT
  curl -fsSL https://ollama.com/install.sh -o "$OLLAMA_INSTALLER"
  if ! echo "${OLLAMA_INSTALL_SHA256}  ${OLLAMA_INSTALLER}" | sha256sum -c -; then
    echo "ERROR: ollama install.sh sha256 mismatch; not running it" >&2
    rm -f "$OLLAMA_INSTALLER"
    exit 1
  fi
  sh "$OLLAMA_INSTALLER"
  rm -f "$OLLAMA_INSTALLER"
fi

# Build acpctl from source if not present locally
if [ ! -x "$ACPCTL" ]; then
  CORE_DIR="$(cd "$(dirname "$0")/../../../.." && pwd)"
  echo "=== building acpctl from $CORE_DIR ==="
  cd "$CORE_DIR/cmd/acpctl"
  /usr/local/go/bin/go build -o ~/vg/acpctl .
  cd ~/vg
fi

if [ ! -x "$ACPCTL" ]; then
  echo "ERROR: acpctl binary not found at $ACPCTL"
  exit 1
fi

# Restore ollama:ollama ownership BEFORE ollama pull. Prior demo runs
# may have chown'd the tree to ec2-user (debugging permissions); ollama
# daemon needs ownership back to write the manifest during pull.
# Also add go+rX so subsequent acpctl genome seal (which runs as ec2-user)
# can read as "others".
echo "=== fixing /usr/share/ollama perms (ollama owner, +rX for all) ==="
sudo chown -R ollama:ollama /usr/share/ollama 2>&1 || true
sudo chmod -R u=rwX,go=rX /usr/share/ollama 2>&1 || true

echo "=== pull the model the demo uses ==="
ollama pull "$MODEL"

# Re-apply read perms after pull — Ollama recreates manifest files
# with default 0600 perms during pull. We need o+r so acpctl can read.
sudo chmod -R u=rwX,go=rX /usr/share/ollama 2>&1 || true
ls -ld /usr/share/ollama /usr/share/ollama/.ollama
ls -l /usr/share/ollama/.ollama/models/manifests/registry.ollama.ai/library/llama3.2/ | head -3

echo
echo "=== seal ==="
"$ACPCTL" genome seal \
  --model="$MODEL" \
  --ollama-home=/usr/share/ollama/.ollama \
  --output=demo1-bundle.genome \
  --key-out=demo1-bundle.key \
  --force \
  | tee "$EVIDENCE_DIR/demo1-seal.txt"

echo
echo "=== inspect ==="
"$ACPCTL" genome inspect --bundle=demo1-bundle.genome \
  | tee "$EVIDENCE_DIR/demo1-inspect.txt"

echo
echo "=== open into /tmp/demo1-restored ==="
rm -rf /tmp/demo1-restored
"$ACPCTL" genome open \
  --bundle=demo1-bundle.genome \
  --key-file=demo1-bundle.key \
  --target=/tmp/demo1-restored \
  | tee "$EVIDENCE_DIR/demo1-open.txt"

echo
echo "=== verify (re-hash every blob in restored tree) ==="
"$ACPCTL" genome verify \
  --bundle=demo1-bundle.genome \
  --key-file=demo1-bundle.key \
  --restored=/tmp/demo1-restored \
  | tee "$EVIDENCE_DIR/demo1-verify.txt"

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
  > "$EVIDENCE_DIR/demo1-tamper.txt" 2>&1
TAMPER_EXIT=$?
set -e

echo "tamper test exit code: $TAMPER_EXIT (non-zero == the edited segment failed authentication, expected)"
cat "$EVIDENCE_DIR/demo1-tamper.txt"
rm -f /tmp/tampered.genome

echo
echo "=== Demo 1 complete ==="
echo "Next: ./scripts/04-demo2-chain.sh"
