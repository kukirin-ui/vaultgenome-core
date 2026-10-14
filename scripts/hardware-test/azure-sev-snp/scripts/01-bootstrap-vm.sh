#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Go, Ollama, and the Vault Genome acpctl
# binary on a fresh Azure Confidential VM (DCasv5/DCadsv5). Idempotent
# — safe to re-run.
#
# Prereq: this script runs ON THE VM (after SSH'ing in), not on your
# laptop. Run as a non-root user with sudo access (the Azure default
# 'azureuser' has it).

set -euo pipefail

GO_VERSION="${GO_VERSION:-1.25.9}"

echo "=== verify SEV-SNP active on this Azure CVM ==="
if ! journalctl -k --no-pager 2>/dev/null | grep -qE "sev|SEV-SNP|memory encryption"; then
  echo "WARNING: SEV-SNP indicators not visible in kernel log."
  echo "         This may be a non-Confidential VM. Continuing anyway."
fi
journalctl -k --no-pager 2>/dev/null | grep -iE "sev|memory encryption" | head -10 || true

echo
echo "=== verify /dev/sev-guest device present ==="
if [ ! -c /dev/sev-guest ]; then
  echo "ERROR: /dev/sev-guest device missing."
  echo "       This VM is not running on AMD SEV-SNP confidential silicon."
  echo "       Use a Standard_DC*as_v5 (or DCadsv5) VM size."
  exit 1
fi
ls -l /dev/sev-guest

echo
echo "=== install build dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl git wget jq tar

echo
echo "=== install Go ${GO_VERSION} ==="
if ! command -v go >/dev/null 2>&1; then
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
  rm "go${GO_VERSION}.linux-amd64.tar.gz"
  echo 'export PATH=$PATH:/usr/local/go/bin' >>~/.bashrc
  export PATH=$PATH:/usr/local/go/bin
fi
go version

echo
echo "=== install Ollama (CPU-only — Confidential VMs don't expose GPUs) ==="
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi

echo
echo "=== install snpguest (VirTEE) for Cryptographic Attestation Chain Validation ==="
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # shellcheck disable=SC1091
  . "${HOME}/.cargo/env"
fi
if ! [ -x "${HOME}/snpguest-src/target/release/snpguest" ]; then
  git clone https://github.com/virtee/snpguest.git "${HOME}/snpguest-src" 2>/dev/null || true
  (cd "${HOME}/snpguest-src" && cargo build --release)
fi
"${HOME}/snpguest-src/target/release/snpguest" --version

echo
echo "=== install Azure CLI (for MAA token + IMDS metadata) ==="
if ! command -v az >/dev/null 2>&1; then
  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
fi
az version | head -3

echo
echo "=== prepare workdir ==="
mkdir -p ~/vg ~/vg/evidence

echo
echo "=== capture VM identity from Azure IMDS ==="
{
  echo "=== Azure IMDS metadata ==="
  curl -fs -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance?api-version=2021-12-13" 2>/dev/null \
    | jq . || echo "IMDS unavailable"
} | tee ~/vg/evidence/azure-imds.json

echo
echo "=== bootstrap complete ==="
echo "Next: ./scripts/02-capture-attestation.sh"
