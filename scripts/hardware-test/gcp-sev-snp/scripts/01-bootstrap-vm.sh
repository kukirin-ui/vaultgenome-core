#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Go, Ollama, and the Vault Genome acpctl
# binary on a fresh Confidential VM. Idempotent — safe to re-run.
#
# Prereq: this script runs ON THE VM (after SSH'ing in), not on your
# laptop. Run as a non-root user with sudo access (the GCP default).

set -euo pipefail

GO_VERSION="${GO_VERSION:-1.25.9}"

echo "=== verify SEV-SNP active ==="
if ! journalctl -k --no-pager 2>/dev/null | grep -q "SEV-SNP"; then
  echo "WARNING: SEV-SNP not visible in kernel log — VM may not be a Confidential VM."
fi
journalctl -k --no-pager 2>/dev/null | grep -iE "sev|memory encryption" | head -10

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
echo "=== prepare workdir ==="
mkdir -p ~/vg ~/vg/evidence

echo
echo "=== bootstrap complete ==="
echo "Next: ./scripts/02-capture-attestation.sh"
