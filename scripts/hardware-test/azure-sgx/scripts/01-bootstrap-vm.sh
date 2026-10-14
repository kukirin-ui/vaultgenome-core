#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Intel SGX DCAP, Open Enclave SDK, Go,
# Ollama, and the Vault Genome acpctl binary on a fresh Azure DCsv3
# SGX VM. Idempotent — safe to re-run.

set -euo pipefail

GO_VERSION="${GO_VERSION:-1.25.9}"

echo "=== verify Intel SGX devices present on this Azure SGX VM ==="
if [ ! -c /dev/sgx_enclave ] || [ ! -c /dev/sgx_provision ]; then
  echo "ERROR: /dev/sgx_enclave and/or /dev/sgx_provision missing."
  echo "       This VM is not running on Intel SGX silicon."
  echo "       Use a Standard_DC*s_v3 VM size (or any DCsv3-family)."
  exit 1
fi
ls -l /dev/sgx_enclave /dev/sgx_provision

echo
echo "=== install build dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl git wget jq tar gnupg lsb-release software-properties-common dkms linux-headers-generic

echo
echo "=== install Intel SGX DCAP libraries ==="
if ! dpkg -l libsgx-enclave-common 2>/dev/null | grep -q '^ii'; then
  curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
    | sudo gpg --dearmor -o /usr/share/keyrings/intel-sgx-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/intel-sgx.list
  sudo apt-get update -qq
  sudo apt-get install -y -qq \
    libsgx-enclave-common libsgx-dcap-default-qpl libsgx-dcap-ql \
    libsgx-dcap-quote-verify libsgx-quote-ex libsgx-urts \
    sgx-aesm-service
fi

# -dev packages for sgx-quote-binding/verify-quote.c (sgx_quote_3.h,
# sgx_dcap_quoteverify.h). Idempotent — apt is a no-op if already
# installed.
sudo apt-get install -y -qq \
  libsgx-dcap-ql-dev libsgx-dcap-quote-verify-dev 2>/dev/null || true
sudo systemctl enable --now aesmd 2>/dev/null || true

echo
echo "=== install Microsoft Azure DCAP client (caches Intel attestation collateral via Azure) ==="
if ! dpkg -l az-dcap-client 2>/dev/null | grep -q '^ii'; then
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
    | sudo gpg --dearmor -o /usr/share/keyrings/microsoft.gpg
  echo "deb [signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/$(lsb_release -rs)/prod $(lsb_release -cs) main" \
    | sudo tee /etc/apt/sources.list.d/azure-dcap.list
  sudo apt-get update -qq
  sudo apt-get install -y -qq az-dcap-client
fi

echo
echo "=== install Open Enclave SDK (provides oeutil for quote generation + verification) ==="
# History: Intel deprecated download.01.org/openenclave/ (returns 404). The
# canonical install paths now are (in order of preference):
#   1. Microsoft prod apt repo we already added above for az-dcap-client
#      (sometimes ships open-enclave, sometimes not — version-dependent)
#   2. GitHub release .deb for Ubuntu 22.04 jammy
# Both paths are idempotent / non-fatal — workload tests proceed even if OE
# install fails (smoke-test fallback in 02-capture-attestation.sh).
if ! dpkg -l open-enclave 2>/dev/null | grep -q '^ii'; then
  # Path 1: try apt (Microsoft prod repo was added above for az-dcap).
  if sudo apt-get install -y -qq open-enclave 2>/dev/null; then
    echo "✓ Open Enclave installed via apt"
  else
    # Path 2: GitHub release .deb. Try a few stable versions.
    echo "(Open Enclave not in apt — trying GitHub release .deb)"
    for OE_VERSION in 0.19.13 0.19.7 0.18.5; do
      OE_URL="https://github.com/openenclave/openenclave/releases/download/v${OE_VERSION}/Ubuntu_2204_open-enclave_${OE_VERSION}_amd64.deb"
      if curl -fsSL --connect-timeout 15 "${OE_URL}" -o /tmp/oe.deb 2>/dev/null && [ -s /tmp/oe.deb ]; then
        sudo apt-get install -y -qq /tmp/oe.deb 2>/dev/null \
          || sudo dpkg -i /tmp/oe.deb 2>/dev/null \
          || sudo apt-get install -fy 2>/dev/null
        if dpkg -l open-enclave 2>/dev/null | grep -q '^ii'; then
          echo "✓ Open Enclave ${OE_VERSION} installed via GitHub release"
          break
        fi
      fi
    done
  fi
fi
# Ensure oeutil is in PATH (Open Enclave installs to /opt/openenclave/bin).
if [ -x /opt/openenclave/bin/oeutil ] && ! command -v oeutil >/dev/null 2>&1; then
  echo 'export PATH=$PATH:/opt/openenclave/bin' >>~/.bashrc
  export PATH=$PATH:/opt/openenclave/bin
fi
if command -v oeutil >/dev/null 2>&1; then
  echo "✓ oeutil at: $(command -v oeutil)"
else
  echo "WARNING: oeutil not available — 02b/02f will use smoke-test fallback."
  echo "         Workload tests (Demo 1 + 2 + tamper + inference) will run normally."
fi

# Two libdcap_quoteprov.so files end up on disk:
#   /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1  ← Intel default QPL
#                                                       (apt: libsgx-dcap-default-qpl)
#                                                       Talks to local PCCS
#                                                       (sgx_default_qcnl.conf →
#                                                        localhost:8081 → not running)
#   /usr/local/lib/libdcap_quoteprov.so               ← Microsoft az-dcap-client
#                                                       Talks to Azure cache
#                                                       (global.acccache.azure.net)
#
# The dynamic loader resolves "libdcap_quoteprov.so" → /usr/lib/x86_64-linux-gnu
# by default, so without intervention we'd use Intel's QPL and fail with
# CURL error 7 (couldn't connect to localhost:8081). Force the dynamic
# loader onto Microsoft's variant by replacing the standard-path symlinks.
echo
echo "=== libdcap_quoteprov.so → Microsoft az-dcap-client (Azure-aware) ==="
if [ -f /usr/local/lib/libdcap_quoteprov.so ]; then
  sudo ln -sf /usr/local/lib/libdcap_quoteprov.so \
              /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
  sudo ln -sf /usr/local/lib/libdcap_quoteprov.so \
              /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
  echo "✓ libdcap_quoteprov.so / .so.1 → /usr/local/lib/libdcap_quoteprov.so (az-dcap)"
else
  echo "WARNING: az-dcap-client not at /usr/local/lib/libdcap_quoteprov.so"
  echo "         Quote generation + verification will use Intel QPL"
  echo "         (which fails on Azure without a local PCCS)."
fi

# CRITICAL: aesmd may already be running with the *previous* (Intel)
# QPL cached in memory. Force it to reload by restarting the unit, so
# subsequent oe_get_report / sgx_qe_get_target_info calls go through
# the Microsoft az-dcap-client we just symlinked in.
echo
echo "=== restart aesmd to pick up the swapped libdcap_quoteprov.so ==="
sudo systemctl restart aesmd
sleep 2
sudo systemctl is-active aesmd && echo "✓ aesmd reloaded"

# AESM daemon must be running for oeutil generate-evidence to call into
# the SGX DCAP quoting enclave. Bootstrap above already enabled it via
# systemctl enable --now, but verify here and add azureuser to sgx group
# (so non-root code can use /dev/sgx_provision).
if ! systemctl is-active aesmd >/dev/null 2>&1; then
  echo "(re-starting aesmd...)"
  sudo systemctl restart aesmd 2>/dev/null || true
fi
sudo usermod -a -G sgx_prv "$(whoami)" 2>/dev/null || true

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
echo "=== install Ollama (CPU-only) ==="
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi

echo
echo "=== install Azure CLI ==="
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
echo "=== sanity-check installed tools ==="
FAIL=0
if command -v go >/dev/null 2>&1; then echo "✓ go     $(go version | awk '{print $3}')"; else echo "✗ go MISSING"; FAIL=1; fi
if command -v ollama >/dev/null 2>&1; then echo "✓ ollama $(ollama --version 2>/dev/null | head -1 || echo 'present')"; else echo "✗ ollama MISSING"; FAIL=1; fi
if command -v az >/dev/null 2>&1; then echo "✓ az     $(az version --output tsv --query '\"azure-cli\"' 2>/dev/null || echo 'present')"; else echo "✗ az MISSING"; FAIL=1; fi
if command -v jq >/dev/null 2>&1; then echo "✓ jq     $(jq --version)"; else echo "✗ jq MISSING"; FAIL=1; fi
if [ -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ]; then echo "✓ /dev/sgx_*"; else echo "✗ /dev/sgx_* MISSING"; FAIL=1; fi
if [ "${FAIL}" = "1" ]; then
  echo
  echo "ERROR: one or more critical tools missing. Workload tests will fail."
  exit 1
fi

echo
echo "=== bootstrap complete ==="
echo "Next: ./scripts/02-capture-attestation.sh"
