#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 01-bootstrap-vm.sh — install Nitro Enclaves CLI, Docker, Go, and
# configure the Nitro Enclaves allocator on a fresh Amazon Linux 2023
# parent EC2 instance. Run this first after SSH'ing into a new VM
# created by ../terraform/.
#
# What this installs:
#   1. nitro-enclaves-cli + nitro-enclaves-cli-devel (AWS official)
#   2. Docker (for building enclave images)
#   3. Go 1.27.2 (the toolchain core/go.mod names), the tarball checked
#      against its go.dev sha256 before it is unpacked
#   4. Configures /etc/nitro_enclaves/allocator.yaml: 4 GB RAM + 2 vCPU
#      reserved for the enclave (enough for Vault Genome workload)
#   5. Adds the user to ne and docker groups
#
# After this script, the user MUST log out + back in (so group
# membership takes effect), or run `newgrp ne` and `newgrp docker`.

set -euo pipefail

# Resolved before any cd: the Go install below works in /tmp, and the
# requirements file is read after it.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== verifying instance has Nitro Enclaves support ==="
# This file is created by AWS only on Nitro Enclaves capable instances
# that have enclave_options.enabled = true. Absence = not Nitro-capable.
if ! [ -e /sys/devices/virtual/misc/nitro_enclaves ] && \
   ! lscpu | grep -q "Hypervisor vendor:.*KVM"; then
  echo "WARNING: this instance may not support Nitro Enclaves. Check terraform enclave_options.enabled = true."
fi

echo
echo "=== installing system packages ==="
sudo dnf update -y -q
sudo dnf install -y -q \
  aws-nitro-enclaves-cli \
  aws-nitro-enclaves-cli-devel \
  docker \
  git \
  jq \
  openssl \
  pkgconfig \
  python3-pip

echo
echo "=== configuring nitro_enclaves allocator (4 GB RAM, 2 vCPUs) ==="
sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null <<EOF
---
# How much memory to reserve for nitro enclaves (in MiB).
memory_mib: 4096
# How many CPUs to reserve for nitro enclaves.
cpu_count: 2
EOF

echo
echo "=== enabling and starting nitro-enclaves-allocator ==="
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl status nitro-enclaves-allocator.service --no-pager | head -8

echo
echo "=== enabling and starting docker ==="
sudo systemctl enable --now docker
sudo systemctl status docker --no-pager | head -5

echo
echo "=== adding $USER to ne and docker groups ==="
sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"

echo
GO_VERSION="1.27.2"
GO_SHA256="ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"  # go.dev/dl, go1.27.2.linux-amd64.tar.gz
echo "=== installing Go ${GO_VERSION} ==="
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go${GO_VERSION} "; then
  cd /tmp
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o go.tar.gz
  echo "${GO_SHA256}  go.tar.gz" | sha256sum -c -
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go.tar.gz
  rm go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
  export PATH=$PATH:/usr/local/go/bin
fi
/usr/local/go/bin/go version

echo
echo "=== installing the host's Python packages (hash-pinned) ==="
# cbor2 parses the attestation document in 02e; every wheel is checked
# against its sha256 (scripts/requirements-host.txt).
pip3 install --user --quiet --require-hashes -r "$SCRIPT_DIR/requirements-host.txt"
python3 -c 'import cbor2, importlib.metadata as m; print("cbor2", m.version("cbor2"))'

echo
echo "=== nitro-cli version ==="
nitro-cli --version

echo
echo "=== ✓ bootstrap complete ==="
echo "IMPORTANT: log out and SSH back in (so 'ne' and 'docker' group memberships take effect)"
echo "Then run: ./scripts/02-build-enclave-image.sh"
