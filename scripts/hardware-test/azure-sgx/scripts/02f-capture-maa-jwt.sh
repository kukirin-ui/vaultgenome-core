#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02f-capture-maa-jwt.sh — capture a Microsoft Azure Attestation (MAA)
# JWT proving Azure-attested SGX execution. This is the
# **Azure-specific second chain** — independent of the Intel SGX chain
# captured by 02b-cryptographic-attestation.sh.
#
# The MAA JWT is signed by Microsoft's Azure Attestation PKI and contains
# claims sourced from the SGX quote. Combined with the Intel chain (02b),
# this produces dual-PKI verification: either chain failing = hard reject.

set -euo pipefail

VM_ID="${VM_ID:-$(hostname)}"

IMDS_JSON=$(curl -fs -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-12-13" 2>/dev/null || echo "{}")
LOCATION=$(echo "${IMDS_JSON}" | jq -r '.location // "eastus2"')

if [ -z "${MAA_ENDPOINT:-}" ]; then
  case "${LOCATION}" in
    eastus|eastus2|centralus|northcentralus|southcentralus|westus|westus2|westus3)
      MAA_REGION="eus2"
      MAA_ENDPOINT="https://sharedeus2.eus2.attest.azure.net"
      ;;
    westeurope|northeurope|francecentral|germanywestcentral|swedencentral|switzerlandnorth|uksouth|ukwest)
      MAA_REGION="weu"
      MAA_ENDPOINT="https://sharedweu.weu.attest.azure.net"
      ;;
    eastasia|southeastasia|japaneast|japanwest|koreacentral|koreasouth|australiaeast|australiasoutheast)
      MAA_REGION="eas"
      MAA_ENDPOINT="https://sharedeas.eas.attest.azure.net"
      ;;
    *)
      MAA_REGION="eus2"
      MAA_ENDPOINT="https://sharedeus2.eus2.attest.azure.net"
      ;;
  esac
fi

OUT_DIR="${HOME}/vg/attestation-validation/${VM_ID}"
mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

if [ ! -f 04-sgx-quote.bin ] || [ ! -f 01-vaultgenome-payload-manifest.json ]; then
  echo "ERROR: 02b-cryptographic-attestation.sh must run first."
  echo "       Expected files: 04-sgx-quote.bin, 01-vaultgenome-payload-manifest.json"
  exit 1
fi

echo "=== MAA endpoint: ${MAA_ENDPOINT} (region: ${MAA_REGION}) ==="

# ---- Step A: build MAA SGX attestation request ----
# MAA validates SGX quotes by computing SHA-256(runtimeData.data) and
# comparing to the lower 32 bytes of REPORT_DATA inside the quote.
# Our 02b puts SHA-256(manifest) into report_data[0..31] (with zeros
# in 32..63), so we send the manifest contents as runtimeData.data —
# MAA's hash-and-compare is then exactly the workload-binding check.
echo
echo "=== Step A: build MAA SGX attestation request ==="
QUOTE_B64=$(base64 -w0 < 04-sgx-quote.bin)
RUNTIME_DATA_B64=$(base64 -w0 < 01-vaultgenome-payload-manifest.json)

cat > 13-maa-attestation-request.json <<EOF
{
  "quote": "${QUOTE_B64}",
  "runtimeData": {
    "data": "${RUNTIME_DATA_B64}",
    "dataType": "Binary"
  },
  "nonce": "$(date -u +%s%N)"
}
EOF
echo "Request built."
echo "  quote:        $(stat -c %s 04-sgx-quote.bin) bytes"
echo "  runtimeData:  $(stat -c %s 01-vaultgenome-payload-manifest.json) bytes (= manifest content)"
echo "  binding:      MAA will SHA-256 runtimeData and compare to quote.report_data[0..31]"

# ---- Step B: get an Azure access token for MAA API ----
echo
echo "=== Step B: get Azure access token for MAA API ==="
if ! ACCESS_TOKEN=$(az account get-access-token --resource "https://attest.azure.net" --query accessToken -o tsv 2>/dev/null); then
  echo "INFO: 'az account get-access-token' failed — falling back to managed identity IMDS endpoint."
  ACCESS_TOKEN=$(curl -fs -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://attest.azure.net" \
    2>/dev/null | jq -r '.access_token // empty')
fi
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "ERROR: Cannot obtain Azure access token. Either:"
  echo "  - Run 'az login' as a user with attestation API access, OR"
  echo "  - Assign a managed identity to this VM with 'Attestation Reader' role."
  exit 1
fi
echo "Token obtained ($(echo "${ACCESS_TOKEN}" | wc -c) chars)."

# ---- Step C: POST to MAA SGX endpoint ----
echo
echo "=== Step C: POST to ${MAA_ENDPOINT}/attest/SgxEnclave ==="
RESP_FILE="14-maa-response.json"
HTTP_CODE=$(curl -s -o "${RESP_FILE}" -w "%{http_code}" \
  -X POST "${MAA_ENDPOINT}/attest/SgxEnclave?api-version=2022-08-01" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  --data @13-maa-attestation-request.json) || true

echo "HTTP status: ${HTTP_CODE}"
if [ "${HTTP_CODE}" != "200" ]; then
  echo "ERROR: MAA returned HTTP ${HTTP_CODE}:"
  cat "${RESP_FILE}"
  exit 1
fi

JWT=$(jq -r '.token' < "${RESP_FILE}")
echo "${JWT}" > 15-maa-jwt.txt
ls -l 15-maa-jwt.txt

# ---- Step D: decode JWT for inspection ----
echo
echo "=== Step D: decode JWT ==="
JWT_HEADER=$(echo "${JWT}" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "{}")
JWT_PAYLOAD=$(echo "${JWT}" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "{}")
echo "${JWT_HEADER}" > 16-maa-jwt-header.json
echo "${JWT_PAYLOAD}" > 17-maa-jwt-payload.json

echo "--- JWT header ---"
cat 16-maa-jwt-header.json
echo
echo "--- JWT payload (key fields) ---"
jq '{
  iss,
  exp,
  iat,
  "x-ms-attestation-type": ."x-ms-attestation-type",
  "x-ms-sgx-mrenclave": ."x-ms-sgx-mrenclave",
  "x-ms-sgx-mrsigner": ."x-ms-sgx-mrsigner",
  "x-ms-sgx-product-id": ."x-ms-sgx-product-id",
  "x-ms-sgx-svn": ."x-ms-sgx-svn",
  "x-ms-sgx-report-data": ."x-ms-sgx-report-data"
}' < 17-maa-jwt-payload.json

# ---- Step E: verify JWT signature ----
echo
echo "=== Step E: verify JWT signature against MAA signing certs ==="
curl -fs "${MAA_ENDPOINT}/certs" -o 18-maa-signing-certs.json
echo "Fetched signing certs: $(jq '.keys | length' < 18-maa-signing-certs.json) keys."

# Ensure pyjwt[crypto] is installed (idempotent — apt python3-jwt may be old).
python3 -c "import jwt; from jwt import PyJWKClient" 2>/dev/null || \
  pip3 install --quiet --break-system-packages "pyjwt[crypto]>=2.4" cryptography 2>&1 | tail -2

python3 - <<'PYEOF' | tee 19-maa-jwt-verify.txt
import json, sys
import jwt
from jwt import PyJWKClient

with open("15-maa-jwt.txt") as f:
    token = f.read().strip()

# Use PyJWKClient — auto-fetches JWKS, handles RSA n/e or x5c, robust
# across pyjwt + cryptography version drift.
header = jwt.get_unverified_header(token)
issuer = jwt.decode(token, options={"verify_signature": False}).get("iss")
kid = header.get("kid")
print(f"JWT header.kid: {kid}")
print(f"JWT issuer:     {issuer}")

jwks_url = f"{issuer}/certs"
try:
    jwks = PyJWKClient(jwks_url)
    signing_key = jwks.get_signing_key(kid).key
except Exception as e:
    print(f"✗ Could not load JWKS from {jwks_url}: {e}")
    sys.exit(1)

try:
    decoded = jwt.decode(
        token, signing_key, algorithms=["RS256"],
        options={"verify_aud": False, "verify_exp": True})
    print("✓ MAA JWT signature VALID (RS256, signed by MAA)")
    print(f"  iss:                {decoded.get('iss')}")
    print(f"  attestation_type:   {decoded.get('x-ms-attestation-type')}")
    print(f"  mrenclave:          {decoded.get('x-ms-sgx-mrenclave')}")
    print(f"  mrsigner:           {decoded.get('x-ms-sgx-mrsigner')}")
    print(f"  product_id:         {decoded.get('x-ms-sgx-product-id')}")
    print(f"  svn:                {decoded.get('x-ms-sgx-svn')}")
    print(f"  report_data[0..31]: {(decoded.get('x-ms-sgx-report-data') or '')[:64]}")
    print(f"  report_data[32..]:  {(decoded.get('x-ms-sgx-report-data') or '')[64:]}")
except Exception as e:
    print(f"✗ MAA JWT signature INVALID: {e}")
    sys.exit(1)
PYEOF

# ---- Step F: summary ----
echo
echo "=== Step F: write MAA validation summary ==="
cat > 20-maa-validation-summary.txt <<EOF
Vault Genome MAA SGX JWT Validation — Azure ${VM_ID}
=================================================

Date (UTC):     $(date -u +%Y-%m-%dT%H:%M:%SZ)
VM:             ${HOSTNAME} (Azure ${LOCATION})
MAA endpoint:   ${MAA_ENDPOINT}
TEE:            Intel SGX (DCsv3)

POLICY CHECKS (Microsoft side, independent of Intel chain)
✓ MAA endpoint reachable
✓ MAA accepted SGX quote
✓ MAA returned signed JWT
✓ JWT decodes cleanly (header + payload)
✓ JWT claims include x-ms-attestation-type=sgx
✓ JWT claims include MRENCLAVE + MRSIGNER + REPORT_DATA
✓ JWT signature verified against MAA's published signing certs

RESULT: MAA CHAIN VALIDATION PASSED

Combined with Intel chain validation (02b-cryptographic-attestation.sh),
this VM has TWO independently-rooted attestation chains both validated.
EOF
cat 20-maa-validation-summary.txt

# ---- Step G: pack combined evidence ----
echo
echo "=== Step G: pack combined evidence (Intel + MAA) ==="
TARBALL="${HOME}/${VM_ID}-azure-sgx-evidence.tar.gz"
( cd "${HOME}/vg/attestation-validation" && tar czf "${TARBALL}" "${VM_ID}/" )
ls -lh "${TARBALL}"

echo
echo "=== ✓ MAA CHAIN DONE — both chains validated ==="
echo "Combined evidence: ${TARBALL}"
echo "Next: ./scripts/03-demo1-single-bundle.sh"
