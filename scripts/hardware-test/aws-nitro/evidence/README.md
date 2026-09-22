# AWS Nitro Enclaves — captured cohort evidence (production-mode)

This directory contains **sanitized excerpts** from the May 2026 4-VM AWS Nitro
Enclaves validation sprint, **production-mode** (auditor-grade). The full
evidence pack (raw 4.5 KB COSE_Sign1 attestation documents, .eif build
artifacts, vsock-attest binaries, console captures) is shared under NDA
— see `SECURITY.md` in the repo root.

## What's here

```
evidence/
├── README.md                             ← this file
├── CROSS-VM-MATRIX.md                    ← rendered cross-VM matrix (production-grade)
└── 0N-VM<N>-<az>/                        ← one dir per cohort VM
    ├── 00-vm-identity.txt                ← instance_id, region, AZ, mode
    ├── 02d-expected-pcrs.json            ← EXPECTED PCR0/1/2 from describe-eif
    ├── 05-attestation-parsed.json        ← module_id, pcr0/1/2 (NON-ZERO), user_data
    ├── 06-chain-validation.json          ← all 4 cryptographic checks + cert chain + production_grade
    ├── 06-pcr-binding-check.json         ← per-PCR captured-vs-expected delta
    └── 07-go-verifier-audit.json         ← the same document audited by the shipping verifier
                                             (`acpctl attest nitro --json`, ADR 0024, 2026-09-22)
```

## Cohort

| VM  | Region              | AZ           | Module ID                                       |
|-----|---------------------|--------------|-------------------------------------------------|
| VM1 | us-east-2 (Ohio)    | us-east-2a   | `i-0e35190ae3157095d-enc019e0512a5715d4f`       |
| VM2 | us-east-2 (Ohio)    | us-east-2b   | `i-0bd337f6016592526-enc019e051510f2b161`       |
| VM3 | us-east-2 (Ohio)    | us-east-2c   | `i-048db5e223f6854af-enc019e0516e3dcf1e8`       |
| VM4 | eu-west-1 (Ireland) | eu-west-1a   | `i-0bd0777f07917c095-enc019e05191df392d3`       |

All four cohort entries pass **all six production-grade checks**:

1. Cabundle integrity (chain valid)
2. AWS Nitro Root CA G1 anchor
3. COSE_Sign1 signature (ECDSA P-384)
4. user_data SHA-512 binding to workload manifest
5. **PCR0 non-zero** (proves enclave was launched WITHOUT --debug-mode)
6. **PCR0 matches expected** (chip's PCR0 in attestation == PCR0 from
   `nitro-cli describe-eif` of the deployed .eif → proves running enclave
   content equals the built image)

The shared production-mode `.eif` PCR0:
`69d556eff8606bd9828baaac20612f03851f29ddd989387ce5ab3a9cde8917add48d78f1f84c53dc2aafedb9ecb8734e`

The shared workload `user_data` (SHA-512 of build manifest):
`6775ac5075b68a5b48767c1cc1e11a28d761158adfd6236da96bac19450a6f2aa37096e477f134baf511368f4fd08135103ebfb2b12093b2e1044cbc3e15f5bb`

See `CROSS-VM-MATRIX.md` for the full per-VM result table.

## Production-mode workflow (vsock-based)

The enclaves were launched **without `--debug-mode`**, which means:
- PCR0/PCR1/PCR2 are **non-zero** (debug-mode forces them to all-zeros by AWS design)
- Console output is unavailable, so the in-enclave attestation client must
  ship the COSE_Sign1 document back to the parent over **vsock** instead

The in-tree binary `vsock-attest/` (Go, ~1.9 MB static) opens a vsock
connection from the enclave to the parent EC2 (CID 3, port 5005), reads the
NSM session attestation, and sends it length-prefixed. The parent runs the
companion Python listener `scripts/vsock-receive.py` to receive + save.

This is the **auditor-grade production attestation path** — the chip's
PCR0 in the resulting attestation document MUST match the EXPECTED PCR0
from `nitro-cli describe-eif`, otherwise the integrity binding fails.

## What is NOT in this directory (NDA-scoped)

- `04-attestation-document.bin` — raw 4.5 KB CBOR/COSE_Sign1 attestation per VM
- `04-attestation-document.b64` — base64 transport-encoded variant
- `vault-genome-attest-prod.eif` — 152 MB Enclave Image Format binary
- `vsock-attest` — compiled Go binary embedded in the .eif
- `06-certificates/` — full per-VM cabundle (Root + 4 intermediates + leaf)
- `01-vaultgenome-enclave-build-manifest.json` — full build manifest
- `02-report-data.bin` / `02-report-data.hex` — the SHA-512 manifest hash bytes

These are available in the founders' Desktop pack
(`~/Desktop/AWS-Nitro-Real-Hardware-Test/`) and shared with NDA-counterparties.

## Reproducing the cohort

Run the kit at `core/scripts/hardware-test/aws-nitro/` against your own AWS
account in 4 different AZs:

```bash
cd vaultgenome-core/scripts/hardware-test/aws-nitro/
# Build prod .eif on first VM (or run debug full-test-run.sh first):
./scripts/02-build-enclave-image.sh
./scripts/02d-build-enclave-image-prod.sh   # NEW: builds prod .eif
./scripts/02e-capture-attestation-prod.sh   # NEW: vsock capture (non-debug)
# Repeat 02e on each cohort VM (with the prebuilt .eif scp'd over)

# Then collate evidence into a fresh root dir and run the matrix builder:
./scripts/07-cross-vm-matrix.sh ./my-evidence-root/
```

Total wall time: ~2 hours for the 4-VM cohort. Total AWS cost: ~$0.50.

## Independent verification (third-party)

Anyone can re-run the cryptographic chain validation **plus PCR binding
check** offline given:
1. The `04-attestation-document.bin` (NDA-scoped above)
2. The `02d-expected-pcrs.json` (expected PCR0 from describe-eif)
3. AWS's published Root CA G1 PEM (downloadable from
   <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>)
4. Python 3 with `cbor2` and `cryptography` installed

Use `scripts/08-normalize-attestation-output.py <vm-dir>` to re-validate.
The 6 checks reproduce the same `production_grade: true` result on any
machine with no AWS account required — the proof is self-contained in the
attestation document + the publicly published Root CA + the EXPECTED PCR0
captured at build time.

---

_**Vault Genome Inc.** · AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts_
