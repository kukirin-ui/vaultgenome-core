# Vault Genome — AWS Nitro Enclaves Hardware Validation Kit

Reproducible end-to-end validation kit for running the Vault Genome
continuity layer on AWS EC2 instances with Nitro Enclaves enabled.

This package is the AWS counterpart to the GCP SEV-SNP kit at
`core/scripts/hardware-test/gcp-sev-snp/`. It provisions a real
EC2 instance with Nitro Enclaves, builds and runs a Vault Genome
enclave image, captures the AWS Nitro attestation document
(COSE_Sign1, ~3 KB), validates the cryptographic chain against
AWS Nitro Root CA, and runs the full Vault Genome demo suite.

Total reproduction time: ~30-45 minutes per instance, including
Llama 3.2 3B model download.

## What this kit produces

After running the kit end-to-end against one EC2 instance, you will have:

1. A real EC2 m5.xlarge instance with Nitro Enclaves enabled
2. A `.eif` (Enclave Image Format) built from acpctl source — its
   PCR0 (SHA-384 of the enclave content) is captured for KMS policy binding
3. A real AWS Nitro Enclaves attestation document (CBOR-encoded
   COSE_Sign1) signed by the AWS Nitro hypervisor's per-instance certificate
4. Verified cert chain: AWS Nitro Root CA → regional intermediate →
   per-instance leaf → COSE_Sign1 signature
5. Workload binding: `user_data` field in the attestation = SHA-512 of a
   manifest describing the enclave build — chip-signed proof that this
   attestation describes *this* workload
6. Demo 1 evidence — full Llama 3.2 3B model sealed and restored
   byte-identical, with `acpctl genome verify` confirming every blob
   hash matches the envelope record
7. Demo 2 evidence — chain of 6 generations sealed, chain-validated,
   lineage walked back to genesis, mid-chain rewind
8. Tamper detection evidence — 1-byte flip in the sealed payload
   produces an AES-256-GCM authentication failure
9. (Optional) Inference comparison — same prompt + seed against
   original and restored daemons producing byte-identical output

For a full N-instance cohort matching the GCP test scope:
- Run the orchestrator N times across different AZs (us-east-2a/b/c/d)
- Then run `scripts/07-cross-vm-matrix.sh` on your laptop to collate
  the evidence into a single `CROSS-VM-MATRIX.md` report showing N
  unique Nitro Module IDs, N unique attestation signatures, and
  per-VM check status.

## Prerequisites

- An AWS account with billing enabled
- Service Quota: at least 16 vCPUs of "Running On-Demand Standard
  instances" in your region (the default 5 vCPUs is too low — see
  Service Quotas console). Submit a quota increase to **32 vCPUs** to
  run 4× m5.xlarge in parallel.
- An EC2 KeyPair created in your target region — download the .pem and
  place at `~/.ssh/<key-name>.pem` with `chmod 600`
- IAM permission to create EC2 instances, IAM roles, and security groups
  (typical "AdministratorAccess" or a custom role with `ec2:*`,
  `iam:CreateRole`, `iam:PutRolePolicy`, `iam:CreateInstanceProfile`)
- `terraform >= 1.5` installed locally
- `aws` CLI configured with credentials (`aws configure`)
- ~30-45 minutes per instance
- About $1-3 per instance (m5.xlarge = $0.192/hour × ~5 hours wall time)

## Architecture (parent EC2 + child enclave)

```
[ your laptop ]
       │
       │  terraform apply
       ▼
[ EC2 m5.xlarge — parent host (Amazon Linux 2023) ]
   │
   ├── /dev/nitro_enclaves         allocator interface
   ├── nitro-cli                   Build/run/terminate enclaves
   ├── /usr/local/bin/acpctl       Vault Genome CLI (built from source)
   ├── /usr/share/ollama           Llama 3.2 3B model (~2 GB)
   ├── ~/vg/enclave-build/         .eif image + build manifest
   └── ~/vg/attestation-validation/ all captured outputs
       │
       │  vsock (parent ↔ enclave)
       ▼
[ Vault Genome Enclave (child VM running .eif) ]
   ├── /dev/nsm                    Nitro Security Module device
   ├── acpctl in-enclave           handles attestation request
   └── (no disk, no network)       enclave is isolated by design
```

The Vault Genome workflow:
- **Seal/restore** runs on parent EC2 (where the model files live)
- **Attestation** comes from the enclave (where /dev/nsm is)
- **REPORT_DATA binding** = SHA-512 of build manifest, embedded in
  attestation `user_data` field — analogous to GCP SEV-SNP REPORT_DATA

## Quick start — one command

```bash
# Set required env (edit to match your AWS setup)
export TF_VAR_ssh_key_name="my-aws-keypair"
export TF_VAR_region="us-east-2"
export TF_VAR_availability_zone="us-east-2a"

# Run the full pipeline (provisions, tests, packs, downloads, destroys)
cd vaultgenome-core/scripts/hardware-test/aws-nitro/
./examples/full-test-run.sh
```

The runner takes ~30-45 minutes and emits an evidence tar archive
in your current directory at the end.

## Step-by-step (if you want to inspect each phase)

```bash
# 1. Provision EC2 with Nitro Enclaves enabled
cd terraform/
export TF_VAR_ssh_key_name="my-aws-keypair"
terraform init
terraform apply

# 2. SSH into the instance (terraform output prints the command)
INSTANCE_IP=$(terraform output -raw public_ip)
ssh -i ~/.ssh/${TF_VAR_ssh_key_name}.pem ec2-user@$INSTANCE_IP

# 3. On the EC2 instance — bootstrap (install nitro-cli, Docker, Go)
~/scripts/01-bootstrap-vm.sh
# Log out + log back in (so 'ne' and 'docker' groups take effect)

# 4. Build enclave image .eif (PCR0 captured)
~/scripts/02-build-enclave-image.sh

# 5. Run enclave + capture attestation document
~/scripts/02-capture-attestation.sh

# 6. Verify cert chain against AWS Nitro Root CA
~/scripts/02b-cryptographic-attestation.sh

# 7. Pull a model + run Demo 1
~/scripts/03-demo1-single-bundle.sh

# 8. Run Demo 2 (chain of 6 generations)
~/scripts/04-demo2-chain.sh

# 9. (Optional) inference comparison
~/scripts/05-inference-test.sh

# 10. Pack evidence
~/scripts/06-pack-evidence.sh

# 11. Cleanup (back on laptop)
exit
cd terraform/ && terraform destroy
```

## Multi-instance cross-attestation matrix

For an N-instance cohort proving N distinct physical Nitro security modules:

```bash
# Run the full pipeline N times in different AZs
for az in us-east-2a us-east-2b us-east-2c us-east-2d; do
  TF_VAR_availability_zone=$az \
  TF_VAR_instance_name=vault-genome-nitro-$az \
    ./examples/full-test-run.sh
done

# Each run produces its own evidence tar archive in the current dir.
# Untar them into a directory layout like:
mkdir -p ~/Desktop/AWS-Nitro-Real-Hardware-Test/Cryptographic-Chain-Validation
cd ~/Desktop/AWS-Nitro-Real-Hardware-Test/Cryptographic-Chain-Validation
mkdir 01-VM1-us-east-2a 02-VM2-us-east-2b 03-VM3-us-east-2c 04-VM4-us-east-2d
# (extract each tar into the matching dir)

# Then collate:
~/path/to/core/scripts/hardware-test/aws-nitro/scripts/07-cross-vm-matrix.sh \
  ~/Desktop/AWS-Nitro-Real-Hardware-Test/Cryptographic-Chain-Validation/
# Produces CROSS-VM-MATRIX.md with all checks side-by-side.
```

## Cross-region / cross-AZ variants

For full disaster-recovery story, repeat steps in a second AWS region
(e.g. `eu-west-1`). Bundle from the first instance can then be transferred
via S3 and restored on the second — bytes will be identical (verify pass)
and inference output will match. This is the AWS analog of our GCP
us-central1 → europe-west4 cross-region restore.

For our reference Week 2 validation we ran:
- VM1: us-east-2a (Ohio) — primary
- VM2: us-east-2b — cross-AZ same region
- VM3: us-east-2c — cross-AZ same region
- VM4: eu-west-1a (Ireland) — cross-region disaster-recovery target

## What's *not* in this kit

- **Multi-cloud / cross-cloud** — this kit covers AWS Nitro Enclaves only.
  GCP SEV-SNP is in `gcp-sev-snp/`. Azure SGX, Intel SGX bare metal, and
  cross-cloud KMS-mediated restore are separate kits or planned for
  Weeks 3-6 of the multi-TEE testing sprint.

- **Production-mode enclave attestation** — the kit captures attestation
  in `--debug-mode` (which zeroes PCR0/PCR1/PCR2 by AWS design — debug
  enclaves are explicitly not trustworthy in production). The chain
  validation steps still exercise the same code path. For production
  attestation, build the enclave without `--debug-mode` and either:
  (a) run a vsock-based attestation client in the enclave to export the
  document, or (b) use AWS KMS attestation-conditional decryption.

- **AGPL / commercial licensing decisions** — the bundle format and
  the conformance suite are AGPL. The reproducible deployment package
  itself (Terraform, scripts, README) is shared under your NDA scope.

## What our Week 2 test produced

A reference cohort produced from running this kit against four EC2 instances
across two AWS regions and four availability zones. Each VM passed all four
cryptographic checks (cabundle integrity, AWS Nitro Root CA G1 anchor,
COSE_Sign1 ECDSA P-384 signature, user_data SHA-512 binding).

| VM  | Region              | AZ           | Module ID                                  |
|-----|---------------------|--------------|--------------------------------------------|
| VM1 | us-east-2 (Ohio)    | us-east-2a   | `i-009208835ad0028a4-enc019e03e0a7156d1f`  |
| VM2 | us-east-2 (Ohio)    | us-east-2b   | `i-002dda1f31b5bf955-enc019e03ff519e08de`  |
| VM3 | us-east-2 (Ohio)    | us-east-2c   | `i-02414476f562d2cf0-enc019e0406d306ac66`  |
| VM4 | eu-west-1 (Ireland) | eu-west-1a   | `i-09f511fb6ad35468f-enc019e042695c8989a`  |

Sanitized excerpts (rendered matrix + per-VM parsed JSONs) committed to this
repo at `evidence/`. The raw COSE_Sign1 attestation documents, .eif build
artifacts, and full evidence tarballs are shared under NDA — see the
founders' Desktop pack (`~/Desktop/AWS-Nitro-Real-Hardware-Test/`).

See `evidence/CROSS-VM-MATRIX.md` for the full validation matrix and
`evidence/README.md` for context.

## Re-validating captured evidence with the shipping verifier

The daemons' own Nitro verifier (`internal/shared/tee`, ADR 0024) audits a
captured document offline, at the document's own timestamp by default —
the hypervisor's signing certificate expires three hours after it signed:

```bash
acpctl attest nitro --doc 04-attestation-document.bin \
  --expected-pcr0 "$(jq -r .expected_pcr0 02d-expected-pcrs.json)" [--json]
```

Exit 0 and `VERIFIED at <capture time>` mean the envelope decoded, the
chain reached the pinned AWS Nitro Enclaves Root G1, the ES384 signature
held and PCR0 is the image's. `evidence/0N-*/07-go-verifier-audit.json`
holds that output for the four production documents of May 2026.

## Re-validating captured evidence offline

If you have a captured `04-attestation-document.bin` and the AWS Nitro
Root CA G1 PEM, you can re-run the cryptographic validation independently
on any machine (no AWS account required):

```bash
cd evidence/01-VM1-us-east-2a/   # or any cohort dir
pip install cryptography cbor2
../../scripts/08-normalize-attestation-output.py .
```

This re-parses the COSE_Sign1, walks the cert chain, verifies the ECDSA P-384
signature, and confirms the user_data binding — overwriting
`06-chain-validation.json` with the unified schema expected by
`scripts/07-cross-vm-matrix.sh`.

## Support

ops@vaultgenome.com — we read every message.

If you're a security researcher who finds a bug while running this kit,
see `SECURITY.md` in the repo root for our coordinated disclosure
process.

---

*Vault Genome Inc. · AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts*
