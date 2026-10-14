# Vault Genome — STRIDE threat model

| Last updated | 2026-10-14 ([review record](review-2026-10.md)) |
|--------------|------------|
| Owner        | The maintainers (`GOVERNANCE.md`) |
| Audience     | Enterprise security teams, regulators, auditors |
| Methodology  | STRIDE per platform + Vault Genome control plane (Microsoft 2002) |
| Shipped backends | `gcp-sev-snp`, `gcp-tdx`, `azure-cgpu`; `simulated` for tests only. AWS Nitro, Azure SGX and Intel SGX bare metal are measurement kits (`scripts/hardware-test/`), not shipped verifiers (`VERIFIABLE-CLAIMS.md`) |

This document is the formal threat model for Vault Genome. Each
section identifies:

1. **Trust boundaries** for the platform under analysis.
2. **Assets** that cross those boundaries.
3. **Threats** per STRIDE category (Spoofing, Tampering, Repudiation,
   Information disclosure, Denial of service, Elevation of privilege).
4. **Mitigations** mapped to specific Vault Genome controls
   (`VG-NNN` from [`compliance/crosswalk.md`](../compliance/crosswalk.md))
   or to the underlying TEE primitive.

## Table of contents

- [Vault Genome control plane](#vault-genome-control-plane)
- [AWS Nitro Enclaves](#aws-nitro-enclaves-aws-nitro)
- [Azure Confidential Computing — SGX (azure-sgx)](#azure-confidential-computing--sgx-azure-sgx)
- [GCP Confidential VMs — SEV-SNP (gcp-sev-snp)](#gcp-confidential-vms--sev-snp-gcp-sev-snp)
- [Intel SGX bare metal (intel-sgx-dcap)](#intel-sgx-bare-metal-intel-sgx-dcap)
- [Simulated backend (simulated)](#simulated-backend-simulated)
- [Cross-platform residual risks](#cross-platform-residual-risks)

---

## Vault Genome control plane

This section covers threats above the TEE layer — the orchestrator,
audit log, validation pipeline, and operator-facing surfaces.

### Trust boundaries

```
              ┌─────────────────────────────────────────┐
              │ Operator console (acpctl, REST API)     │
              ├─────────────────────────────────────────┤  ← TLS + ACL
              │ sagvd authority daemon                  │
              │  ├── job queue                          │
              │  ├── HTTP API server                    │
              │  ├── return-path listener (4-frame)     │  ← TEE attestation
              │  ├── validation pipeline                │
              │  ├── audit log (bbolt, append-only)     │
              │  └── keystore (in-memory, sealed at rest)│
              ├─────────────────────────────────────────┤  ← TEE measurement
              │ acp-compute worker (in TEE)              │
              └─────────────────────────────────────────┘
```

Assets crossing each boundary: session secrets, model weights, audit
event chain, attestation evidence, sealed material.

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | Attacker presents a forged worker certificate to sagvd | mutual TLS via worker registry (VG-002, VG-014); attestation in handshake (VG-002, VG-008); MRENCLAVE / PCR0 / launch-MEASUREMENT pinning (per platform) |
| **S** Spoofing | Attacker spoofs an operator API call | mTLS + bearer token on `/v1/jobs` (VG-014); rate-limited + audit-logged (VG-004) |
| **T** Tampering | Attacker modifies audit log entries | append-only bbolt with hash chain (VG-004); doctrine invariant `TestInvariant_07` blocks any non-allowlisted write sink (VG-005) |
| **T** Tampering | Attacker tampers with sealed key material | AAD-bound sealing with hardware-rooted key (VG-003); unseal authentication failure raises Integrity error (handled by `internal/vault/incident/`) |
| **T** Tampering | Attacker modifies validation result on the wire | every validation verdict signed by validator's signing key (VG-019); receiver verifies via `recvvalidator` — doctrine invariant `TestInvariant_06` |
| **R** Repudiation | Operator denies submitting a job they actually submitted | every API call recorded in append-only log with operator identity (VG-004); commit timestamp and request hash bound into hash chain |
| **R** Repudiation | Worker denies producing a candidate output they actually produced | candidate output frame is signed by worker's TEE-bound signing key (VG-002); signature pinned to worker's MRENCLAVE / PCR0 |
| **I** Information disclosure | Operator-side secrets leak via logs | structured `slog.Logger` with `LogValuer` redaction on key material (`internal/vault/keys/`); doctrine invariant `TestInvariant_07b` blocks `os` / `net` / `log` imports inside `vault/disclosure` |
| **I** Information disclosure | Genome plaintext leaks through a non-vault sink | doctrine invariant `TestInvariant_07_NoRawExport` rejects any `os.WriteFile` / `os.OpenFile` / `io.Copy` outside allowlisted paths (VG-005) |
| **I** Information disclosure | Side-channel from sagvd memory (cold-boot, swap) | TEE-protected memory (per platform); systemd hardening `MemoryDenyWriteExecute=true`, `LockPersonality=true` (VG-014); zeroization on `Daemon.Zeroize()` shutdown |
| **D** DoS | Attacker floods `/v1/jobs` to exhaust queue | bounded `JobQueue` capacity + 429 response when full; rate limit at the ingress (operator's responsibility per BAA) |
| **D** DoS | Attacker submits jobs designed to make validation hang | per-stage timeouts in `internal/validation/operational`; circuit breakers in `internal/validation/service` |
| **D** DoS | Attacker forces sagvd to allocate large attestation buffers | `tee.NonceMinBytes` enforces lower bound; per-adapter upper bound on `Evidence` size in `Verify` (e.g., AWS Nitro 64 KiB cap) |
| **E** Elevation of privilege | Worker compromises sagvd by exploiting a return-path deserialisation bug | every protobuf field validated by `recvvalidator` before use (VG-010); doctrine invariant `TestInvariant_06_NoBypassOfReturnValidator` |
| **E** Elevation of privilege | Operator gains worker-level capability | one-way trust: sagvd can issue jobs to workers but cannot execute their code; workers attest into sagvd, not the other way round |

---

### Since 2026-05-06

Decisions that moved the control plane's boundary, each with its record:

| Change | Boundary it touches | Record |
|--------|---------------------|--------|
| Every Return Path decision is on an append-only record before it takes effect; a log that cannot take an event stops the decision | authority ↔ worker; the audit chain | [ADR 0014](../adr/0014-return-path-on-the-record-and-on-hardware.md) |
| The sentinel and policy-driven failover: one policy serial authorises at most one move, the operator's stop list overrides any policy, the primary's word is bounded by the chip's report | authority ↔ standby; the operator | [ADR 0012](../adr/0012-sentinel-and-policy-driven-failover.md), [0017](../adr/0017-limits-on-the-primarys-word.md) |
| The escrow key sealed to the release host's TEE, or to the vTPM where the TEE gives no sealing key | authority ↔ its storage | [ADR 0016](../adr/0016-escrow-key-sealed-to-the-release-host.md), [0022](../adr/0022-the-escrow-key-sealed-to-the-vtpm.md) |
| Every daemon key file sealed to the host, the key's name in the AEAD's associated data | authority and worker ↔ their storage | [ADR 0023](../adr/0023-the-daemons-key-files-sealed-to-the-host.md) |
| Refusals are recorded, with the peer, the phase and the reason | every boundary | [ADR 0010](../adr/0010-operator-stop-and-recorded-refusals.md) |
| The worker restores the genome and computes through the integer door; the gate's verdict is signed | worker ↔ authority | [ADR 0013](../adr/0013-worker-restores-the-genome.md), [0020](../adr/0020-the-integer-door-for-the-lora-worker.md), [0008](../adr/0008-equivalence-gate.md) |

---

## AWS Nitro Enclaves (`aws-nitro`)

> **Kit, not product.** The tree ships no verifier for this backend
> (`VERIFIABLE-CLAIMS.md`, "What we do not claim"); the section states the
> boundary and the properties a verifier would have to establish, and is
> what the measurement kit under `scripts/hardware-test/aws-nitro` is checked
> against.

### Trust boundaries

```
┌───────────────────────────────────────────────────────────┐
│ AWS account / VPC                                          │
│  ┌───────────────────────────────────────────────────────┐│
│  │ Parent EC2 instance                                    ││
│  │  ├── KMS endpoint (mTLS via VPC endpoint)              ││  ← AWS region boundary
│  │  ├── nitro-enclaves-cli (vsock proxy)                  ││  ← parent ↔ enclave boundary
│  │  └── ┌────────────────────────────────────────────┐   ││
│  │      │ Nitro Enclave (vault-genome image)          │   ││  ← TEE measurement boundary
│  │      │  ├── /dev/nsm (NSM)                          │   ││
│  │      │  ├── attestation document signer (NSM root)   │   ││
│  │      │  └── sagvd / acp-compute binary               │   ││
│  │      └────────────────────────────────────────────┘   ││
│  └───────────────────────────────────────────────────────┘│
└───────────────────────────────────────────────────────────┘
```

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | Parent EC2 lies about being a Nitro Enclave when it isn't | NSM device only present inside genuine enclaves; NSM-signed attestation document chains to AWS PCA root (pinned at build); `awsNitroPinnedRoots` |
| **S** Spoofing | Attacker forges an attestation document | document signed by AWS-managed PCA root; signature verified by `verifyCOSESignature` against pinned root; production verifier rejects debug-mode enclaves (`isDebugAttestation`) |
| **T** Tampering | Attacker rebuilds the enclave image with malicious code | PCR0 (enclave image hash) changes deterministically; verifier's `AcceptablePCRSet` only includes blessed PCRs; mismatched PCR0 fails Verify with Integrity error |
| **T** Tampering | KMS key policy modified to allow other principals | AWS IAM audit logs (deployer's responsibility); KMS key policy includes `kms:RecipientAttestation:ImageSha384` condition pinned to expected PCR0 — modifying policy doesn't grant access if PCR0 condition still pins the enclave |
| **R** Repudiation | Parent EC2 instance owner denies an attestation came from their enclave | attestation document includes Module ID (per-enclave UUID); CloudTrail logs enclave start/stop |
| **I** Information disclosure | Parent EC2 reads enclave memory | impossible by design — Nitro hypervisor isolates enclave RAM; AWS Nitro hardware-rooted memory protection |
| **I** Information disclosure | KMS key material leaks | KMS keys never leave HSM; cleartext requested with `RecipientAttestation` only available to enclave bound to the correct PCR0 |
| **I** Information disclosure | Side-channel via shared CPU caches | AWS publishes Nitro hypervisor security model; cache-partitioning at HV layer; we accept "AWS is honest" as a trust assumption — alternative: deploy on Intel SGX bare metal with PRMRR cache flushing |
| **D** DoS | Parent EC2 is terminated mid-session | acpctl recover (VG-007) re-runs sagvd on a fresh enclave with same PCR0; sealed material in S3 / KMS unaffected |
| **D** DoS | NSM device hangs producing attestation | adapter sets per-Quote timeout (default 30s); failed attestation returns Structural error and the daemon refuses to enter the session |
| **E** Elevation of privilege | Attacker compromises Nitro firmware | out of scope — relies on AWS to patch firmware; we verify attestation against PCA root which AWS rotates on firmware changes |
| **E** Elevation of privilege | Attacker swaps an unsigned vsock proxy for the official one | vsock proxy is OUTSIDE the trust boundary; attacker who replaces it can drop connections but cannot decrypt the contents (TLS terminates inside the enclave, not at the proxy) |

### Trust assumptions specific to AWS Nitro

- **Trusted**: AWS Nitro hypervisor, NSM, AWS PCA root, KMS HSMs.
- **Untrusted**: parent EC2 OS, vsock proxy daemon, AWS console
  operator (relative to the enclave's running code).

---

## Azure Confidential Computing — SGX (`azure-sgx`)

> **Kit, not product.** The tree ships no verifier for this backend
> (`VERIFIABLE-CLAIMS.md`, "What we do not claim"); the section states the
> boundary and the properties a verifier would have to establish, and is
> what the measurement kit under `scripts/hardware-test/azure-sgx` is checked
> against.

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | Attacker forges an SGX quote | quote signed by platform's PCK chained to Intel SGX Root CA; verified locally (DCAP) or via MAA JWT signed by Microsoft (MAA mode) |
| **S** Spoofing | MAA endpoint impersonation | TLS to `*.attest.azure.net` with HSTS; JWT verification against MAA's published JWKS pinned in config |
| **T** Tampering | Attacker rebuilds enclave with malicious code | MRENCLAVE changes; verifier's `AcceptableMRENCLAVES` set rejects unpinned values; `MRSIGNER` enforced if non-empty |
| **T** Tampering | Attacker swaps Quoting Enclave (QE) for malicious one | QE identity verified as part of DCAP collateral; PCCS-served collateral pinned to Intel-published QE identities |
| **R** Repudiation | Workers in different DCsv2 regions claim the same identity | MRENCLAVE alone is insufficient — Vault Genome combines MRENCLAVE with Microsoft-issued attestation token's `x-ms-policy-hash` claim |
| **I** Information disclosure | Side-channel against SGX (Spectre, Foreshadow, MDS, Plundervolt) | Intel publishes microcode + ISVSVN updates; verifier's `MinISVSVN` floor rejects revoked enclave versions; operators must update the floor on each Intel TCB Recovery Event |
| **I** Information disclosure | Operator-side memory dump of the worker process leaks SGX-derived keys | impossible — SGX sealing key is in protected memory; the only externally-visible bytes are sealed ciphertext |
| **D** DoS | MAA endpoint unavailable | DCAP fallback mode (offline verification) supported; verifier mode set per-deployment via `AzureSGXVerifierConfig.Mode` |
| **D** DoS | PCCS unavailable in DCAP mode | operator's responsibility to mirror collateral; refresh interval `CollateralRefreshInterval` tuneable; cached collateral usable until expiry |
| **E** Elevation of privilege | Attacker leverages a known SGX TCB vulnerability | enforce minimum TCB via `MinISVSVN`; revocation visible through MAA `x-ms-tcb-status` claim; verifier rejects "OutOfDate" or "Revoked" status |

---

## GCP Confidential VMs — SEV-SNP (`gcp-sev-snp`)

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | Attacker forges a SEV-SNP report | report signed by VCEK (per-CPU AMD-issued cert); VCEK chains to AMD Root CA (ARK); `verifyAMDChain` checks against pinned `AMDRootPEM` |
| **S** Spoofing | Attacker presents a stale report | `REPORT_DATA[:32] = SHA-256(nonce)` binds report to challenger nonce; verifier checks `nonceMatchesReportDataSEV` |
| **T** Tampering | Attacker rebuilds VM image with malicious code | launch MEASUREMENT (SHA-384 of guest pages at launch) changes; `AcceptableMeasurements` set is the policy; HOST_DATA pinning available for hypervisor-set context |
| **T** Tampering | Attacker swaps the VCEK for an attacker-controlled one | VCEK chain validation rejects any cert not issued by AMD's KDS; KDS lookup keyed on CHIP_ID + reported TCB |
| **R** Repudiation | Two VMs with same image claim different chip IDs | CHIP_ID is unique per AMD CPU + VM instance UUID; sagvd records CHIP_ID + REPORT_ID per session; 7-year audit retention via Terraform-provisioned Cloud Storage with versioning |
| **I** Information disclosure | Hypervisor reads guest memory | SEV-SNP hardware encrypts guest memory under per-VM key derived from chip; HV cannot decrypt |
| **I** Information disclosure | Side-channel via shared L3 cache between guests | AMD publishes SEV-SNP security model; we accept "AMD is honest" trust assumption; for stricter isolation deploy on Intel SGX bare metal with PRMRR or AWS Nitro with dedicated CPU |
| **D** DoS | AMD KDS unavailable when fetching VCEK | per-CHIP_ID + per-TCB cache (`vcekCache`); GCP mirrors KDS at `confidentialcomputing.googleapis.com`; air-gapped operators can pre-populate the cache via `--amd-kds-url` override |
| **D** DoS | Attacker triggers CPU PRECONDITIONS via flood of report requests | `/dev/sev-guest` rate-limited at kernel level; per-Quote producer mutex serialises calls |
| **E** Elevation of privilege | SEV-SNP TCB rollback to vulnerable firmware | `MinReportedTCB` floor in verifier; AMD security advisories trigger TCB bump; failed match raises Integrity error |

---

## Intel SGX bare metal (`intel-sgx-dcap`)

> **Kit, not product.** The tree ships no verifier for this backend
> (`VERIFIABLE-CLAIMS.md`, "What we do not claim"); the section states the
> boundary and the properties a verifier would have to establish, and is
> what the measurement kit under `scripts/hardware-test/intel-sgx` is checked
> against.

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | Attacker presents a quote from a non-attested SGX system | DCAP local verification chains to Intel SGX Root CA (`IntelRootPEM`); failed chain validation returns Integrity error |
| **S** Spoofing | Attacker uses an unsigned enclave | MRSIGNER pinning rejects unblessed signers; `AcceptableMRSIGNERS` is the operator's policy |
| **T** Tampering | Operator with physical access reads SGX-sealed data | hardware-defended; even with physical access the sealing key is bound to the chip's fuses and PRMRR. Defence-in-depth: wrap the SGX-sealed blob with HSM key (`hsmWrap` / `IntelSGXSealer.hsmSlot`) |
| **T** Tampering | PCCS serves stale collateral | `CollateralRefreshInterval` enforces freshness; operators must mirror Intel's published TCB info + QE identity + PCK CRL on schedule |
| **R** Repudiation | Operator denies an enclave produced a particular output | quote includes ISVPRODID + ISVSVN + REPORT_DATA; sagvd's audit log records every release with the verified MRENCLAVE |
| **I** Information disclosure | Side-channel attacks (Foreshadow, RIDL, ZombieLoad, MDS, Plundervolt) | enforce minimum TCB via `MinISVSVN`; operators required to disable SMT for high-risk deployments (banking config); HSM-wrap defence-in-depth |
| **I** Information disclosure | Cold-boot attack on RAM | SGX integrity tree validates RAM contents on each access; PRMRR-protected pages encrypted with chip-resident key |
| **D** DoS | PCCS down → no fresh collateral | operator runs PCCS locally (sovereign deployment requirement); cached collateral usable until configured expiry |
| **D** DoS | SGX driver wedge under high load | per-Producer mutex serialises ECALLs; daemon health probe surfaces stuck Quote calls (operator alerts via Prometheus `vg_tee_attestation_total{result="error"}`) |
| **E** Elevation of privilege | Privileged OS user calls into the enclave with crafted parameters | enclave EDL declares parameter directions explicitly (`[in]`, `[out]`, `[user_check]`); no `[user_check]` in our enclave; ECALL signature verified by SGX SDK |

### Trust assumptions specific to Intel SGX bare metal

- **Trusted**: Intel SGX hardware, Intel SGX Root CA, operator's
  PCCS server, operator's HSM (if HSM-wrap enabled).
- **Untrusted**: BIOS / firmware (verified at boot via TXT/measured
  boot, deployment responsibility), OS kernel (relative to the
  enclave's running code).
- **Compromised at deployment time**: an attacker with bare-metal
  physical access who has not yet observed an enclave run can
  potentially extract sealing keys via cold-boot or chip-decap
  attacks — operators with this threat model must combine SGX with
  HSM-wrap (`IntelSGXSealer.hsmSlot`) and physical security controls
  (locked cage, intrusion sensors).

---

## GCP Confidential VMs — Intel TDX (`gcp-tdx`)

Added 2026-10-14 ([ADR 0018](../adr/0018-intel-tdx-on-the-return-path.md),
shipped 2026-09-16; proven on a Trust Domain, VERIFIABLE-CLAIMS C21, C23).

### Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ GCP project                                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Trust Domain (confidential VM, Intel TDX)               │ │  ← TD memory encrypted; host hypervisor untrusted
│  │  ├── MRTD ‖ RTMR0..3 = the measurement the peer pins    │ │
│  │  ├── configfs-tsm (tdx_guest): quotes for REPORTDATA    │ │  ← quote signed by the host's Quoting Enclave
│  │  ├── vTPM: the escrow key and key files sealed (0022/23)│ │
│  │  └── sagvd / acp-compute / acp-bootstrap                │ │
│  └────────────────────────────────────────────────────────┘ │
│  Intel PCS (or a PCCS mirror): TCB info, QE identity         │  ← signed documents, cached
└─────────────────────────────────────────────────────────────┘
```

Assets crossing the boundaries: the handshake nonce and the quote; the
measurement pin; Intel's TCB and QE documents; the escrow key and the
daemons' key files (sealed, ADR 0022/0023).

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | A machine that is not a Trust Domain presents a quote | the quote (version 4, ECDSA-P256 attestation key) is signed by the host's Quoting Enclave; the attestation key is certified by the platform's PCK certificate, whose chain the verifier checks to the Intel SGX Root CA; the QE report's binding of the attestation key is checked (`gcp_tdx_quote.go`, `TestTDXVerifierRefusesWhatItShould`) |
| **S** Spoofing | A stale or replayed quote | `REPORTDATA = SHA-256(nonce) ‖ 32 zero bytes`, the same binding as SEV-SNP's REPORT_DATA; the verifier checks the nonce of this handshake |
| **T** Tampering | The guest image or boot chain is rebuilt | the measurement is `SHA-384(MRTD ‖ RTMR0 ‖ RTMR1 ‖ RTMR2 ‖ RTMR3)`: firmware, configuration, kernel, initrd and command line in one value; the peer pins it (`acceptable_measurements`), and the producer refuses to serve a quote whose registers differ from its first |
| **T** Tampering | Forged or stale TCB info or QE identity from the PCS path | both documents are signed by Intel; signatures are verified before use (`gcp_tdx_pcs.go`, `TestTDXPCSDocumentsAreVerifiedBeforeUse`); a PCCS mirror is reached through, not trusted |
| **R** Repudiation | A peer denies a handshake or a release | the quote's REPORTDATA, the measurement and the verdict are on the Return Path's append-only record before the decision takes effect (ADR 0014) |
| **I** Information disclosure | The host reads the Trust Domain's memory | TDX encrypts TD memory under a per-TD key; the hypervisor is outside the boundary by design |
| **I** Information disclosure | Keys at rest on the guest's disk | no sealing key from TDX itself: the escrow key and every daemon key file are sealed to the vTPM under a policy of the pinned boot (`vtpm_sealer.go`, ADR 0022/0023); another boot or machine does not open them |
| **I** Information disclosure | Side channels not yet public | accepted residual risk (cross-platform table); TCB status floors raise with Intel's advisories |
| **D** DoS | Intel PCS unavailable | TCB and QE documents cached (`pcs_cache_dir`); the operator may run a PCCS mirror; a missing document is a refusal, not a pass |
| **E** Elevation of privilege | A TCB rolled back to a vulnerable level | the TCB status of the quote is evaluated against the documents (`TestTDXTCBEvaluation`); a status below the policy's floor is refused |

---

## Azure confidential GPU VM — SEV-SNP, vTPM and an H100 (`azure-cgpu`)

Added 2026-10-14 ([ADR 0019](../adr/0019-a-confidential-gpu-worker-on-azure.md),
[0021](../adr/0021-the-verifiers-own-evaluation-of-the-gpu.md),
[0022](../adr/0022-the-escrow-key-sealed-to-the-vtpm.md); shipped
2026-09-16; proven on the NCC H100 v5, VERIFIABLE-CLAIMS C17, C18, C20, C26).

### Trust boundaries

```
┌───────────────────────────────────────────────────────────────┐
│ Azure subscription                                             │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Confidential VM (AMD SEV-SNP under Azure's paravisor)     │ │  ← guest memory encrypted; host untrusted
│  │  ├── vTPM: HCL report (SNP report issued at boot, VCEK-   │ │
│  │  │        signed, REPORT_DATA = SHA-256(runtime data) that │ │
│  │  │        names the vTPM's attestation key)                │ │  ← paravisor trusted (residual)
│  │  ├── TPM quote by that key over PCRs 0–14, extraData =    │ │
│  │  │        SHA-256(nonce): the handshake's binding          │ │
│  │  ├── NVIDIA H100 in confidential mode: SPDM report signed  │ │  ← a second root of trust
│  │  │        by a per-device key under NVIDIA's device CA     │ │
│  │  ├── operator-installed tools run as processes: NVIDIA's   │ │
│  │  │        local verifier (gpu_attest_command), tpm2-tools  │ │  ← the host's integrity
│  │  └── sagvd / acp-compute / acp-bootstrap                   │ │
│  └──────────────────────────────────────────────────────────┘ │
│  NVIDIA NRAS (verdict tokens), RIM service (reference          │
│  manifests), OCSP (revocation) — reached through, verified      │  ← roots pinned in the binary
│  AMD KDS (VCEK), through Azure                                   │
└───────────────────────────────────────────────────────────────┘
```

Assets crossing the boundaries: the nonce, the three-part evidence
(`vault-genome/azure-cgpu-evidence/v1`: HCL report, TPM quote, NVIDIA
tokens, and the GPU's SPDM report and certificate chain when the policy
asks for them); the pins (launch measurement, the vTPM's PCRs 0–14, the
GPU model, driver and VBIOS); the escrow key and key files sealed to the
vTPM.

### Threat table

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| **S** Spoofing | A forged SEV-SNP report | the HCL report's SNP report is signed by the chip's VCEK, whose chain is verified to AMD's root (`verifyAMDChain`, as on GCP); the report's REPORT_DATA is the SHA-256 of the runtime data that names the vTPM's attestation key (`azure_cgpu_hcl.go`) |
| **S** Spoofing | A report from boot replayed for a later handshake | the handshake is bound by a TPM quote under the key the report vouches for, over PCRs 0–14, with `SHA-256(nonce)` in `extraData` (`azure_cgpu_tpm.go`); the report alone proves nothing about this handshake |
| **S** Spoofing | A forged GPU verdict | NVIDIA's tokens (Entity Attestation Tokens) are verified against NRAS's keys and carry the handshake's nonce (`nvidia_eat.go`); under `gpu_policy.evaluation: both` the verifier also evaluates the GPU's own SPDM report: its signature (ECDSA P-384) under the device certificate, that certificate's chain to the NVIDIA Device Identity CA pinned in the binary, the firmware id in the certificate's DICE extension (`nvidia_gpu_report.go`, `TestGPUReport_ChainToThePinnedNVIDIARootAndFirmwareID`) |
| **T** Tampering | The guest image or boot is changed | the SNP launch measurement (what Azure measures of the paravisor and firmware) is pinned; the vTPM's PCRs 0–14 (the OS and the driver) are pinned as the boot (`tee.vtpm_seal_pcrs`, the registry pin) |
| **T** Tampering | The GPU's driver or VBIOS is swapped | NVIDIA's verdict names driver and VBIOS and the operator may pin them (`gpu_policy`); the verifier's own evaluation checks every runtime measurement against NVIDIA's reference manifests for those versions, the manifests hashed to the service's SHA-256 and signed under the NVIDIA CoRIM root pinned in the binary (`nvidia_rim.go`, `TestRIM_ParsesNVIDIAsManifests`); `both` refuses a report NVIDIA's verdict disagrees with |
| **T** Tampering | A revoked GPU certificate | OCSP for the device chain with a nonce, answers checked for the nonce in the response extensions (`nvidia_ocsp.go`, `gpu_policy.revocation`, ADR 0021 amendment) |
| **R** Repudiation | A host denies what it attested or what the GPU ran | the evaluation of every check is on the audit record with the verdict (`GPUEvaluation`, ADR 0021 amendment; ADR 0014) |
| **I** Information disclosure | The host reads guest or GPU memory | SEV-SNP encrypts the guest; the H100 in confidential mode encrypts its memory and protects transfers (NVIDIA); both accepted as the vendors' word (residual) |
| **I** Information disclosure | Keys at rest on the guest's disk | the escrow key and every daemon key file are sealed to the vTPM under a policy of the pinned boot (ADR 0022/0023); a new boot or image does not open them, and the operator re-provisions through the recovery ceremony |
| **I** Information disclosure | Side channels in the GPU or the chip | accepted residual risk; NVIDIA's verdict and the TCB floors follow the vendors' advisories |
| **D** DoS | NRAS, the RIM service or OCSP unavailable | NRAS and RIM responses cached (`nras_cache_dir`, the RIM cache) with refresh; the policy decides what a missing answer means, and the default is a refusal |
| **E** Elevation of privilege | A compromised paravisor | Azure's paravisor issues the HCL report and holds the vTPM; it is trusted as the chip's intermediary, a residual risk named here because no measurement of ours covers it |
| **E** Elevation of privilege | The operator-installed tools (NVIDIA's local verifier, `tpm2-tools`) replaced on the host | they run as processes, outside the binary and its dependency policy; their integrity is the host's, whose OS is in the pinned PCRs; the GPU's report and NVIDIA's tokens are verified by the daemon, not taken from the tools' word |

---

## Simulated backend (`simulated`)

The simulated backend is **explicitly NOT a TEE**. It exists for
doctrinal demonstration, CI testing, and as a reference for the
contract suite.

| STRIDE | Threat | Status |
|--------|--------|--------|
| All categories | Every TEE protection is simulated only — Ed25519 sig over (measurement, nonce); AES-GCM with measurement-derived sealing key | **NOT MITIGATED** — production deployments MUST NOT use this backend |

The hardware backends are the production path: `gcp-sev-snp` (AMD
SEV-SNP through configfs-tsm; ADR 0009, 0014, 0016), `gcp-tdx` (Intel
TDX; ADR 0018) and `azure-cgpu` (an Azure confidential GPU VM: the chip,
the vTPM and the H100; ADR 0019), each proven on live machines
(VERIFIABLE-CLAIMS C7, C12–C17). The simulated backend is refused unless
the configuration says `tee.insecure_simulation: true`, and is gated by
the daemon's startup `Capability` check + a runtime warning:
`simulated TEE is not for production`.
A future invariant will require a build tag (`+build dangerous_sim`)
to compile a production binary that includes it.

---

## Cross-platform residual risks

These threats apply regardless of which TEE backend is selected. They
are documented here so an enterprise security team can confirm that
their procurement scope accepts them or asks for additional controls.

| # | Residual risk | Why we accept it | Compensating control |
|---|---------------|-------------------|---------------------|
| 1 | Vendor compromise of the TEE silicon (AWS Nitro / Intel SGX / AMD SEV-SNP / Azure SGX) | Root-of-trust transitively requires the silicon vendor to be honest; Vault Genome cannot verify silicon below the attestation root | Multi-cloud deployment lets a customer migrate when a vendor's TCB drops below acceptable; the frozen contract makes migration a config change |
| 2 | Side-channel attacks not yet publicly known | New side-channels are discovered annually (Spectre, Foreshadow, Downfall, …) | Monitor Intel/AMD/AWS TCB advisories; bump `MinISVSVN` / `MinReportedTCB` on each event; HSM-wrap option for highest-risk deployments |
| 3 | TEE attestation root rotation during a long session | Root rotations may cause mid-session attestations to fail | acpctl recover (VG-007) re-runs sagvd on fresh attestation; sealed material survives root rotation if the measurement is unchanged |
| 4 | Insider threat at Vault Genome Inc. | Founders + future engineers have CI commit access | Doctrinal invariants enforced by tests (VG-013); reproducible builds let buyers verify (VG-011); SLSA L3 provenance for every release; cosign keyless removes the "compromise the signing key" attack class |
| 5 | Supply-chain attack via a Go module update | go.mod allowlist + dep-depth limits; govulncheck + osv-scanner on every PR | Buyer can re-build from source on their own infrastructure and confirm byte equivalence (VG-011) |
| 6 | Quantum cryptanalysis of Ed25519 / ECDSA-P384 / AES-256 | NIST PQC standards finalised 2024-2025; SLH-DSA / ML-DSA selected | Migration plan in `business/29_post_quantum_migration.md` (private repo); frozen contract supports algorithm rotation by per-Provider Sealer/Producer change |

## Maintenance

This threat model is reviewed quarterly by the maintainers, and the
review is a record under `docs/security/` ([October 2026](review-2026-10.md)
is the first). The next scheduled review is **2027-01-14**. A material
change to the threat surface (a new TEE backend, a new listener, a new key
release path, a new cryptographic primitive) triggers a review attached to
the ADR that makes the change, and the ADR is not accepted without it. The
review of 2026-08-06 was not held; the October record says so.
