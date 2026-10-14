# Continuity Drill, the GPU leg: a model leaves a CPU TEE and comes back on an attested confidential GPU in another cloud

The failover drill ([gcp-failover](../gcp-failover)) with one thing changed:
the standby is not another CPU confidential VM in the same project, but an
**Azure NCC H100 v5** — an AMD SEV-SNP guest with an H100 in
confidential-computing mode — reached over the Internet, attesting as
`azure-cgpu` (the chip's report from the vTPM, a TPM quote per challenge,
NVIDIA's tokens for the H100), and gating the restored model through the
door **on the GPU**. The primary and the release authority stay on GCP
SEV-SNP. Two clouds, two TEE families, one operator-signed policy.

```bash
bash scripts/hardware-test/failover-cgpu/run.sh <gcp-project> [gcp-zone] [azure-rg]
```

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, verifies Microsoft's onboarding package
(V4.4.1, by SHA-256) and brings up three machines:

- The **authority** ([`authority.sh`](authority.sh)) — GCP `n2d-standard-4`,
  SEV-SNP: `sagvd failover` attesting with its chip, its escrow key made in
  its own process and written only sealed to that chip (ADR 0016). It hands
  the escrow public key to the primary and its TLS material and bearer token
  to the standby through the run's private bucket, waits for the standby's
  identity, signs a policy pinning the primary's chip (ADR 0017) and the
  standby's launch measurement and vTPM boot, and arms.
- The **primary** ([`../gcp-failover/primary.sh`](../gcp-failover/primary.sh))
  — GCP `n2d-standard-8`, SEV-SNP, unchanged from the failover drill: it
  fine-tunes Qwen2.5-0.5B-Instruct, the sentinel seals each generation with
  its key escrowed to the authority and the chip's report on every record,
  the outbox is replicated; then it is attacked.
- The **standby** ([`destination-cgpu.sh`](destination-cgpu.sh)) — Azure
  `Standard_NCC40ads_H100_v5`, West Europe, Ubuntu 24.04 CVM image, after
  Microsoft's onboarding (kernel, the 595 open driver pinned to the version
  the signed modules need, NVIDIA's local GPU verifier) and tpm2-tools:
  `acp-bootstrap` with `tee.provider: "azure-cgpu"`, listening on 8443 for
  the authority only (a network rule for its IP), the door running
  `--device cuda`. It restores whatever genome the authority releases a key
  for and signs a receipt with its evidence.

The orchestrator is the operator's hands and nothing more: it carries the
authority's TLS material to the standby and the standby's identity back
(`handoff/destination.json`: endpoint, launch measurement, vTPM PCR
digest), replicates every sealed bundle from the primary's outbox to the
standby, waits for both sides, collects, and deletes the GCP machines and
the bucket on every exit. The Azure VM is deleted too, unless the run
failed and `VG_KEEP_ON_FAILURE` is set (then delete it yourself:
`az vm delete -g <rg> -n <vm>`). `VG_REUSE_AZURE_VM=<name>` reuses an
existing standby VM (started if deallocated) instead of creating one.
GCP zones are tried in rounds until one has n2d Milan capacity.

The genome key never crosses in the clear: it lives on the primary only as
an escrow envelope, which the authority opens with the key unsealed from
its chip and re-wraps to the standby's attested per-handshake key
(ADR 0009, 0011, 0012). What the standby has to show for that key is the
`azure-cgpu` envelope of ADR 0019, verified by the authority against AMD's
Genoa root, the vTPM's attestation key and NVIDIA's key set, with the
policy of `gpu_policy` (here: `hw_models: ["GH100"]`, the defaults for
secure boot, no debug, signed manifests, matched measurements) and the
`pcr_digests` pin.

**Design:** [ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md),
[ADR 0019](../../../docs/adr/0019-a-confidential-gpu-worker-on-azure.md),
operator runbooks [07](../../../docs/operator/07_failover.md) and
[real-tee-azure-cgpu](../../../docs/operator/real-tee-azure-cgpu.md).

## The scenario

1. The authority provisions itself on its chip and publishes its escrow
   public key (to the primary) and its TLS material and token (to the
   standby, through the orchestrator).
2. The standby is onboarded and comes up as `acp-bootstrap` on the H100;
   `acp-bootstrap identity` prints its launch measurement and the digest of
   its vTPM's PCRs; the orchestrator hands both to the authority.
3. The primary fine-tunes generation 0; the sentinel seals it.
4. The operator signs a failover policy pinning the primary's sentinel key
   and chip, and the standby: kind `azure-cgpu`, its endpoint on the
   Internet, its launch measurement; an EQUIVALENT gate is required. The
   authority's verifier registry pins the standby's vTPM boot as well.
   `sagvd failover` arms.
5. The primary keeps training: generation 1. The sentinel seals it; the
   orchestrator replicates the bundle to the standby.
6. **The attack.** A tripwire is touched and the adapter overwritten. The
   sentinel never seals the tampered state: it writes a signed, attested
   compromise report naming generation 1 as the last good one and exits 3.
7. The authority sees the report in the replica — with the primary chip's
   report on it — chooses generation 1, records `FAILOVER_DECIDED`, opens
   a handshake to Azure over mTLS, verifies the standby's chip, vTPM and
   GPU, releases the key, and waits for the receipt: the standby restores
   the genome, runs the door on the H100, and signs for the result with
   its evidence. The authority confirms it on the record.

## Results — run `20260916T150456Z`

Three live confidential machines, two clouds, two TEE families; the model
of the failover drill (Qwen2.5-0.5B-Instruct, LoRA r8, float32 on the
primary's CPUs).

**Machines** (`*/metadata.txt`, `*/system.txt`, `*/tsm.txt`,
`destination/conf-compute.txt`, `destination/gpu.csv`):

- Primary: GCP `n2d-standard-8`, europe-west4-a, AMD EPYC 7B13 (Milan),
  `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`,
  `/dev/sev-guest`. Launch measurement `69da361d…c790`
  (`primary/sentinel-identity.json`).
- Authority: GCP `n2d-standard-4`, europe-west4-a, the same SEV-SNP lines.
  Launch measurement `21199b36…9546` (`authority/authority-identity.json`).
- Standby: Azure `Standard_NCC40ads_H100_v5`, West Europe, Ubuntu 24.04.5
  CVM, kernel `6.17.0-1018-azure-fde`, NVIDIA H100 NVL, driver 595.71.05,
  VBIOS 96.00.9F.00.04, `CC State: ON`, `CPU CC Capabilities: AMD
  SEV-SNP(vTOM Mode)`, `CC GPUs Ready State: Ready`; torch 2.7.1+cu126.
  Launch measurement `aa7c9da5…0eef`, vTPM PCR digest (sha256:0–14)
  `92fe2c20…26e2` (`destination/destination-identity.json`,
  `destination-handoff.json`).

**The escrow key, sealed** (`authority/escrow-provision.json`,
`authority-identity.json`): `sagvd escrow-provision` exit 0, key
`51696c297968cb3c`, `tee: gcp-sev-snp`, sealed at the authority's
measurement, wrapped to recovery key `b1557cfdb8f35195`; `sagvd identity`
says `key_escrow_storage: sealed:gcp-sev-snp`. No key file.

**The operator's policy** (`authority/failover-verify.txt`,
`failover-policy.json`, `verifiers.json`, `allow.json`): serial 1, primary
sentinel `sentinel-2311a7b13a0faf35`, primary TEE `gcp-sev-snp` at
`69da361d…c790` (every record must carry its report), standby
`azure-cgpu https://51.137.32.48:8443` at `aa7c9da5…0eef`, triggers:
compromise report, no heartbeat for 120 s, stopped and not back within
60 s; required gate EQUIVALENT. The registry's `azure-cgpu` entry carries
the Genoa chain, NVIDIA's key set, `gpu_policy.hw_models: ["GH100"]` and
`pcr_digests: ["92fe2c20…26e2"]`; its `gcp-sev-snp` entry carries the
Milan chain — the anchors the executor verifies the primary's reports
with.

**The primary's word** (`primary/sentinel.json`, `finetune-*.json`,
`attack-at.txt`): two generations sealed (120 steps in 54.7 s, 160 steps
in 76.2 s, loss 5.33 → 0.0009), each record carrying the chip's report
(`attestation.kind: gcp-sev-snp`). Attacked at 15:12:32.35Z: the tripwire
`/root/canary` fired, the sentinel reported `outcome: compromised` with
generation 1 as the last good state (sealed 15:12:23.07Z) and exited 3.

**The failover** (`authority/report.json`, `failover.log`,
`destination/acp-bootstrap.log`, `*.receipt.json`):

| | |
| - | - |
| Trigger | compromise report at 15:12:35.07Z, `primary_measurement_hex` = the primary's chip, verified with the Milan anchors |
| Decision | `FAILOVER_DECIDED` at 15:12:40.67Z: *restore generation 1 on the standby* |
| Handshake | over the Internet, mTLS + bearer token, to the H100 host; its Evidence — the SEV-SNP report from the vTPM (Genoa, VCEK from AMD for the chip's product), the TPM quote under the vTPM's attestation key with `SHA-256(nonce)` in `extraData`, the PCR digest matching the pin, NVIDIA's ES384 tokens for the H100 under NVIDIA's key set and the claims policy — `CROSS_CLOUD_ATTESTATION_VERIFIED` |
| Key release | `KEY_RELEASE_AUTHORIZED` at 15:12:41.96Z, `destination_kind: azure-cgpu`, `destination_measurement_hex: aa7c9da5…0eef`, `policy_version: failover-policy-v1;failover=1;revocation=1` |
| Genome restored | **generation 1** — the last sealed before the attack (key `genome-07106de97ec8-g1-e21b6f7b90a9`, bundle 2,208,627 bytes), **not** the tampered state; 5 files, 2,202,999 bytes, tree `00d13217…8ef9`, in **11.4 ms** |
| Gate on the H100 | **EQUIVALENT** — door "native float" on `cuda`, 16 fixtures, max abs err **1.52e-4**, max rel err 1.65e-5 (atol 1e-2, rtol 1e-3), 12.11 s; required: EQUIVALENT |
| Receipt | signed by the standby, carrying the same `azure-cgpu` Evidence; `CROSS_CLOUD_RESTORE_COMPLETED` at 15:13:00.06Z; the key erased on the standby after the restore |
| Detect | **5.59 s** (the sentinel's detection → the authority acting, across the bucket replication) |
| RPO | **12.00 s** (attack − generation-1 seal time) |
| Failover | **19.40 s** (trigger observed → confirmed restore) |
| RTO | **24.99 s** (the intrusion → a gated, confirmed model running on the GPU in another cloud), of which the gate ran the model on the H100 for 12.1 s |
| Audit | 5 events — `FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` → `CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`; `audit-verify.json`: `ok: true`, tip `d46be63a…943a`; `sagvd failover` exit 0 |

**Attestation on both ends, and the GPU in the release.** The authority
took the primary's compromise report only with the primary chip's report
on it, and released the key only after verifying the standby's chip, its
vTPM and NVIDIA's word on the H100 under one nonce. The receipt it
confirmed carries that same Evidence. Compared with the CPU-only drill
(`gcp-failover`, RTO 23.98 s, gate EXACT on the pinned runtime): one
second more across the Internet, and EQUIVALENT rather than EXACT because
the model trained on CPUs and was proven on a GPU — the measured
CPU→GPU float32 error of this model, 1.5e-4, is where the honest ladder
says it is.

**A note on the vTPM pin.** The PCR digest is a property of a boot: the
standby's identity was taken after the last reboot of the onboarding and
pinned in the registry for that boot; the handshake's quote matched it. A
reboot changes it (a previous boot of the same VM measured
`f3930f82…af5a`), so the pin is taken from `acp-bootstrap identity` on the
running machine, not from an earlier capture.

**Cost.** About 25 minutes on the three machines; the H100 VM at ~$8.9/h
is the bulk of it.

## Every secret file sealed, and the verifier's word on the record — run `20260916T233717Z` (evidence/20260916T233717Z)

The same cross-cloud drill with ADR 0023 amended twice and ADR 0021 amended
on the record. On the primary the sentinel ran from its seed sealed to the
chip (`primary/steps.txt`: `sentinel seal-key exit=0 tee=gcp-sev-snp sealed=True`); on the authority `sagvd seal-keys`
sealed keys.authority_signing.seed_path,keys.session_sealing.material_path,keys.audit_signing.seed_path,vault.tls.server_key,http_api.bearer_token_file, and again after the failover config was written —
`seal-keys (failover config) exit=0 sealed=crosscloud.transport_tls.client_key already=5` — so the cross-cloud transport's client key was sealed too; on
the H100 destination `acp-bootstrap seal-keys` sealed http.tls.server_key,http.bearer_token_file to the vTPM
(`destination/steps.txt`). The failover: generation 1 restored on the
H100 and gated **EQUIVALENT**, RTO **25.74 s**, RPO 9.00 s, 5 audit
events verified (tip `468d9a80…b1c6`).

What the authority's verifier said about the destination is on the key
release's record: `authority/audit-events.jsonl`, the
`CROSS_CLOUD_ATTESTATION_VERIFIED` event's `destination_detail` — provider
`azure-cgpu`, product `Genoa`, reported TCB `6348668099708846090`, the vTPM quote's
PCRs `sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14`, GPU-0 `GH100` driver `595.71.05` VBIOS `96.00.9F.00.04` vouched for by
`https://nras.attestation.nvidia.com`.

## The raised runtime — run `20261014T121030Z` (evidence/20261014T121030Z)

The same cross-cloud drill on the raised Python runtime (torch 2.14.1 on
every machine, transformers 5.19.0; `*/pip-freeze.txt`): primary
`n2d-standard-8` and authority `n2d-standard-4` in us-central1-c at the
measurements of the September run above (`10f5ac22…4519`,
`7dc7c12e…5acc`), the standby a `Standard_NCC40ads_H100_v5` CVM in West
Europe on the day's image and driver — kernel `7.0.0-1016-azure-fde`, NVIDIA H100
NVL, driver **595.91.07** (September 595.71.05), VBIOS 96.00.9F.00.04, `CC State:
ON`, `CC GPUs Ready State: Ready`; launch measurement `aa7c9da5…0eef` as
in September, the vTPM's PCR digest of this boot `c1e0b0f8…ad85`, which the
registry pinned (`destination/destination-identity.json`).

Every secret file sealed as in the run above: the sentinel's seed on the
primary (`sentinel seal-key exit=0 … sealed=True`), the authority's five
key files and then the cross-cloud transport's client key (`seal-keys
(failover config) exit=0 sealed=crosscloud.transport_tls.client_key
already=5`), the standby's two to its vTPM (`destination/dest-seal-keys.json`:
`tee: azure-cgpu`). Two generations sealed (120 steps in 52.0 s, 160 in
82.1 s), the attack, the compromise report with the chip's report on it;
the authority verified the standby's SEV-SNP report to AMD's Genoa root,
its TPM quote under the vTPM's attestation key against the pinned PCR
digest, and the H100 both ways — NVIDIA's tokens and its own evaluation
of the GPU report under `gpu_policy.evaluation: both` — released the key
and confirmed the receipt: generation 1 restored on the H100 (5 files,
2,210,904 bytes, 11.8 ms) and gated **EQUIVALENT** through the door on the
GPU (native float, 16 fixtures, max abs err 2.48e-04, 6.9 s).

| Phase | Measured |
| - | - |
| Detect — tripwire → authority observes | **6.88 s** |
| **RPO** — data at risk | **9.00 s** |
| Key release — across the clouds, mTLS | 2.11 s |
| Restore — 5 files, 2,210,904 B | **11.8 ms** |
| Gate on the H100 | 6.86 s |
| Failover — trigger observed → confirmed | 12.98 s |
| **RTO** | **19.86 s** (September 25.74 s) |

Audit chain of 5 events, `audit-verify.json`: `ok: true`, tip
`f86923a4…4be9`. What the verifier said about the destination is on the key
release's record as before (`authority/audit-events.jsonl`,
`CROSS_CLOUD_ATTESTATION_VERIFIED` → `destination_detail`): provider
`azure-cgpu`, product `Genoa`, reported TCB `6348668099708846090`, the quote's PCRs
`sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14`, GPU-0 `GH100` driver `595.91.07` VBIOS
`96.00.9F.00.04` vouched for by `https://nras.attestation.nvidia.com`, and the
authority's own evaluation of the GPU report with every check true
(`report_parsed`, `nonce_match`, `chain_verified`, `fwid_match`, `signature_verified`, `measurements_match`, `revocation_checked`, `revocation_good`).

## Evidence files

- `primary/` — `finetune-0.json`, `finetune-1.json` (+ `.log`),
  `sentinel-identity.json` (the chip's measurement and the sentinel key
  id), `sentinel-keygen.txt`, `sentinel.json` (the sentinel's final report:
  outcome, the generation it last sealed, the wire that fired, the attested
  compromise report), `sentinel.log`, `attack-at.txt`, `metadata.txt`,
  `system.txt`, `tsm.txt`, `pip-freeze.txt`, `steps.txt`, `console.log`.
- `authority/` — `escrow-provision.json`, `recovery-keygen.txt`,
  `authority-identity.json` (the sealed escrow key and the chip),
  `destination-handoff.json` and `primary-identity.json` (what the operator
  pinned), `verifiers.json` and `allow.json` (the registry and the
  allow-list as armed), `failover-issue.txt`, `failover-verify.txt`,
  `failover-policy.json` (the signed policy), `report.json` (the failover
  report), `failover.log`, `audit-events.jsonl` and `audit-verify.json`
  (the log checked offline after the failover), `cache-*.der` (the VCEKs
  fetched from AMD for both chips) and `cache-nras-jwks.json` (NVIDIA's
  key set as fetched), `timeline.txt`, `metadata.txt`, `system.txt`,
  `tsm.txt`, `steps.txt`, `console.log`.
- `destination/` — `destination-identity.json`, `conf-compute.txt`,
  `gpu.csv`, `system.txt`, `torch.txt`, `pip-freeze.txt`, `inputs.sha256`
  (the binaries and the worker as installed), `acp-bootstrap.log`,
  `genome-…-g1-….receipt.json` (the signed receipt and its Evidence:
  HCL report, quote, NVIDIA's tokens), `restored-ls.txt`,
  `restored-tree.txt`, `bundles-ls.txt`, `sha256sums.txt`, `steps.txt`,
  `console.log`.
- `destination-handoff.json` — what the orchestrator carried to the
  authority.

The evidence holds no key, seed, token or config: the sealed escrow key's
bytes are not in it, the bearer token and the TLS material crossed only
through the run's private bucket and an ssh session, and the bucket was
deleted with the VMs.

## Scope

This proves a governed key release to an attested confidential GPU and a
gated restore on it, across two clouds and two TEE families, on real
hardware — with the 0.5B model of the failover drill. What it does not
change: the GPU's own measurements are evaluated by NVIDIA's service and
the authority verifies NVIDIA's signed word (KNOWN_ISSUES #1); the
standby held no sealed escrow key in this run (since ADR 0022 it seals one
to its vTPM); the gate is a
float door, so the level across CPU training and GPU restore is
EQUIVALENT, not EXACT — the pinned-runtime EXACT of the failover drill is
a same-device property.
