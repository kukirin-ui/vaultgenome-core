# Continuity Drill, the TDX leg: a model leaves an AMD SEV-SNP VM and comes back on an attested Intel TDX Trust Domain

The failover drill ([gcp-failover](../gcp-failover)) with the standby on
the other CPU TEE family: the primary and the release authority stay on
GCP AMD SEV-SNP, and the destination is a GCP `c3` **Intel TDX** Trust
Domain running `acp-bootstrap` as `gcp-tdx` — a TDX quote per challenge,
verified by the authority to Intel's root with Intel's TCB word
(ADR 0018) — reached over the VPC with mTLS. Two TEE families, one
operator-signed policy, one project.

```bash
bash scripts/hardware-test/failover-tdx/run.sh <gcp-project> [n2d-zone] [tdx-zone]
```

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, and boots three Confidential VMs in
one project, each driven by its startup script:

- The **authority** ([`authority.sh`](authority.sh)) — `n2d-standard-4`,
  SEV-SNP: `sagvd failover` attesting with its chip, its escrow key made
  in its own process and written only sealed to that chip (ADR 0016). It
  hands the escrow public key to the primary and its TLS material and
  bearer token to the standby through the run's private bucket, waits for
  both identities, signs a policy pinning the primary's chip (ADR 0017)
  and the standby's TDX measurement, and arms. Its verifier registry
  holds the `gcp-tdx` destination (Intel PCS for the TCB and QE identity,
  the pinned Intel root) and the primary's `gcp-sev-snp` anchors.
- The **primary** ([`../gcp-failover/primary.sh`](../gcp-failover/primary.sh))
  — `n2d-standard-8`, SEV-SNP, unchanged from the failover drill.
- The **standby** ([`destination-tdx.sh`](destination-tdx.sh)) —
  `c3-standard-4`, Intel TDX: `acp-bootstrap` with `tee.provider:
  "gcp-tdx"`, listening on the VPC for the authority only (mTLS, the
  authority's CA and token), pulling the primary's outbox replica itself
  from the bucket, restoring whatever genome the authority releases a key
  for and gating it through the door on its CPUs. No sealer on a TDX
  host: it receives, it does not escrow.

Every hand-off goes through the private bucket; nothing is copied by
hand, and every VM and the bucket are deleted on exit, on success or
failure.

**Design:** [ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md),
[ADR 0018](../../../docs/adr/0018-intel-tdx-on-the-return-path.md),
operator runbooks [07](../../../docs/operator/07_failover.md) and
[real-tee-tdx](../../../docs/operator/runbooks/real-tee-tdx.md).

## Results — run `20260916T181528Z`

Three live confidential machines in one GCP project, two TEE families;
the model of the failover drill (Qwen2.5-0.5B-Instruct, LoRA r8, float32
on the primary's CPUs).

**Machines** (`*/metadata.txt`, `*/system.txt`, `*/tsm.txt`):

- Primary: `n2d-standard-8`, europe-west4-a, AMD EPYC 7B13 (Milan), kernel `7.0.0-1011-gcp`,
  `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`, `/dev/sev-guest`. Launch measurement `69da361d…c790`
  (`primary/sentinel-identity.json`).
- Authority: `n2d-standard-4`, europe-west4-a, the same SEV-SNP lines. Launch
  measurement `21199b36…9546` (`authority/authority-identity.json`).
- Standby: `c3-standard-4`, us-central1-a, `Vendor ID: GenuineIntel`, CPU family 6
  model 143 (Sapphire Rapids), 4 vCPUs, kernel `7.0.0-1011-gcp`,
  `Memory Encryption Features active: Intel TDX`, `/dev/tdx_guest`, `tdx: Guest detected`. Measurement
  `ed70198a…177b` — MRTD `c1ee9c16…70a5`, RTMR0 `60d411d6…77b6`, RTMR1 `c7183cb4…f287`, RTMR2
  `90e31c74…5c90` (`destination/destination-identity.json`,
  `destination-handoff.json`).

**The escrow key, sealed** (`authority/escrow-provision.json`,
`authority-identity.json`): `sagvd escrow-provision` exit 0, key
`4d26b63927274587`, `tee: gcp-sev-snp`, sealed at the authority's measurement,
wrapped to recovery key `8ed0ad7892cff009`; `sagvd identity` says
`key_escrow_storage: sealed:gcp-sev-snp`. No key file.

**The operator's policy** (`authority/failover-verify.txt`,
`failover-policy.json`, `verifiers.json`, `allow.json`): serial 1, primary
sentinel `sentinel-90b47c956550f2ed`, primary TEE `gcp-sev-snp` at `69da361d…c790` (every
record must carry its report), standby `gcp-tdx https://10.128.15.216:8443` at `ed70198a…177b`,
triggers: compromise report, no heartbeat for 120 s, stopped and not back
within 60 s; required gate EQUIVALENT. The registry's `gcp-tdx` entry
carries the pinned measurement and a cache directory for Intel PCS; its
`gcp-sev-snp` entry carries the Milan chain — the anchors the executor
verifies the primary's reports with. What the authority fetched from
Intel is in the evidence: `cache-pcs-tdx-tcb-00806f050000.json` (TCB info for FMSPC `00806f050000`,
issued 2026-09-16T17:21:16Z, top level `UpToDate`) and
`cache-pcs-tdx-qe-identity.json` (issued 2026-09-16T17:24:24Z), each with its
issuer chain to the Intel SGX Root CA pinned in the binary.

**The primary's word** (`primary/sentinel.json`, `finetune-*.json`,
`attack-at.txt`): two generations sealed (120 steps in 55.2 s, 160
steps in 75.9 s, loss 5.33 → 0.0009; the integer door's references
recorded beside the float ones, top-1 16/16), each record carrying the
chip's report (`attestation.kind: gcp-sev-snp`). Attacked at 18:27:16.77Z:
the tripwire `/root/canary` fired, the sentinel reported `outcome:
compromised` with generation 1 as the last good state (sealed
18:27:06.85Z) and exited 3.

**The failover** (`authority/report.json`, `failover.log`,
`destination/acp-bootstrap.log`, `*.receipt.json`):

| | |
| - | - |
| Trigger | compromise report at 18:27:18.85Z, `primary_measurement_hex` = the primary's chip, verified with the Milan anchors |
| Decision | `FAILOVER_DECIDED` at 18:27:28.96Z: *restore generation 1 on the standby* |
| Handshake | across the VPC, mTLS + bearer token, to the Trust Domain; its Evidence — a TDX quote for the authority's challenge, verified through the attestation key and the PCK chain to the pinned Intel SGX Root CA, with Intel's signed TCB info and QE identity on the platform, the TDX module and the Quoting Enclave, no DEBUG, the measurement matching the pin — `CROSS_CLOUD_ATTESTATION_VERIFIED` at 18:27:30.04Z |
| Key release | `KEY_RELEASE_AUTHORIZED` at 18:27:30.04Z, `destination_kind: gcp-tdx`, `destination_measurement_hex: ed70198a…177b`, `policy_version: failover-policy-v1;failover=1;revocation=1` |
| Genome restored | **generation 1** — the last sealed before the attack (key `genome-9937cc360c97-g1-1e3eec824c6a`, bundle 2,216,819 bytes), **not** the tampered state; 5 files, 2,210,917 bytes, tree `9ad5d0ff…54c9`, in **11.6 ms** |
| Gate on the Trust Domain's CPUs | **EQUIVALENT** — door "native float" on `cpu`, 16 fixtures, max abs err **1.45e-4**, max rel err 1.14e-5 (atol 1e-2, rtol 1e-3), 10.87 s; required: EQUIVALENT |
| Receipt | signed by the standby, carrying its TDX quote as Evidence (8,000 bytes); `CROSS_CLOUD_RESTORE_COMPLETED` at 18:27:42.94Z; the key erased on the standby after the restore |
| Detect | **10.11 s** (the sentinel's detection → the authority acting, across the bucket replication) |
| RPO | **12.00 s** (attack − generation-1 seal time) |
| Failover | **13.99 s** (trigger observed → confirmed restore) |
| RTO | **24.09 s** (the intrusion → a gated, confirmed model running on Intel silicon), of which the gate ran the model on the Trust Domain's CPUs for 10.87 s |
| Audit | 5 events — `FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` → `CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`; `audit-verify.json`: `ok: true`, tip `03758aa2…4cb3`; `sagvd failover` exit 0 |

**Two roots, one policy.** The authority took the primary's compromise
report only with the primary chip's report on it, verified to AMD's root,
and released the key only after verifying the standby's quote to Intel's
root with Intel's current word on the platform, the TDX module and the
Quoting Enclave. The receipt it confirmed carries that quote. Compared
with the SEV-SNP-to-SEV-SNP drill (`gcp-failover`, RTO 23.98 s, gate EXACT
on the pinned runtime): EQUIVALENT rather than EXACT, because the model
trained on AMD Milan cores and was proven on Intel Sapphire Rapids cores
— float32 is not byte-identical across CPU vendors either, and the
measured difference, 1.45e-4, is the same order as the CPU→GPU one
of the GPU leg (1.52e-4). The integer door is the route that would give
EXACT here (ADR 0020).

**Cost.** About 15 minutes on the three machines, a few cents each.

## The raised runtime — run `20261014T041150Z` (evidence/20261014T041150Z)

The same drill on the raised Python runtime (torch 2.14.1+cpu,
transformers 5.19.0, numpy 2.5.4 on the primary and the standby;
`*/pip-freeze.txt`): primary `n2d-standard-8` and authority
`n2d-standard-4` in europe-west4-a at the September measurements
(`69da361d…c790`, `21199b36…9546`); standby `c3-standard-4` in
us-central1-a on the current image — kernel `7.0.0-1014-gcp`, MRTD
`c1ee9c16…70a5` as in September, RTMR0–2 new, so a new measurement
`dfe77c76…1a9a`, which is what the operator's policy pinned
(`authority/failover-verify.txt`, `destination/destination-identity.json`).

Two generations sealed (120 steps in 47.4 s, 160 in 67.8 s), the
attack, the compromise report with the chip's report on it. The
authority — its escrow key sealed, its five key files and the cross-cloud
transport's client key sealed (`seal-keys (failover config) exit=0
sealed=crosscloud.transport_tls.client_key already=5`) — verified the
standby's TDX quote to Intel's root with Intel's TCB word (the PCS
documents in `authority/cache-pcs-tdx-*`), released the key
(`destination_kind: gcp-tdx`, measurement `dfe77c76…1a9a`,
`failover-policy-v1;failover=1;revocation=1`) and confirmed the receipt:
generation 1 restored on the Trust Domain (5 files, 2,210,904 bytes,
11.9 ms) and gated **EQUIVALENT** on its CPUs (native float, 16
fixtures, max abs err **1.46e-04**, 10.6 s). Detect 8.50 s, RPO
9.00 s, release 1.10 s, failover 11.92 s, RTO **20.42 s**
(September 24.09 s); 5 audit events verified, tip `58043177…c776`. The
standby's own key files were sealed too (`destination/dest-seal-keys.json`:
`tee: gcp-tdx`).

## Evidence files

- `primary/` — `finetune-0.json`, `finetune-1.json` (+ `.log`),
  `sentinel-identity.json` (the chip's measurement and the sentinel key
  id), `sentinel-keygen.txt`, `sentinel.json` (the sentinel's final report:
  outcome, the generation it last sealed, the wire that fired, the attested
  compromise report), `sentinel.log`, `attack-at.txt`, `metadata.txt`, `system.txt`, `tsm.txt`,
  `pip-freeze.txt`, `steps.txt`, `console.log`.
- `authority/` — `escrow-provision.json`, `recovery-keygen.txt`,
  `authority-identity.json` (the sealed escrow key and the chip),
  `destination-handoff.json` and `primary-identity.json` (what the operator
  pinned), `verifiers.json` and `allow.json` (the registry and the
  allow-list as armed), `failover-issue.txt`, `failover-verify.txt`,
  `failover-policy.json` (the signed policy), `report.json` (the failover
  report), `failover.log`, `audit-events.jsonl` and `audit-verify.json`
  (the log checked offline after the failover), `cache-vcek-*.der` (the
  VCEK fetched from AMD for the primary's chip), `cache-pcs-tdx-*.json`
  and `.issuer-chain.pem` (Intel's TCB info and QE identity for the
  standby's platform, as fetched and verified), `timeline.txt`,
  `metadata.txt`, `system.txt`, `tsm.txt`, `steps.txt`, `console.log`.
- `destination/` — `destination-identity.json` (measurement, MRTD, RTMRs),
  `destination-handoff.json`, `system.txt`, `tsm.txt`, `pip-freeze.txt`,
  `inputs.sha256` (the binaries and the worker as installed),
  `acp-bootstrap.log`, `acp-bootstrap-metrics.txt`,
  `genome-…-g1-….receipt.json` (the signed receipt and its Evidence:
  the TDX quote), `replica-ls.txt`, `restored-ls.txt`,
  `restored-tree.txt`, `steps.txt`, `console.log`.

The evidence holds no key, seed, token or config: the sealed escrow key's
bytes are not in it, the bearer token and the TLS material crossed only
through the run's private bucket, and the bucket was deleted with the VMs.

## Scope

This proves a governed key release to an attested Intel TDX Trust Domain
and a gated restore on it, from an AMD SEV-SNP authority under one
operator policy, on real hardware — with the 0.5B model of the failover
drill, once. What it does not change: in this run the standby held no
sealed escrow key (since ADR 0022 a TDX host seals one to its vTPM —
[failover-tdx-authority](../failover-tdx-authority) is the authority on
TDX); Intel PCS is on the path at verification time
(cached here; without it and without a cache the verifier refuses); the
pin is the image's, and a kernel update re-issues it; the gate is a float
door, so the level across AMD training and Intel restore is EQUIVALENT,
not EXACT.

Two earlier runs of this kit (`20260916T174300Z`, `20260916T180021Z`; not
kept) completed the same failover — RTO 23.14 s and 23.32 s, the gate
EQUIVALENT at the same 1.45e-4 both times — but were reported as failed
by the orchestrator: the primary script waited for the sentinel's
expected exit 3 under `set +e`, which does not silence bash's ERR trap,
so the trap wrote a FAILED marker beside the DONE one the script wrote
seconds later, and the poll happened to see FAILED first. The wait is a
`||` list now (`../gcp-failover/primary.sh`, and the standby's negative
check in `standby.sh`); this run is the one with the fix.
