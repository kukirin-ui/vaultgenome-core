# Operator Overview

**Audience:** A new operator onboarding to the AI Continuity Platform core.
**Prerequisite reading:** the eleven doctrinal invariants, asserted as tests in
`test/doctrine/invariants_test.go` ([ADR 0004](../adr/0004-doctrine-invariants-as-tests.md)).
**This document answers:** *who holds what authority, where the boundary
between the Vault and the compute plane lies, and which parts of that design
the shipped binaries run today.*

---

## 0. What ships today

| Binary | What it does | Built by `make build` |
| - | - | - |
| `sagvd` (daemon) | Return Path listener for `acp-compute` workers (mTLS required off loopback); operator REST API (`POST /v1/jobs` names a sealed genome in `genome.bundle_dir`, `GET /v1/jobs/{id}` shows the gate's signed verdict); health listener (`/healthz`, `/readyz`, `/metrics`). Attests with AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`) or the simulated TEE. Writes every decision about a job to its signed audit log (`audit.log_path`, ADR 0014). | yes |
| `sagvd identity`, `sagvd crosscloud-restore`, `sagvd crosscloud-confirm`, `sagvd failover` | Print the keys other hosts pin; release genome keys to an attested destination and confirm its restore ([06](06_cross_cloud_restore.md)); carry out the operator's failover policy when the primary is compromised or dies ([07](07_failover.md)). The cross-cloud subcommands write the only audit log any binary writes (`crosscloud.audit_log_path`). | same binary |
| `acp-compute` | Worker: dials sagvd's Return Path and runs one gate job per session — restores the sealed genome's model in memory through the `vg_genome` door named by `genome.door.command` and answers the genome's prompts (ADR 0013). Needs Python, the pinned torch and the public base model on its host. Attests with AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`) or the simulated TEE (ADR 0014). | yes |
| `acp-bootstrap` | Cross-cloud destination: attests with AMD SEV-SNP (or the simulator), receives genome keys, restores genomes, signs receipts. | yes |
| `acpctl` | Administrative CLI (§1.3). | yes |
| `acp-demo` | Self-contained cross-hardware regeneration demo. | yes |

The nine-stage flow in §2 is library code under `internal/`, and `sagvd`
drives it for every gate job (ADR 0015): `POST /v1/jobs` is a RecoveryRequest
admitted at intake, and a worker's session carries it through trust, session,
disclosure, manifest, candidate, validation, decision and audit. The
vertical-slice tests (`make demo`, `internal/integration`) remain the
library's own end-to-end proof. Documents 01–04 describe that flow and say,
item by item, what a deployment can check today.

---

## 1. Two operator roles

The platform splits responsibility across two distinct roles, and this split
is doctrine. Collapsing them is an invariant violation.

### 1.1 Vault operator

**Runs:** `sagvd` (Secure AI Genome Vault Daemon).

**Holds authority over (by design):** every continuity-relevant decision —
intake, trust admission, session issuance, policy evaluation, disclosure
sequencing, release decision, audit appendage. The Vault is **the sole source
of truth** for what is allowed to happen next in the nine-stage flow. The
daemon takes those decisions for every gate job (ADR 0015) — its
`orchestration.Authority` runs intake, trust, the session issuer, the staged
disclosure sequencer, the validation service and the incident service over
its Return Path audit log — and, through `sagvd crosscloud-restore`, releases
genome keys to attested destinations under the operator's allow-list and
signed stop list (06). The same stop list, named by `operator_stop`, denies
gate jobs at Trust Admission.

**Must have:** the key files its config names — `keys.authority_signing`
(Ed25519 seed; signs cross-cloud handshakes and key-release tokens),
`keys.session_sealing` (AES-256 key shared with the workers) and, for
cross-cloud releases, `keys.audit_signing`; custody of the cross-cloud audit
log; the allow-list and verifier registry; the operator's public key for the
stop list.

**Must NOT:** run generative reconstruction workloads. The Vault is
intentionally compute-light; heavy work is delegated outward by design.

### 1.2 Compute-plane operator

**Runs:** `acp-compute` (one or more external workers).

**Holds:** delegated execution rights only. In the design, workers receive
DisclosureMessage sequences scoped to one session and component, execute the
authorised reconstruction step and return a result bound to the session. The
shipped worker does that job for one genome at a time: it dials sagvd's
Return Path, completes a handshake in which each side checks the other's TEE
Evidence against pinned values, receives one JobRequest whose components —
the genome's description, its adapter, the fixtures' prompts — sagvd sealed
under the session-sealing key, restores the model in memory through the
`vg_genome` door and returns the model's outputs as a CandidateOutputFrame
signed with its worker key (ADR 0013). It never sees the reference outputs
and writes nothing of the genome. It gains no continuity authority and cannot
issue a ReleaseDecision; sagvd judges what it returns.

**Must have:** a TEE to attest with — `tee.provider: "gcp-sev-snp"` on an
AMD SEV-SNP guest (the chip signs; see
[runbooks/real-tee-sev-snp.md](runbooks/real-tee-sev-snp.md)), `"gcp-tdx"`
on an Intel TDX guest (a TDX quote; see
[runbooks/real-tee-tdx.md](runbooks/real-tee-tdx.md)), `"azure-cgpu"` on
an Azure confidential GPU VM (the chip, the vTPM and the H100; see
[runbooks/real-tee-azure-cgpu.md](runbooks/real-tee-azure-cgpu.md)), or `"simulated"`
with `tee.insecure_simulation: true` on a laptop or in CI; a pin of the
vault's TEE (`tee.peer`: its 48-byte measurement and the AMD chain for a
SEV-SNP vault, its 48-byte measurement and a PCS cache directory for a TDX
vault, its attestation key and measurement for a simulated one); the same `keys.session_sealing` kid and key as sagvd; a
worker signing key whose kid and public key are listed in sagvd's
`workers.registry_path`; a `genome.door.command` that runs the `vg_genome`
door (`workers/genome`: Python 3.12, the pinned torch and transformers) and a
local copy of the public base model whose files hash to the genome's
manifest. No Intel TDX, AWS Nitro or SGX adapter attests in this repository.

**Must NOT:** log, persist, or forward plaintext disclosed material outside
the bounds of the session. A worker that caches plaintext past session
termination is by definition in violation of invariant #7 ("No raw export").

### 1.3 Administrator

**Runs:** `acpctl` (administrative CLI).

**Holds:** inspection tools and the operator's signing key for stop lists.
The commands that exist:

| Command | Purpose |
| - | - |
| `acpctl status --audit PATH [--json]` | Summary of an audit log: event count, time range, kinds, latest event |
| `acpctl audit query --audit PATH [--kind K] [--session S] [--manifest M] [--since T] [--until T] [--limit N] [--json]` | List events |
| `acpctl audit verify --audit PATH --audit-pubkey FILE --audit-kid KID [--json]` | Replay the chain from its first event, check every hash and signature, print the tip |
| `acpctl lineage --audit PATH (--session-id ID \| --manifest-id ID) [--json]` | Events tied to one session or manifest |
| `acpctl genome seal \| open (alias rewind) \| verify \| inspect \| chain \| lineage \| gate` | Seal, restore and check genome bundles |
| `acpctl stop keygen \| issue \| verify` | Create and check the operator's signed stop list (06) |
| `acpctl escrow keygen \| recovery-keygen \| recover` | The operator's side of escrow custody: a plaintext escrow key for the simulated TEE only; the recovery key a sealed escrow key is wrapped to; opening a recovery envelope for `sagvd escrow-provision -stdin` (06, ADR 0016) |
| `acpctl sentinel keygen \| identity \| watch` | On the primary: keep a running model's state sealed, generation by generation, every record attested by the primary's TEE (`--tee`), and report when a tripwire fires; `identity` prints what the operator pins (07) |
| `acpctl failover issue \| verify` | Sign and check the operator's failover policy: the sentinel, the primary's TEE, the standby, the triggers and the `stopped` grace (07) |
| `acpctl recover --vault PATH …` | Unseal a `VG-VAULT-01` envelope with the TEE backend it names; no shipped binary writes that format yet |

The audit commands read any audit log file; in practice the one
`sagvd crosscloud-restore` writes. No command issues a ReleaseDecision and
none appends audit events — release authority lives only in the Vault's
disclosure-and-release pipeline and is driven by validated work products, not
by CLI invocation.

---

## 2. The nine stages (one-line each)

| # | Stage | Authority holder | Package | Code today |
| - | - | - | - | - |
| 1 | Recovery Request | Vault — intake | `/internal/vault/intake` | `Intake.Admit`: well-formed, not a duplicate; `sagvd` at `POST /v1/jobs` (`REQUEST_RECEIVED`) |
| 2 | Trust Admission | Vault — trust | `/internal/vault/trust` | `Admission.Evaluate`: the operator's stop list, the policy profile, the attested peer → signed `AttestationResult`; `sagvd` at dispatch (`TRUST_EVALUATED`) |
| 3 | Trusted Session | Vault — session | `/internal/vault/session` | In-memory session Issuer; `sagvd` issues one per admitted job (`SESSION_ISSUED`) |
| 4 | Staged Disclosure | Vault — disclosure (StagedIssuer + StagedSequencer) | `/internal/vault/disclosure` | `sagvd` discloses the genome's model side to the session (`DISCLOSURE_AUTHORIZED` per component) |
| 5 | Delegated External Compute | Compute plane — worker | `/internal/compute/worker` | `GenomeReconstructor`: the model restored in memory through the `vg_genome` door, used by `acp-compute` (ADR 0013); `sagvd` issues the signed manifest (`MANIFEST_ISSUED`) |
| 6 | Return Path | Compute plane, gated by Vault | `/internal/compute/returnpath` | Used by `sagvd` and `acp-compute` (`CANDIDATE_RECEIVED`) |
| 7 | Validation | Vault — validation/service | `/internal/validation/service` | The six operational sub-checks over the job's own artifacts and the gate's two verdicts (`VALIDATION_*`) |
| 8 | Release Decision | Vault — orchestration | `/internal/vault/orchestration` | `Flow.Decide`: `RELEASE_DECIDED`, then the signed `ReleaseDecision` (release, refusal, or refusal at trust) |
| 9 | Audit | Vault — audit | `/internal/audit` | Hash chain and bbolt store; `Flow.Seal` closes on the chain tip, a refusal through the incident service |

Authority moves through the Vault for stages 1–4, 6–9 and through the compute
plane for stage 5 only. The legal transitions between stages are listed in
`/internal/vault/orchestration/state.go`, checked by the doctrine tests in
`/test/doctrine/invariants_test.go`, and taken at run time by
`orchestration.Machine` for every gate job `sagvd` serves (ADR 0015); a
transition the table does not allow is refused, never taken silently.

---

## 3. What the Vault is NOT

It is useful to state this plainly up front so first-week confusions are
avoided:

- **The Vault is not a model server.** It does not serve inference traffic.
- **The Vault is not a backup target.** It does not store model weights.
  It stores the AI Genome and the authority objects that govern its
  disclosure.
- **The Vault is not a key management service.** It uses one internally,
  but KMS-equivalent duties are a subset of its function, not the whole.
- **The Vault is not a DR tool.** Disaster recovery addresses artifact
  survival. The Vault addresses *continuity of intelligence* — the right
  and the ability to reconstruct AI capability in a new trusted environment.
- **The Vault is not a research platform.** Every function the Vault
  exposes is a production-path function. Exploratory work happens
  elsewhere.

---

## 4. Reading this runbook

- `01_preflight.md` — what to check before relying on a deployment.
- `02_recovery_flow.md` — the nine-stage flow and the receive-side round trip,
  as implemented in the library and exercised by the tests.
- `03_incident_response.md` — the incident module's three MVP scenarios, the
  two it defers, and what an operator does.
- `04_observability.md` — how to prove, after the fact, what happened.
- `05_release_procedure.md` — the signed-tag / SBOM / cosign / SLSA release loop.
- `06_cross_cloud_restore.md` — releasing genome keys to an attested
  destination and confirming its restore.
- `07_failover.md` — the sentinel on the primary, the operator's failover
  policy, and the executor that moves a genome to the standby.
- `triage_table.md` — from an observed signal to the first action.
- `08_upgrading.md` — which releases are supported, the compatibility ledger
  release by release, how to move a deployment and how to go back.
- `runbooks/` — disaster recovery, AWS and Azure notes, real AMD SEV-SNP.

If you find yourself wanting to take an action this runbook does not cover,
stop and open a design discussion — the runbook intentionally covers only
the doctrine-sanctioned operations.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
