# Status — what works today

The authoritative maturity summary of this repository. Every statement
below is backed by an evidence file and a reproduction command in
[`VERIFIABLE-CLAIMS.md`](../VERIFIABLE-CLAIMS.md) (C1–C26); the open limits
are in [`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) and
[what we do not claim](../VERIFIABLE-CLAIMS.md#what-we-do-not-claim); what
is next is in [`ROADMAP.md`](../ROADMAP.md). Component-level design
rationale lives in the architecture decision records under
[`adr/`](adr/README.md).

**Stage:** E — release-side doctrine closed; the receive side (Stage F,
a destination that bootstraps itself) is deferred to V2 per resolution
R-11.
**Doctrine invariants:** 11 of 11 CI-enforced (asserted as tests in
`test/doctrine/`; [ADR 0004](adr/0004-doctrine-invariants-as-tests.md)).
**CI gate:** `vault-gate` with 18 sub-checks (fmt, vet, build, unit, race,
integration, coverage, lint, terminology, govulncheck, osv-scanner,
gitleaks, sbom, license-headers, doctrine-tests, dep-allowlist, dep-depth,
verify-reproducible), plus CodeQL, Semgrep, a benchmark comparison, the
Python worker's tests and OpenSSF Scorecard.
**Module path:** `github.com/vault-genome/vaultgenome-core`. **Go:** 1.26.
**Hardware measured:** AMD SEV-SNP (GCP, Azure), Intel TDX (GCP), an
NVIDIA H100 in confidential-computing mode (Azure); NVIDIA L4 and T4 and
Intel Xeon CPUs for the determinism measurements.

## What works today

- **Byte-exact model continuity** — `acpctl genome seal / rewind / chain`:
  seal any model to a portable bundle whose key lives apart from it,
  restore it byte-exact on any server, and track versions with a validated
  lineage chain. Opening authenticates every 1 MiB segment before a byte of
  it is used and leaves the target untouched on any refusal.
- **Attested self-restore across clouds** — the operator's policy releases
  a genome's key to an attested, allow-listed destination TEE; the
  destination restores the genome by itself and signs a receipt with its
  TEE; the source verifies the receipt and records the restore
  (`sagvd crosscloud-confirm`, [ADR 0011](adr/0011-genome-v3-and-attested-self-restore.md)),
  under an operator stop that halts every release
  ([ADR 0010](adr/0010-operator-stop-and-recorded-refusals.md)).
- **A real fine-tune survives the machine** — `workers/genome` fine-tunes a
  real model deterministically and writes its genome. Measured on hardware
  ([gcp-drill](../scripts/hardware-test/gcp-drill)) for a genome sealed in a
  SEV-SNP guest: on the pinned runtime it comes back bit for bit; on an
  NVIDIA L4 it comes back EQUIVALENT (16/16 identical top-1 tokens and
  greedy continuations, max |Δ logit| 1.9e-4); on an Intel CPU EQUIVALENT
  too; its recipe replays to a bit-identical adapter. At **7B**
  ([gpu-7b](../scripts/hardware-test/gpu-7b)): a 10 MB genome against 15 GB
  of base weights (1 : 1 502), EXACT on the pinned GPU. At **32B**
  ([azure-cgpu](../scripts/hardware-test/azure-cgpu), [C26](../VERIFIABLE-CLAIMS.md#c26)):
  Qwen2.5-32B-Instruct fine-tuned on a confidential H100, its 33.6 MB genome
  restored and gated **EXACT** on the H100 over the Return Path.
- **Automatic failover, decided by the operator** — a sentinel on the
  primary seals every new state with its key escrowed to the authority,
  attests every record with the primary's chip, and reports when a
  tripwire fires (`acpctl sentinel watch`). Under a failover policy the
  operator signed in advance, `sagvd failover` restores the last genome
  sealed before the intrusion, or before a lost heartbeat, on the one
  standby the policy names, and confirms the restore by the standby's
  TEE-signed gate verdict ([ADR 0012](adr/0012-sentinel-and-policy-driven-failover.md),
  [ADR 0017](adr/0017-limits-on-the-primarys-word.md)). Measured on live
  hardware:
  - SEV-SNP → SEV-SNP ([gcp-failover](../scripts/hardware-test/gcp-failover)):
    detect 2.53 s, RPO 9.0 s, **RTO 16.81 s** from intrusion to a gated,
    confirmed model; the clean generation came back gated **EXACT**.
  - SEV-SNP → an **Azure confidential GPU** across the Internet
    ([failover-cgpu](../scripts/hardware-test/failover-cgpu)): the key
    released on the H100 host's chip report, vTPM quote and NVIDIA's
    tokens; gated **EQUIVALENT** on the GPU, **RTO 24.99 s**.
  - SEV-SNP → an **Intel TDX** Trust Domain
    ([failover-tdx](../scripts/hardware-test/failover-tdx)): the key
    released on Intel's word for the platform, the TDX module and the
    Quoting Enclave; gated **EQUIVALENT** on Intel CPUs, **RTO 24.09 s**.
  - The authority itself on TDX, its escrow key in the vTPM
    ([failover-tdx-authority](../scripts/hardware-test/failover-tdx-authority)):
    RTO 20.27 s.
  - Asked eight times against one attack
    ([failover-negatives](../scripts/hardware-test/failover-negatives)): an
    expired policy, an RPO bound, a quarantine, an operator stop, a foreign
    standby, a spent policy and a stranger's signature each **refused** for
    their own stated reason — two of them *after* the standby's chip
    verified — and the one move went to the generation whose bytes matched
    the sentinel's word.
- **No secret file bare on a host** — the authority's escrow key is made in
  its own process and written only sealed to its chip
  ([ADR 0016](adr/0016-escrow-key-sealed-to-the-release-host.md)), or to the
  guest's vTPM where the TEE gives no sealing key
  ([ADR 0022](adr/0022-the-escrow-key-sealed-to-the-vtpm.md)); every other
  secret file the daemons read — signing seeds, the session sealing key,
  TLS keys, tokens, the sentinel's seed — is sealed to the host in place by
  `seal-keys` ([ADR 0023](adr/0023-the-daemons-key-files-sealed-to-the-host.md));
  a sealed file taken to another chip does not open
  ([C24](../VERIFIABLE-CLAIMS.md#c24), [C25](../VERIFIABLE-CLAIMS.md#c25)).
- **Real attestation, verified here** — an AMD SEV-SNP report is parsed,
  its signature verified and its VCEK chained to AMD's root, on GCP and
  Azure; an Intel TDX quote is verified through its attestation key and
  PCK chain to the Intel SGX Root CA, with Intel's signed TCB info and QE
  identity ([ADR 0018](adr/0018-intel-tdx-on-the-return-path.md)); an Azure
  confidential GPU VM's evidence carries the chip's report, the vTPM's
  quote binding the handshake and NVIDIA's tokens for the H100
  ([ADR 0019](adr/0019-a-confidential-gpu-worker-on-azure.md)). The GPU's
  attestation report is evaluated by this verifier too — signature, chain to
  NVIDIA's root, firmware id, every measurement against NVIDIA's signed
  reference manifests, and the chain's revocation asked of NVIDIA's OCSP
  responder — so a verdict may rest on our evaluation alone
  ([ADR 0021](adr/0021-the-verifiers-own-evaluation-of-the-gpu.md)), and
  what the verifier checked is on the audit record that admits the peer
  ([C20](../VERIFIABLE-CLAIMS.md#c20)).
- **Cross-hardware regeneration gate** — a signed EXACT / EQUIVALENT / FAIL
  verdict on recomputed reference fixtures, behind a determinism ladder
  that finds a working door (pinned float → reproducible float →
  byte-portable integer) or fails closed
  ([ADR 0008](adr/0008-equivalence-gate.md)). The integer door computes the
  real model's forward in integer arithmetic
  ([ADR 0020](adr/0020-the-integer-door-for-the-lora-worker.md)): a genome
  restored on an Intel Xeon and on an NVIDIA L4 gives **the same bytes**,
  at 0.5B and at 7B ([integer-door](../scripts/hardware-test/integer-door)).
- **A worker that restores the model, judged by the authority** — a job on
  `sagvd`'s REST API names a sealed genome; the authority ships its model
  side sealed over the Return Path, `acp-compute` brings the model back in
  memory and answers the genome's own reference prompts, and the authority
  holds the answers to the sealed references, signing the verdict
  ([ADR 0013](adr/0013-worker-restores-the-genome.md)). Nothing of the
  genome touches the worker's disk. A job is one Return Path frame of at
  most 128 MiB.
- **The vault daemon drives the nine stages** — every gate job goes through
  intake, Trust Admission, a signed session, staged disclosure, a signed
  manifest, the candidate, three-dimension validation and a signed release
  decision, with every decision on a signed, hash-chained audit log before
  it takes effect ([ADR 0014](adr/0014-return-path-on-the-record-and-on-hardware.md),
  [ADR 0015](adr/0015-one-binary-drives-the-nine-stages.md));
  `acpctl audit verify` checks the log under the published key.
- **Both ends of the Return Path attest with the chip** — `sagvd` and
  `acp-compute` run on SEV-SNP, TDX or the Azure confidential GPU VM, each
  pinning the other's measurement; a worker whose evidence is not the
  pinned identity gets no job, on the record.

## Honest boundaries

- Off hardware the daemons run a simulated TEE that announces itself and
  refuses to start without `tee.insecure_simulation: true`.
- No AWS Nitro or Intel SGX adapter attests. The Nitro verifier is written
  from AWS's specification and proven offline on the four production
  documents of May 2026 (ADR 0024, `acpctl attest nitro`); its producer and
  sealer are unproven, the SGX verifiers do not exist, and the registry
  refuses both families until a live enclave has been verified end to end
  ([ROADMAP.md](../ROADMAP.md)).
- The largest model measured is 32B, on one confidential GPU, on the pinned
  runtime; cross-device equivalence is measured at 0.5B and 7B; every
  failover number is at 0.5B.
- Byte-identical float inference across CPUs and GPUs is not achievable —
  divergence enters at the first transformer block
  ([gpu-exact](../scripts/hardware-test/gpu-exact)); the integer door is the
  answer, and the float doors fail closed, as they should.
- Under the `own` GPU policy the secure-boot and debug-mode claims only
  NVIDIA's tokens carry are not asserted; `both` asserts them.
- The reproducible-float rung stands on RepDL / ReproBLAS
  ([`prior-art-and-attribution.md`](prior-art-and-attribution.md)).
