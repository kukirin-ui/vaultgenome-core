# Verifiable claims

Every public claim this project makes, the artifact that proves it, and the
command that reproduces it. If a claim is not in this table, we are not making
it. If an artifact does not support its claim, that is a bug — open an issue.

The rule we hold ourselves to: **a claim is a measurement with a file behind
it, or it is not a claim.** Numbers below are copied from committed evidence,
not from memory. Every path is a file in this repository.

Reading order for an evaluator in a hurry: [C1](#c1), [C6](#c6), [C8](#c8),
[C11](#c11), [C12](#c12), [C13](#c13), [C14](#c14), [C15](#c15), [C16](#c16), [C17](#c17), [C18](#c18), [C19](#c19), [C20](#c20), [C21](#c21), [C22](#c22), [C23](#c23), [C24](#c24), [C25](#c25), [C26](#c26), then [What we do not claim](#what-we-do-not-claim) —
that last section is the one we would want to read first if we were evaluating someone else.

---

## Vocabulary, so the table cannot be misread

| Term | Precise meaning here |
| - | - |
| **EXACT** | Bit-identical outputs. Used only for (a) restoring sealed bytes, and (b) model replay **on the pinned runtime that sealed the genome**. |
| **EQUIVALENT** | Not bit-identical; measured difference inside a declared tolerance, and behaviourally identical on the sealed fixtures (same top-1 token, same greedy continuation). |
| **FAIL** | The gate refuses. Nothing is brought up. |
| **Pinned runtime** | Same device class, same framework build, same pinned dependency set as the sealing environment. |

The distinction between the first two rows is the whole product. We enforce it
in code (`internal/validation/reconstruction/ladder.go`) and we enforce it in
our own marketing: see [C5](#c5), where the gate itself **refuses** EXACT on a
GPU and falls to EQUIVALENT.

---

## Continuity of a real model

<a id="c1"></a>
### C1 — A real fine-tuned model's genome is ~1/447 the size of its base weights

**Claim.** For Qwen2.5-0.5B-Instruct fine-tuned with LoRA inside an AMD SEV-SNP
confidential VM, the sealed genome is **2,208,446 bytes** against **988,097,824
bytes** of base weights — a ratio of **1 : 447**. The genome carries the base
model's content digest, the sealed LoRA delta (540,672 adapter parameters) and
the deterministic recipe.

**Evidence.**
[`scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/seal.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/seal.json)
— `bundle_bytes: 2208446`, `payload_bytes: 2207232`, `component_count: 5`,
`payload_sha256: sha256:fe5271f1…f9d5`.
[`…/source/finetune.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/finetune.json)
— `adapter_parameters: 540672`, `loss_first: 5.325` → `loss_last: 0.00090`,
`train_seconds: 75.766`. The same drill on the raised runtime (torch
2.14.1, transformers 5.19.0),
[`…/20261014T032714Z/source/seal.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/seal.json)
— `bundle_bytes: 2216638` (1 : 446),
[`…/source/finetune.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/finetune.json)
— `loss_last: 0.00090`, `train_seconds: 72.219`.
The base-weights figure is `model.safetensors` of `Qwen/Qwen2.5-0.5B-Instruct`
@ `7ae5576`, recorded in
[the drill README](scripts/hardware-test/gcp-drill/README.md); every base file
is pinned by SHA-256 in the genome's manifest (`sha256:7504966b…e927`).

**Reproduce.** `bash scripts/hardware-test/gcp-drill/run.sh <gcp-project>`
(boots a SEV-SNP VM and a GPU VM, ~30 min, deletes both). See
[the drill README](scripts/hardware-test/gcp-drill/README.md).

**Caveat.** The ratio is a property of LoRA fine-tuning at this rank, not a
universal compression claim. A full-weight fine-tune has no such ratio. At
7B the same recipe gives 1 : 1 502 ([C16](#c16)); nothing larger has been
run — see [What we do not claim](#what-we-do-not-claim).

---

<a id="c2"></a>
### C2 — The genome replays to a bit-identical adapter on the pinned runtime

**Claim.** Re-running the sealed recipe on the pinned runtime reproduces the
adapter **bit for bit**: `max_abs_diff = 0.0`, `max_rel_diff = 0.0`, and every
training loss identical (`max_loss_diff = 0.0`).

**Evidence.**
[`…/source/replay-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/replay-source-cpu.json)
— `exact: true`, `losses_equal: true`; and on the raised runtime,
[`…/20261014T032714Z/source/replay-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/replay-source-cpu.json)
— `exact: true`, `max_abs_diff: 0`, `max_rel_l2: 0`, `losses_equal: true`.

**Reproduce.** Same drill as C1; the replay step is `replay-source-cpu`.

---

<a id="c3"></a>
### C3 — Restoring a sealed bundle is byte-exact, and authenticated before use

**Claim.** Opening a genome restores the recorded tree byte for byte
(5 files, 2,202,926 bytes, `tree_sha256: 5fe536b0…9503`) and every 1 MiB
segment is authenticated before any of it is used. An edited, truncated or
wrong-key bundle leaves the target untouched.

**Evidence.**
[`…/gpu/open-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/open-gpu.json)
and
[`…/gpu/verify-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/verify-gpu.json)
— `authenticated: true`, `restored_verify: "ok: every file matches its recorded
digest"`; and on the raised runtime,
[`…/20261014T032714Z/gpu/open-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/open-gpu.json) and
[`verify-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/verify-gpu.json) — 5 files,
2,210,904 bytes, `tree_sha256: efdb6aa5…1ab6`, the same verdict.
Tamper behaviour is asserted in
`internal/genome/bundle/*_test.go`.

**Reproduce, with no cloud and no hardware:**

```bash
make build
./bin/acpctl genome seal --content-dir=./my-model --output=gen-0.genome --key-out=gen-0.key
./bin/acpctl genome rewind --bundle=gen-0.genome --key-file=gen-0.key --target=./restored
diff -r ./my-model ./restored && echo "byte-exact"
```

This is the one claim in the table an evaluator can check in 60 seconds on a
laptop. **Note the scope:** this is byte-exactness of *sealed bytes*, which is
cryptography, not of *model inference across devices* — see [C5](#c5).

---

<a id="c4"></a>
### C4 — On the pinned runtime the restored model is EXACT on all 16 fixtures

**Claim.** The equivalence gate returns **EXACT** at door 0 (`pinned-replay`):
16/16 fixtures bit-identical, `max_abs_err: 0`, `max_rel_err: 0`.

**Evidence.**
[`…/source/gate-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/source/gate-source-cpu.json)
— `level: "EXACT"`, `n_exact: 16`, `n_mismatch: 0`,
`fixtures_hash: 98d31611…486b`; and on the raised runtime,
[`…/20261014T032714Z/source/gate-source-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/source/gate-source-cpu.json)
— `level: "EXACT"`, `n_exact: 16`, `fixtures_hash: 717daed9…c608`.

---

<a id="c5"></a>
### C5 — Across hardware the model is EQUIVALENT, and the gate says so itself

**Claim.** Restored on different hardware, the model is **not** bit-identical,
and our gate reports that rather than hiding it. On each device the gate tries
door 0 first, **fails it**, and falls through to door 1 (`native-float`):

| Destination | Door 0 `pinned-replay` | Door 1 `native-float` | max abs Δ logit | Fixtures | Gate time |
| - | - | - | - | - | - |
| Source AMD CPU (SEV-SNP, pinned) | **EXACT** | — | 0 | 16/16 exact | 9.73 s |
| NVIDIA L4 (us-east4) | **FAIL** | **EQUIVALENT** | 1.907e-4 | 16/16 equivalent | 11.83 s |
| Intel CPU | **FAIL** | **EQUIVALENT** | 1.450e-4 | 16/16 equivalent | 16.78 s |

Tolerance was declared in advance (`atol 1e-2`, `rtol 1e-3`), and the measured
error is ~50× inside it. `n_critical_mismatch: 0` on every device. On the
raised runtime (run `20261014T032714Z`, the L4 in us-central1-c) the same
shape: door 0 **FAIL** and door 1 **EQUIVALENT** on both destinations,
1.612e-04 on the L4 (11.36 s) and 1.459e-04 on the Intel CPU
(16.41 s), `n_critical_mismatch: 0`
([`…/20261014T032714Z/gpu/gate-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/gate-gpu.json),
[`gate-intel-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20261014T032714Z/gpu/gate-intel-cpu.json)).

**Evidence.**
[`…/gpu/gate-gpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/gate-gpu.json)
and
[`…/gpu/gate-intel-cpu.json`](scripts/hardware-test/gcp-drill/evidence/20260914T234359Z/gpu/gate-intel-cpu.json)
— read the `attempts` array: `[{rung 0, pinned-replay, "FAIL"}, {rung 1,
native-float, "EQUIVALENT"}]`.

**Why this is the most important row in the document.** A vendor who wanted to
overstate would report "EXACT" from C4 and stay quiet about the device. Our
gate is built so that it cannot: door 0 fails on foreign hardware, by
construction, and the failure is written into the signed verdict.

---

<a id="c6"></a>
### C6 — Byte-identical float across CPU and GPU is physically unavailable; we measured where it breaks

**Claim.** CPU↔GPU divergence for a real transformer enters at the **first
transformer block**, on **every** fixture, in **both** float32 and float64. It
is a property of the devices' matmul and transcendental kernels, not
accumulation over depth, and double precision shrinks it ~16× without closing
it. Token behaviour is nonetheless identical.

| CPU vs CUDA | max abs err | top-1 agree | top-64 order agree | first divergent layer |
| - | - | - | - | - |
| float32 | 1.5e-4 | 16/16 | 16/16 | layer 1 (all 16) |
| float64 | 9.5e-6 | 16/16 | 16/16 | layer 1 (all 16) |

An integer projection on the real `lm_head`, from identical quantised inputs,
is **byte-identical** on CPU and CUDA (`a03737b1f418` on both) — integer
arithmetic is associative, so a fixed-point path is device-portable by
construction.

**Evidence.**
[`scripts/hardware-test/gpu-exact/evidence/20260915T025643Z/probe.json`](scripts/hardware-test/gpu-exact/evidence/20260915T025643Z/probe.json),
narrated in [the probe README](scripts/hardware-test/gpu-exact/README.md);
and, on the raised runtime (torch 2.14.1+cu126, transformers 5.19.0),
[`scripts/hardware-test/gpu-exact/evidence/20261014T032040Z/probe.json`](scripts/hardware-test/gpu-exact/evidence/20261014T032040Z/probe.json)
— the same table to the rounding (1.48e-4 and 9.99e-6, layer 1 on all
16, top-1 and top-64 order 16/16, the integer projection `a03737b1f418`
again).

**Reproduce.** `bash scripts/hardware-test/gpu-exact/run.sh <gcp-project>`
(one L4, ~20 min, deletes the VM). The integer door this probe pointed at
now exists for the whole model: [C19](#c19).

**Why we publish a negative result.** It is the reason our ladder has the shape
it has, and it is the claim a serious reviewer will test first. Anyone
advertising "byte-exact AI across hardware" on native float is, on this
evidence, wrong.

---

## Attestation and governed key release

<a id="c7"></a>
### C7 — Real AMD SEV-SNP attestation, verified to AMD root, on two clouds

**Claim.** Attestation reports from live confidential VMs are parsed, their
ECDSA-P384 signatures verified, and the VCEK chained to **AMD ARK-Milan** — on
**GCP and Azure**. Key release happens only to a destination whose measurement
the operator's policy admits.

**Evidence.** `scripts/hardware-test/` (per-VM reports and cross-VM matrices);
ADR [0007](docs/adr/0007-measurement-variable-length.md) /
[0009](docs/adr/0009-x25519-kem-cross-cloud-key-delivery.md); operator procedure in
[`docs/operator/06_cross_cloud_restore.md`](docs/operator/06_cross_cloud_restore.md).
A concrete released-to measurement appears in the failover report below
(`destination_measurement_hex: 7dc7c12e…125acc`, `destination_kind:
gcp-sev-snp`).

**Scope.** Released to SEV-SNP destinations, once to an Azure
confidential GPU destination — an SEV-SNP guest whose Evidence also carries
the vTPM's quote and NVIDIA's tokens ([C18](#c18)) — and once to an Intel
TDX destination, its quote verified to Intel's root with Intel's TCB word
([C21](#c21)); AWS Nitro and SGX verifiers are **not** shipped — see
[What we do not claim](#what-we-do-not-claim).

---

<a id="c8"></a>
### C8 — A model under attack fails over to another machine, on real hardware, with the operator deciding

**Claim.** On two live SEV-SNP VMs: a sentinel on the primary seals each new
model state with its key escrowed to the authority; when a tripwire fires it
refuses to seal, signs a compromise report and exits 3. The authority, under a
failover policy the operator signed **in advance**, releases the key for the
last genome sealed **before** the intrusion to the one standby the policy
names. The standby restores it, gates it, and signs a receipt.

Measured end to end, run `20260915T021334Z`:

| Metric | Measured |
| - | - |
| Detect (tripwire → authority observes) | **2.53 s** |
| RPO (data at risk) | **9.00 s** |
| Key release | 0.27 s |
| Restore (5 files, 2,202,926 B) | **13.2 ms** |
| Gate on the standby | 13.54 s |
| **RTO (intrusion → gated, confirmed model)** | **16.81 s** |

Integrity of the outcome: restored **generation 1** — the clean state, *not*
the tampered one; gate level **EXACT** (16 fixtures, `max_abs_err: 0`) against
a required level of only `EQUIVALENT`; audit chain 5 events, verified;
`policy_version: failover-policy-v1;failover=1;revocation=1`.

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/standby/report.json`](scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/standby/report.json)
(the full signed report),
[`…/standby/audit-verify.json`](scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/standby/audit-verify.json),
[`…/primary/sentinel.json`](scripts/hardware-test/gcp-failover/evidence/20260915T021334Z/primary/sentinel.json).
Design: [ADR 0012](docs/adr/0012-sentinel-and-policy-driven-failover.md).

**Reproduce.** `bash scripts/hardware-test/gcp-failover/run.sh <gcp-project>`.

**The anti-worm invariants, stated so they can be checked against the code.**
One signed policy serial authorises **at most one** move
(`internal/vault/failover/gate.go`); every hop needs a fresh operator
signature; the operator stop list is a global halt that overrides any policy
([ADR 0010](docs/adr/0010-operator-stop-and-recorded-refusals.md)); a key is released only to an attested,
allow-listed measurement; every decision is written to the signed hash-chained
audit log **before** any key moves (`FAILOVER_DECIDED`, audit schema v6). This
system moves a model **because an operator signed for it to**, and cannot move
itself twice on one authorisation. That property is the difference between
continuity infrastructure and a worm, and we treat it as the primary safety
requirement of the project. Each invariant is exercised on live chips in
[C22](#c22): the spent policy, the operator stop, the foreign standby, the
expired policy and the corrupted bundle are each refused on the record.

---

<a id="c11"></a>
### C11 — The compute worker restores a real fine-tune in memory and the authority's gate says EXACT

**Claim.** A job on `sagvd`'s REST API names a sealed genome; `acp-compute`
restores the model through the `vg_genome` door from the components it was
sent — nothing of the genome touches its disk — and answers the genome's own
prompts; `sagvd` holds the answers to the sealed references and signs the
verdict. On the runtime that sealed the genome the verdict is **EXACT** on
every fixture ([ADR 0013](docs/adr/0013-worker-restores-the-genome.md)).

**Evidence.** Code and tests, not a hardware capture: the live-daemon suite
[`test/integration/daemons_test.go`](test/integration/daemons_test.go)
(`TestLiveDaemons_JobRoundTripOverMTLS`, `…GateRefusesAModelThatMissesItsReferences`,
`…EscrowedGenomeNeedsNoKeyFile`) runs the shipping `sagvd` and `acp-compute`
over mutual TLS with a door that speaks the protocol exactly
([`test/integration/fakedoor`](test/integration/fakedoor)); the
[`genome-worker`](.github/workflows/genome-worker.yml) workflow runs the real
door on a real fine-tune with the pinned torch
(`internal/compute/worker/genome_real_test.go`).

**Reproduce, with no cloud and no hardware:**

```bash
make test-integration
cd workers/genome && pip install -r requirements.txt && cd ../..
VG_GENOME_WORKER=$PWD/workers/genome go test -count=1 -v -run TestGenomeReconstructor_RealDoor ./internal/compute/worker/
```

**Scope.** The job carries an adapter of at most one Return Path frame, so a
full-weight fine-tune goes by key release ([C7](#c7), ADR 0011), not by job.
The same path on real SEV-SNP, with both daemons attesting with the chip and
every decision on the record, is [C12](#c12).

<a id="c12"></a>
### C12 — Both ends of the Return Path attest with real SEV-SNP, and every decision of the authority is on a verifiable record before it takes effect

**Claim.** `sagvd` and `acp-compute` run on an AMD SEV-SNP guest with
`tee.provider: "gcp-sev-snp"`, each pinning the other's 48-byte launch
measurement and verifying the other's Evidence to the AMD root during the
Return Path handshake. A worker whose Evidence is not the pinned identity is
refused at the handshake and gets no job. Every decision `sagvd` takes about
a job — accepted, worker admitted, candidate received, gate started, judged,
verdict signed — is written to its signed, hash-chained audit log **before**
the decision takes effect, and the log verifies offline under the key
`sagvd identity` publishes ([ADR 0014](docs/adr/0014-return-path-on-the-record-and-on-hardware.md)).

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260915T230907Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260915T230907Z/)
— `n2d-standard-4`, us-central1-c, kernel `7.0.0-1011-gcp`, `tsm.txt`
showing SEV-SNP active at VMPL0.
`sagvd-identity.json` and `acp-compute-identity.json`: `tee_provider:
gcp-sev-snp`, `tee_measurement_hex: 7dc7c12e…25acc` on both (one guest).
`sagvd.log`: the simulated-TEE worker's handshake refused
(`client TEE evidence verification failed … evidence shorter than SEV-SNP
report`), then `session opened` with `peer_measurement` equal to the pin.
`job.json`: `status: succeeded`, gate `EXACT`, `pinned replay`, rung 0,
`n_exact: 6` of 6, `max_abs_err: 0`, signed by `sagvd-authority-e2e`;
accepted 23:11:59.017Z, verdict 23:12:03.321Z — **4.30 s**.
`audit-verify.json`: `ok: true`, `event_count: 7`, tip `f6e1dc8f…1874`.
`audit-events.jsonl`, in order: `TRUST_EVALUATED` deny (`handshake`) ·
`MANIFEST_ISSUED` · `TRUST_EVALUATED` allow (`peer_measurement_hex` = the
pin) · `CANDIDATE_RECEIVED` · `VALIDATION_STARTED` ·
`VALIDATION_DIMENSION_EVALUATED` (EXACT) · `VALIDATION_COMPLETED` (pass,
`verdict_sha256`). `sagvd-metrics.txt`:
`sagvd_handshake_failures_total{phase="handshake"} 1`,
`sagvd_gate_verdicts_total{level="EXACT"} 1`.

The ordering is enforced in code, not only observed:
[`cmd/sagvd/http_api_test.go`](cmd/sagvd/http_api_test.go)
(`TestHTTPAPI_PostJobs_IsOnTheRecordFirst`) shows a job is on the log under
its id before it is queued and that a closed log refuses the submission;
[`cmd/sagvd/audit_returnpath_test.go`](cmd/sagvd/audit_returnpath_test.go)
shows a closed log stops the decision and an edited log is refused;
[`test/integration/daemons_test.go`](test/integration/daemons_test.go) reads
the same event sequence back from the shipping binaries.

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project>
make test-integration
go test -count=1 -run 'TestReturnPathAudit|TestHTTPAPI_PostJobs_IsOnTheRecordFirst' ./cmd/sagvd/
```

**Scope.** Both daemons ran in one guest, so the measurement each pins is its
own; the run proves genuine hardware Evidence on both sides and the pin being
enforced, not two machines. The model is a tiny random Llama built on the
guest so the run fits in minutes; the scale claims stay with [C1](#c1)–[C5](#c5).
The log records the peer's provider and measurement, not the SEV-SNP report
itself; the report that verifies offline is the receipt in [C7](#c7)'s
key-release evidence. Simulated TEEs remain available off hardware and
announce themselves at start (KNOWN_ISSUES #1).

<a id="c13"></a>
### C13 — The vault daemon drives the nine-stage flow for a real job on real SEV-SNP, and every stage is a signed, recorded decision

**Claim.** A gate job on `sagvd` is a RecoveryRequest that the daemon takes
through the nine stages of the governed reconstruction flow with the
library's own decision-makers — intake, Trust Admission, the session issuer,
the staged disclosure sequencer, the manifest, the Return Path, the
three-dimension validation service, the release decision, the audit seal —
every transition the state machine's, every decision on the audit log
before it takes effect, every artifact signed under the authority key
([ADR 0015](docs/adr/0015-one-binary-drives-the-nine-stages.md)). On an
AMD SEV-SNP guest with both daemons attesting with the chip, that flow ran
end to end and released.

**Evidence.**
[`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260916T003940Z/`](scripts/hardware-test/gcp-sev-snp/returnpath-e2e/evidence/20260916T003940Z/)
— `n2d-standard-4`, us-central1-c, both identities `tee_provider:
gcp-sev-snp`, measurement `7dc7c12e…25acc`.
`audit-verify.json`: `ok: true`, `event_count: 17`.
`audit-events.jsonl`, in order: `TRUST_EVALUATED` deny (a simulated-TEE
worker refused at the handshake) · `REQUEST_RECEIVED` · `TRUST_EVALUATED`
allow (`trust.peer_attested`, `gcp-sev-snp`, the measurement) ·
`SESSION_ISSUED` (`gate-policy/v1;atol=0.01;rtol=0.001;outliers=0`) ·
`DISCLOSURE_AUTHORIZED` ×5 · `MANIFEST_ISSUED` (5 disclosures, budget 666) ·
`CANDIDATE_RECEIVED` · `VALIDATION_STARTED` · `VALIDATION_DIMENSION_EVALUATED`
×3 (operational pass; semantic `top1-agreement` 6/6; behavioral
`equivalence-ladder` EXACT) · `VALIDATION_COMPLETED` (pass) ·
`RELEASE_DECIDED` (`release: true`, `validation_pass`, citing the
attestation).
`job.json`: `state: release_authorized`, 10 transitions, the signed
attestation, session, manifest, validation result and decision — the
decision's `audit_event_id` is the `RELEASE_DECIDED` event's id — intake to
seal **4.48 s**. `sagvd-metrics.txt`:
`sagvd_release_decisions_total{decision="release"} 1`.

The same flow, in process and with the shipping binaries:
[`cmd/sagvd/daemon_flow_test.go`](cmd/sagvd/daemon_flow_test.go) (a release,
a trust denial without a session, a refused model closed as an incident,
an answer that is not an answer, a stale worker sent to attest again),
[`internal/vault/orchestration/flow_test.go`](internal/vault/orchestration/flow_test.go)
(every artifact verified, every stage order-checked, a chain that refuses
a record stops the stage),
[`test/integration/daemons_test.go`](test/integration/daemons_test.go)
(the audit record read back through `acpctl`; the operator's stop-all
denying a job at trust, on the record).

**Reproduce:**

```bash
scripts/hardware-test/gcp-sev-snp/returnpath-e2e/run.sh <gcp-project>
go test -count=1 -run 'TestDaemon_|TestFlow_' ./cmd/sagvd/ ./internal/vault/orchestration/
make test-integration
```

**Scope.** One guest, one worker, one job at a time; the receive-side
round trip (§7 of the recovery-flow document) is still library code no
binary drives. The semantic dimension is top-1 agreement at the reference
positions, not a task-level evaluation; the behavioral dimension is the
gate of [C4](#c4)/[C5](#c5). The model is the tiny one of [C12](#c12).

---

<a id="c14"></a>
### C14 — The escrow key is sealed to the release host's SEV-SNP chip, and a failover takes the primary's word only with its chip's report on it

**Claim.** The release authority's escrow private key — the one that opens
every escrowed genome — is made inside the authority's process and written
only sealed to its host's TEE: on AMD SEV-SNP, under a key the firmware
derives for that chip, launch measurement and guest policy
(`SNP_GET_DERIVED_KEY`), never stored; it is unsealed in memory at start
and survives its chip only through the operator's recovery envelope
([ADR 0016](docs/adr/0016-escrow-key-sealed-to-the-release-host.md)). And
the sentinel on the primary puts the primary chip's report on every record
it writes, so that under a policy pinning that chip a record without a
verifying report is ignored, a sentinel that said `stopped` stands the
authority down only for a grace, and nothing past the generation the
trigger's own record names is restored
([ADR 0017](docs/adr/0017-limits-on-the-primarys-word.md)). Both ran on
two SEV-SNP guests, with a rogue sentinel holding the stolen seed refused.

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260916T021933Z/`](scripts/hardware-test/gcp-failover/evidence/20260916T021933Z/)
— primary `n2d-standard-8` (measurement `10f5ac22…4519`), standby
`n2d-standard-4` (measurement `7dc7c12e…5acc`), us-central1-c, both
`Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP` with
`/dev/sev-guest` (`tsm.txt`).
`standby/escrow-provision.json`: the escrow key's tag `d2aac7b965c6ab76`,
`tee: gcp-sev-snp`, `source: generated`, wrapped to the operator's
recovery key (tag `93b4bd0871bfacf6`);
`escrow-sealed-shape.txt`: `vault-genome/sealed-escrow-key/v1`, the sealed
field 80 base64 characters, no key file;
`escrow-reprovision.json`: the recovery ceremony (`acpctl escrow recover`
piped into `sagvd escrow-provision -stdin`) re-sealed the same key,
`source: stdin`; `authority-identity.json`:
`key_escrow_storage: sealed:gcp-sev-snp`; `failover.log`: `failover escrow
key … storage: sealed:gcp-sev-snp` — the key that opened the genome's
envelope was the unsealed one.
`primary/sentinel.json`: `tee: gcp-sev-snp`, the compromise report with
`attestation.kind: gcp-sev-snp`; `standby/failover-verify.txt`: the policy
pins `primary TEE: gcp-sev-snp, measurements 10f5ac22…4519 (every record
must carry its report)` and `stopped and not back within 60s`.
`standby/report.json`: `status: restored`, trigger `compromise-report`
with `primary_measurement_hex` = the primary's chip, generation 1 restored
(`genome-134ad7e32883-g1-d9318608d0c0`), gate **EXACT** (16 fixtures,
max abs err 0; required EQUIVALENT), detect 7.69 s, RPO 9.00 s, **RTO
23.98 s**; `audit-verify.json`: `ok: true`, 5 events.
`standby/rogue-report.json` — the stolen seed on the standby's own chip,
every record a genuine SEV-SNP report from the wrong machine:
`ignored: [heartbeat.json: … gcp-sev-snp attestation does not verify: …
MEASUREMENT 7dc7c12e…5acc not in acceptable set]`, trigger
`heartbeat-timeout` at the primary's last genuine heartbeat,
`gen-000002.seal.json` set aside *after generation 1, the last the
sentinel's heartbeat-timeout names*, `status: declined` on the record
(audit chain length 6), no key moved.

In process and with the shipping binaries:
[`internal/shared/tee/gcp_sev_snp_seal_test.go`](internal/shared/tee/gcp_sev_snp_seal_test.go)
(the derived-key request, the expansion, a different chip, image or policy
opens nothing),
[`internal/genome/escrow/sealed_test.go`](internal/genome/escrow/sealed_test.go),
[`cmd/sagvd/escrow_key_test.go`](cmd/sagvd/escrow_key_test.go) (a
plaintext key refused on hardware; the ceremony through stdin),
[`internal/genome/sentinel/attest_test.go`](internal/genome/sentinel/attest_test.go)
(the report binds the record; re-signed, borrowed or tampered records do
not verify),
[`internal/vault/failover/limits_test.go`](internal/vault/failover/limits_test.go)
(the stolen seed as silence; only attested genomes; the chain trusted to
the sentinel's last word; `stopped` overdue),
[`test/integration/failover_test.go`](test/integration/failover_test.go)
(`TestLiveFailover_AttestedPrimary`, `TestLiveFailover_StoppedOverdue`).

**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project>
go test -count=1 -run 'SEVSealer|Sealed|Recovery|Escrow|Attest|Pinned|StolenSeed|LastWord|Overdue' ./internal/shared/tee/ ./internal/genome/... ./internal/vault/failover/ ./cmd/sagvd/
make test-integration
```

**Scope.** The escrow key alone is sealed; the authority's signing seed,
audit seed and session-sealing key are still files (KNOWN_ISSUES #1, #11).
The sealed key is bound to the chip and the launch measurement, so a
restart on another host or a new image needs the operator's ceremony;
nothing re-provisions itself. The chip's word bounds an attacker who holds
the seed without the chip; an intruder with root inside the primary's
guest holds both and is caught only by the wires (KNOWN_ISSUES #12). The
model is Qwen2.5-0.5B-Instruct with a LoRA adapter; both machines are CPU
confidential VMs.

---

<a id="c15"></a>
### C15 — Both ends of the Return Path attest with real Intel TDX, verified to Intel's root and Intel's TCB word

**Claim.** `sagvd` and `acp-compute` attest with the Trust Domain they run
in (`tee.provider: "gcp-tdx"`): a TDX quote through the kernel's
configfs-tsm with the handshake's challenge in REPORTDATA, and as the
measurement the SHA-384 of MRTD and RTMR0..3 — the firmware and the boot
chain in one 48-byte pin. The verifier on the other side chains the quote's
PCK certificates to the pinned Intel SGX Root CA, checks the attestation
key's and the PCK leaf's signatures and the QE report's binding of the key,
fetches Intel's TCB info and QE identity from Intel PCS and verifies their
signatures before reading them, requires the platform, the TDX module and
the QE to be at an accepted TCB status (`UpToDate` unless the operator says
otherwise; `OutOfDate` and `Revoked` never), refuses a debuggable TD, binds
the nonce and compares the measurement with the pin
([ADR 0018](docs/adr/0018-intel-tdx-on-the-return-path.md)). On a GCP
Trust Domain, a gate job went through the nine stages and released, and a
worker whose Evidence was not a TDX quote was refused on the record.

**Evidence.**
[`scripts/hardware-test/gcp-tdx/capture/evidence/20260916T031937Z/`](scripts/hardware-test/gcp-tdx/capture/evidence/20260916T031937Z/)
— a genuine `c3-standard-4` quote (8 000 bytes, version 4, TEE type TDX,
`TDATTRIBUTES` without DEBUG, MRTD `c1ee9c16…70a5`, RTMR3 zero) with the
caller's nonce in REPORTDATA, its PCK chain (3 certificates, FMSPC
`00806f050000`), Intel's TCB info (6 levels, the highest `UpToDate`), QE
identity, root CA and CRLs; the verifier's tests run against it offline
([`internal/shared/tee/gcp_tdx_test.go`](internal/shared/tee/gcp_tdx_test.go):
the genuine quote verifies; another root, a flipped DEBUG bit, a changed
byte, a wrong nonce, an unpinned measurement, an edited TCB level, an
expired document or a stale cache without network is refused).
[`scripts/hardware-test/gcp-tdx/returnpath-e2e/evidence/20260916T040416Z/`](scripts/hardware-test/gcp-tdx/returnpath-e2e/evidence/20260916T040416Z/)
— us-central1-a, `c3-standard-4`, `tsm.txt`: `tdx: Guest detected`,
`Memory Encryption Features active: Intel TDX`, `/dev/tdx_guest`.
`sagvd-identity.json` and `acp-compute-identity.json`: `tee_provider:
gcp-tdx`, measurement `ed70198a…177b` on both with the `tdx` block it is
made of (`steps.txt` recomputes it; the same MRTD and RTMRs as the capture
44 minutes earlier on another guest of the same image).
`audit-events.jsonl`, event 1: `TRUST_EVALUATED` deny, `gcp-tdx: parse
quote: quote is 147 bytes, shorter than a header and TD report (636)` — the
simulated TEE's Evidence, refused within 1 s; event 3: `TRUST_EVALUATED`
allow, `trust.peer_attested`, `gcp-tdx`, the pinned measurement.
`job.json`: `POST /v1/jobs` 202 → `release_authorized` in **3.37 s**, gate
**EXACT** (`pinned replay`, 6/6 fixtures, max abs err 0), top-1 6/6, the
signed decision `dec-d6fd9410c50e2fcf` citing attestation
`att-fdc9b5ad-…-0001`; `audit-verify.json`: `ok: true`, **17 events**;
`sagvd-metrics.txt`: `vg_tee_attestation_total{provider="gcp-tdx"}` —
3 produce, 2 verify success, 1 verify error; `pcs-tdx-tcb-00806f050000.json`
and `pcs-tdx-qe-identity.json` with their issuer chains: Intel's documents
as both verifiers fetched them, for offline re-verification.

**Reproduce:**

```bash
scripts/hardware-test/gcp-tdx/capture/run.sh <gcp-project>
scripts/hardware-test/gcp-tdx/returnpath-e2e/run.sh <gcp-project>
go test -count=1 -run 'TDX' ./internal/shared/tee/ ./cmd/sagvd/ ./cmd/acp-compute/ ./cmd/acp-bootstrap/
```

**Scope.** Both daemons ran inside one Trust Domain; the pin is the
image's, so a second guest of the same image has the same measurement. The
CPU side only: the machine had no GPU, and the GPU's own attestation
(NVIDIA confidential computing) is not wired. A key release to a TDX
destination (`acp-bootstrap` on TDX) has since run on hardware, once, as
the standby of a failover ([C21](#c21)), and an authority on TDX has
held its escrow key sealed to the guest's vTPM ([C23](#c23), ADR 0022).
Intel PCS was reachable from the guest; without
it and without a cache the verifier refuses. The model is a tiny one built
on the guest to prove the path, not the scale.

---

<a id="c16"></a>
### C16 — A 7B model goes through the genome path on one GPU: a 10 MB genome, restored and gated EXACT on the pinned runtime; across devices in bfloat16 the float door fails closed while the model's answers do not change

**Claim.** Qwen2.5-7B-Instruct fine-tuned by `vg_genome` on an NVIDIA L4 in
bfloat16 — the recipe records the device and the dtype, and the door
restores the base in the recipe's dtype — is sealed as a 10 142 001-byte
genome against 15 231 271 888 bytes of base weights (1 : 1 502), restored
from the bundle, gated **EXACT** through the door on the same GPU, and its
recipe replays there to a bit-identical adapter. On the host's CPU the same
genome gives the same top-1 token and the same 16-token greedy
continuation on every fixture, and its bfloat16 logits differ by up to 0.5
— one or two bfloat16 quanta at their magnitude — so the float door fails
closed.

**Evidence.**
[`scripts/hardware-test/gpu-7b/evidence/20260916T043622Z/`](scripts/hardware-test/gpu-7b/evidence/20260916T043622Z/)
— `g2-standard-8` in us-central1-b, NVIDIA L4 (driver 580.173.02), torch
2.7.1+cu126 (`nvidia-smi.txt`, `torch.txt`, `pip-freeze.txt`).
`finetune.json`: `device: cuda`, `dtype: bfloat16`, `adapter_parameters:
2523136`, `loss_first: 6.002` → `loss_last: 0.000713`, `train_seconds:
32.378`; `genome.json` carries the recipe and the base manifest
(`sha256:f571d6a7…6107`). `seal.json`: `bundle_bytes: 10142001`,
`payload_bytes: 10140672`, `component_count: 5`; `verify.json`:
`restored_verify: ok`. `gate-gpu.json`: `level: EXACT`, rung 0 `pinned
replay`, 16/16, `max_abs_err: 0`; `measure-gpu.json`: `exact: 16`,
`top1_same: 16`, `greedy_same: 16`; `replay-gpu.json`: `exact: true`,
`losses_equal: true`. `gate-cpu.json`: `level: FAIL`, both rungs at
`max_abs_err: 0.5`; `measure-cpu.json`: `exact: 0`, `top1_same: 16`,
`greedy_same: 16`, `max_abs_err: 0.5`, `max_rel_err: 0.027`, every fixture
between 0.125 and 0.5. Base-weights bytes: the four `model-*.safetensors`
of `Qwen/Qwen2.5-7B-Instruct` @ `a09a354`. The same kit on the raised
runtime, torch 2.14.1+cu126 and transformers 5.19.0:
[`scripts/hardware-test/gpu-7b/evidence/20261014T022551Z/`](scripts/hardware-test/gpu-7b/evidence/20261014T022551Z/)
— `replay-gpu.json`: `exact: true`, `max_abs_diff: 0`, `losses_equal:
true`; `gate-gpu.json`: `level: EXACT`, rung 0, 16/16; `gate-cpu.json`:
`level: EXACT` at rung 2 through the integer door, after both float
doors failed at `max_abs_err: 0.375`; `measure-cpu.json`: `exact: 0`,
`top1_same: 16`, `greedy_same: 16`, `max_abs_err: 0.375`. torch 2.14.1
warns there that flash attention's backward may not be deterministic
under `warn_only`; the replay measured that it was, at these shapes.
In process:
[`workers/genome/tests/test_genome.py`](workers/genome/tests/test_genome.py)
(a bfloat16 genome records its runtime and the door honours it; an unknown
dtype is refused; a genome that predates the field restores in float32).

**Reproduce:**

```bash
scripts/hardware-test/gpu-7b/run.sh <gcp-project>     # one g2-standard-8, ~35 min
cd workers/genome && python -m pytest -q tests/
```

**Scope.** One GPU, one host CPU, one model; LoRA r=8 on two projections;
16 fixtures. The L4 is not a confidential GPU: nothing in this run is
attested, and the sealed genome was opened on the machine that made it
([C17](#c17) is the attested one). The
cross-device result is a measurement of bfloat16 kernels on two devices,
not a property of the model: the float door's default tolerance is the
float32 one; a bfloat16 tolerance is the operator's to set
(`genome.gate.bfloat16`, pinned into every session's policy); the
byte-portable route for such a genome is the integer door, shipped since
[C19](#c19) — on the raised runtime the gate on the host CPU opens
through it, rung 2 EXACT. Frontier scale has not been run.

---

<a id="c17"></a>
### C17 — A confidential GPU worker: on an Azure NCC H100 v5 the Return Path carries the chip's report, the vTPM's quote and NVIDIA's tokens for the H100, and the 7B genome is restored on the GPU in confidential-computing mode

**Claim.** `sagvd` and `acp-compute` attest as an Azure confidential GPU
VM (`tee.provider: "azure-cgpu"`): one Evidence for a handshake nonce
carrying the SEV-SNP report Azure keeps in the vTPM (whose `REPORT_DATA`
is the hash of the runtime data naming the vTPM's attestation key), a TPM
quote by that key with `SHA-256(nonce)` in `extraData`, and NVIDIA's
signed attestation tokens for the H100 under the same value. The verifier
takes the report to AMD's Genoa root, the quote under the key the chip
named, and the tokens under NVIDIA's key set with a claims policy —
overall result, nonce, measurements matched, secure boot, no debug, the
manifests signed, the model, driver and VBIOS pinned when the operator
says so ([ADR 0019](docs/adr/0019-a-confidential-gpu-worker-on-azure.md)).
On such a VM a gate job went through the nine stages with the 7B genome
restored through the door on the H100 in confidential-computing mode, and
a worker whose evidence was not that envelope was refused on the record.

**Evidence.**
[`scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/`](scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/)
— `conf-compute.txt`: `CPU CC Capabilities: AMD SEV-SNP (vTOM Mode)`,
`GPU CC Capabilities: CC Capable`, `CC GPUs Ready State: Ready`;
`hcl-summary.json`: SNP report version 5, no DEBUG, VMPL 0, measurement
`aa7c9da5…0eef`, `REPORT_DATA` = SHA-256 of the runtime data naming
`HCLAkPub`; `cert-chain.pem`: the Genoa ASK+ARK Azure served;
`quote1.msg`/`quote1.sig`: a TPMS_ATTEST over PCRs 0–14 with the capture's
nonce, `Verified OK` under `ak-pub.pem` (handle `0x81000003`);
`nras-claims-decoded.json`: ES384 by `nv-eat-kid-prod-20260916090709987-…`,
`x-nvidia-overall-att-result: true`, `eat_nonce` = the nonce, GPU-0
`hwmodel GH100`, driver `595.71.05`, VBIOS `96.00.9F.00.04`, `measres
success`, `secboot true`, `dbgstat disabled`; `local-verifier.txt`:
NVIDIA's local verifier's own pass; `gate-gpu.json`, `measure-gpu.json`,
`replay-gpu.json`: the 7B genome (26.2 s of training on the H100, 10 142
001 bytes) gated **EXACT** on the GPU and replayed bit for bit.
[`…/evidence/20260916T133506Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z-returnpath/)
— `sagvd-identity.json`, `acp-compute-identity.json`: `tee_provider:
azure-cgpu`, measurement `aa7c9da5…0eef`; `audit-events.jsonl` event 1:
`TRUST_EVALUATED` deny (`evidence is not a vault-genome/azure-cgpu-evidence/v1
envelope`), event 3: allow, `trust.peer_attested`; `job.json`: `POST
/v1/jobs` → `release_authorized` in **18.5 s**, gate **EXACT** (16/16, max
abs err 0), top-1 16/16; `audit-verify.json`: `ok: true`, **17 events**;
`sagvd-metrics.txt`: `vg_tee_attestation_total{provider="azure-cgpu"}`
produce 2, verify success 1, verify error 1.
In process:
[`internal/shared/tee/azure_cgpu_evidence_test.go`](internal/shared/tee/azure_cgpu_evidence_test.go)
(the captured evidence verifies offline with the nonce that produced it,
and is refused for the other nonce, an unlisted driver, past the tokens'
expiry, under the Milan chain),
[`azure_cgpu_test.go`](internal/shared/tee/azure_cgpu_test.go),
[`azure_cgpu_hcl_test.go`](internal/shared/tee/azure_cgpu_hcl_test.go),
[`azure_cgpu_tpm_test.go`](internal/shared/tee/azure_cgpu_tpm_test.go),
[`nvidia_eat_test.go`](internal/shared/tee/nvidia_eat_test.go).

**Reproduce:**

```bash
scripts/hardware-test/azure-cgpu/run.sh vg-cgpu-weu westeurope
go test -count=1 -run 'AzureCGPU|HCL|TPMQuote|NRAS' ./internal/shared/tee/ ./cmd/sagvd/ ./cmd/acp-compute/ ./cmd/acp-bootstrap/
```

**Scope.** Both daemons ran in one guest; the pin is Azure's launch
measurement, which covers the paravisor and firmware, not the OS — the
vTPM's PCRs were recorded in the quote and not policed in this run (a
`pcr_digests` pin exists since, and [C18](#c18) uses it). The GPU's
measurements are evaluated by NVIDIA's service against NVIDIA's reference
manifests; this run's verifier verified NVIDIA's signed tokens and did
not evaluate the GPU's SPDM report itself (it is in the evidence; since
ADR 0021 the verifier does, offline on this very capture — [C20](#c20)).
NRAS is on
the path when evidence is produced. A key release to such a machine
(`acp-bootstrap` on `azure-cgpu`) has since been run as the standby of a
failover ([C18](#c18)); the escrow key on this host seals to its vTPM
since ADR 0022 (proven on `20260916T204311Z-returnpath`: `escrow-provision.json` `tee: azure-cgpu`, the key re-sealed through the recovery ceremony). The model is 7B in bfloat16; the machine cost about $9 an hour and
lived for 35 minutes.

---

<a id="c18"></a>
### C18 — A model under attack on a CPU TEE fails over to an attested confidential GPU in another cloud: the key released on the chip's report, the vTPM's quote and NVIDIA's tokens, the clean generation gated EQUIVALENT on the H100

**Claim.** The failover of [C8](#c8) and [C14](#c14) with the standby an
Azure NCC H100 v5 (`acp-bootstrap` on `tee.provider: "azure-cgpu"`)
reached over the Internet. Under a policy the operator signed in advance —
pinning the primary's chip, the standby's launch measurement and, in the
registry, its vTPM's boot — the authority (GCP SEV-SNP, its escrow key
sealed to its chip) took the primary's attested compromise report,
verified the standby's SEV-SNP report to AMD's Genoa root, its TPM quote
under the vTPM's attestation key against the pinned PCR digest, and
NVIDIA's tokens for the H100 under NVIDIA's key set and the claims policy,
released the key for the last generation sealed before the attack, and
confirmed the standby's receipt: the genome restored and gated through the
door on the H100 in confidential-computing mode. Every step is on the
audit record.

**Evidence.**
[`scripts/hardware-test/failover-cgpu/evidence/20260916T150456Z/`](scripts/hardware-test/failover-cgpu/evidence/20260916T150456Z/)
— `authority/report.json`: `status: restored`; trigger `compromise-report`
at 15:12:35.07Z with `primary_measurement_hex: 69da361d…c790`; `decision:
failover … restore generation 1 on the standby`; `release.destination_kind:
azure-cgpu`, `destination_measurement_hex: aa7c9da5…0eef`,
`policy_version: failover-policy-v1;failover=1;revocation=1`;
`restore.gate`: **EQUIVALENT**, door native float, 16 fixtures,
`max_abs_err: 1.516e-4`, `max_rel_err: 1.65e-5`, `backend_seconds: 12.11`;
`timing`: detect 5.59 s, release 1.30 s, restore 11.4 ms, gate 12.11 s,
failover 19.40 s, **RTO 24.99 s**, **RPO 12.00 s**; `audit_chain_length:
5`. `authority/verifiers.json`: the `azure-cgpu` entry with the Genoa
chain, `gpu_policy.hw_models: ["GH100"]` and `pcr_digests:
["92fe2c20…26e2"]`, and the `gcp-sev-snp` entry — the primary's anchors.
`authority/failover-verify.txt`: the signed policy, serial 1, standby
`azure-cgpu https://…:8443`. `authority/audit-verify.json`: `ok: true`, 5
events (`FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` →
`CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_AUTHORIZED` →
`CROSS_CLOUD_RESTORE_COMPLETED`), tip `d46be63a…943a`.
`authority/escrow-provision.json`: `tee: gcp-sev-snp`, sealed.
`destination/destination-identity.json`: `tee_provider: azure-cgpu`,
measurement `aa7c9da5…0eef`, `vtpm.pcr_digest_hex: 92fe2c20…26e2`.
`destination/genome-…-g1-….receipt.json`: the receipt (`destination_kind:
azure-cgpu`, generation 1, `gate.level: EQUIVALENT`) with its
`vault-genome/azure-cgpu-evidence/v1` Evidence — HCL report, quote,
NVIDIA's tokens. `destination/conf-compute.txt`: `CC State: ON`, `CC GPUs
Ready State: Ready`; `destination/gpu.csv`: H100 NVL, driver 595.71.05,
VBIOS 96.00.9F.00.04. `destination/acp-bootstrap.log`: handshake
answered, key released, restore, gate, key erased. `primary/sentinel.json`:
`outcome: compromised`, `attestation.kind: gcp-sev-snp`, last generation 1.

**Reproduce:**

```bash
scripts/hardware-test/failover-cgpu/run.sh <gcp-project> europe-west4-a vg-cgpu-weu   # ~25 min: two GCP n2d Milan CVMs + an Azure NCC H100 v5
```

**Scope.** One run, with the 0.5B model of the failover drill, trained on
the primary's CPUs in float32 and proven on the GPU: EQUIVALENT (max abs
err 1.5e-4 against atol 1e-2), not EXACT — the same-device EXACT of
[C14](#c14) is not available across devices ([C6](#c6)). The GPU's
measurements are NVIDIA's evaluation, verified by NVIDIA's signature
([C17](#c17) scope). In that run the standby held no sealed escrow key;
since ADR 0022 it seals one to its vTPM and can be an authority.
The vTPM pin is a property of a boot. The other CPU TEE family as the
standby is [C21](#c21).

---

<a id="c19"></a>
### C19 — The integer door: a real model restored on an Intel Xeon and on an NVIDIA L4 gives the same bytes, at 0.5B and at 7B, and the gate holds it to those bytes at tolerance zero

**Claim.** The gate's third door ([ADR 0020](docs/adr/0020-the-integer-door-for-the-lora-worker.md))
computes the restored LoRA model's forward pass in integer arithmetic —
int8 weights with the delta merged, 14-bit activations, int8 GEMMs, an
integer RMSNorm, rotary tables derived without a float, an integer
exponential — and is held to references the same arithmetic sealed with
the genome. On real hardware the same genome gives byte-identical logits
on a CPU and on a GPU, whichever device made the references: a 0.5B
genome made on eight Xeon cores reproduces its references on the L4, and
a 7B genome made on the L4 reproduces its references on the Xeon. At zero
tolerance on the GPU the float doors fail and the integer door opens
EXACT. The door is a different model from the float one, and its
fidelity is measured, not assumed: the same top-1 token on every fixture,
a logit error the genome records.

**Evidence.**
[`scripts/hardware-test/integer-door/evidence/20260916T164511Z/`](scripts/hardware-test/integer-door/evidence/20260916T164511Z/)
— `a-measure-integer-cpu.json` and `a-measure-integer-cuda.json` (the 0.5B
genome, references recorded on the CPU): `exact: 16` of 16 on both
devices, the same `results[].sha256` for all 16 fixtures, `top1_same: 16`,
`max_abs_err: 2.72`, `max_rel_err: 0.25` against the float references;
`a-measure-float-cuda.json`: the float door on the L4, `max_abs_err:
1.52e-4`, `exact: 0`; `a-gate-cuda-tol0.json`: `--atol 0 --rtol 0` on the
L4 — attempts `pinned-replay FAIL 1.52e-4`, `native-float FAIL 1.52e-4`,
`fixed-point EXACT 0`, level **EXACT** at rung 2; `a-gate-cuda.json`:
the default tolerance opens rung 1 EQUIVALENT; `a-gate-cpu.json`: rung 0
EXACT on the machine that sealed. `b-measure-integer-cuda.json` (the 7B
genome, bfloat16, references recorded on the L4): `exact: 16` of 16,
`top1_same: 16`, `max_abs_err: 1.32`, `max_rel_err: 0.14`;
`b-measure-integer-cpu.json`: the first three fixtures on the Xeon,
`exact: 3` of 3, the same `sha256` as on the L4. `divides-exactly.txt`:
both devices divide int64 exactly. `a-genome.json`, `b-genome.json`:
`fixtures.integer` (scheme `vg-integer-door/v1`, fidelity). The same kit
on the raised runtime, torch 2.14.1+cu126 and transformers 5.19.0:
[`scripts/hardware-test/integer-door/evidence/20261014T020420Z/`](scripts/hardware-test/integer-door/evidence/20261014T020420Z/)
— `exact: 16` of 16 on both devices at 0.5B with the same `sha256` for
every fixture, `max_abs_err: 2.70`, `top1_same: 16`; `exact: 16` of 16
on the L4 and `3` of 3 on the Xeon at 7B, `max_abs_err: 0.79`; the gate
at zero tolerance EXACT at rung 2 after `FAIL 1.18e-4` on both float
doors. In process:
[`workers/genome/tests/test_integer.py`](workers/genome/tests/test_integer.py)
(the constants against libm, the primitives against Python integers, the
same bytes at another thread count and on every device the test can
reach, a tampered adapter changing them, the door and the gate protocol),
[`internal/genome/lora/integer_test.go`](internal/genome/lora/integer_test.go),
[`internal/validation/reconstruction/integer_door_test.go`](internal/validation/reconstruction/integer_door_test.go),
[`internal/bootstrap/restorer/gate_integer_test.go`](internal/bootstrap/restorer/gate_integer_test.go),
[`cmd/acpctl/genome_gate_integer_test.go`](cmd/acpctl/genome_gate_integer_test.go),
[`cmd/sagvd/genome_integer_test.go`](cmd/sagvd/genome_integer_test.go).

**Reproduce:**

```bash
scripts/hardware-test/integer-door/run.sh <gcp-project>       # one L4 VM, ~20 min, deletes it
cd workers/genome && python -m pytest -q tests/test_integer.py
```

**Scope.** Two devices (an Intel Xeon and an NVIDIA L4; an Apple GPU in
the worker's tests), two models, two runs on two runtimes (torch 2.7.1
and 2.14.1). Byte identity is of the integer model with itself across
devices, not of the integer model with the float model: the float doors
stay the fidelity path and the integer door the availability path. The
fidelity measured here — top-1 the same on every fixture, logits within
a few units on fine-tunes that drove them to magnitudes of tens — is a
property of these genomes; a genome records its own. The 7B check on the
CPU covered three fixtures. The integer door is not a serving path: a 7B
forward takes seconds per fixture. A third run
([`20261014T012445Z`](scripts/hardware-test/integer-door/evidence/20261014T012445Z/))
held byte identity while the door computed the wrong model: transformers
5 had moved a config's rotary base into `rope_parameters`, the door's
reader fell back to 10 000 where Qwen2.5 has 1 000 000, and every
exactness check passed — the same wrong tables on both devices. Only the
fidelity record showed it (top-1 13 of 16, max abs err 7.29). Byte
identity is a property of the program and says nothing about the program
being the right one; the door now reads the base from the config with no
default, refuses a model whose own rotary module disagrees with it, and
refuses projections whose shapes disagree with the config's head counts
(the kit's README has the account).

---

<a id="c20"></a>
### C20 — The verifier evaluates the H100's attestation report itself: signature, chain to NVIDIA's root, firmware id, and every measurement against NVIDIA's signed reference manifests — on the captured report, complete, refusing what should be refused, and admitted to carry the verdict alone

**Claim.** Beside NVIDIA's signed verdict, the `azure-cgpu` verifier
evaluates the GPU's SPDM attestation report on its own
([ADR 0021](docs/adr/0021-the-verifiers-own-evaluation-of-the-gpu.md)):
the report parses (SPDM 1.1 GET_MEASUREMENTS and MEASUREMENTS, 64 DMTF
blocks), its nonce is the verifier's challenge, its ECDSA P-384 signature
verifies under the GPU's attestation certificate, that certificate's
chain verifies to the NVIDIA Device Identity CA pinned in the binary, the
firmware id in the certificate's DICE extension is the report's, the
driver and VBIOS reference manifests the report names are fetched from
NVIDIA's RIM service — versions matching, chains verifying to the pinned
NVIDIA CoRIM signing root, bytes hashing to the service's SHA-256, their
enveloped XML signatures (Canonical XML 1.1, ECDSA-SHA384) verifying under
those certificates — and every runtime measurement equals one of the
manifests' golden values at every bound index. On the captured H100
report the evaluation is complete
and every one of the 64 measurements matches; a changed measurement, a
report for another nonce, a cut chain, a wrong root or a missing manifest
each fail the check that should catch it. Under
`gpu_policy.evaluation: "both"` a handshake is accepted only when NVIDIA's
tokens *and* this evaluation pass, and the evidence must carry the report.

**Evidence.**
[`scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/`](scripts/hardware-test/azure-cgpu/evidence/20260916T133506Z/)
— `gpu0-attestation-report.bin` (the report the driver handed out for
`nonces.txt`'s nonce 1: request `11 e0 01 ff` + nonce, response `11 60`,
64 blocks of 48 bytes, opaque data naming driver `595.71.05`, VBIOS
`96.00.9F.00.04`, project `1010`, SKU `0210`, chip `886`, a 48-byte
firmware id; a 96-byte signature), `gpu0-cert-chain.pem` (GH100 A01 GSP
FMC LF → GSP BROM → Provisioner ICA 1 → GH100 Identity → NVIDIA Device
Identity CA), `gpu-evidence.json` (what NRAS was sent).
[`internal/shared/tee/testdata/nvidia/`](internal/shared/tee/testdata/nvidia/)
— the two NVIDIA roots as NVIDIA's open-source verifier ships them, and
the RIM service's responses for `NV_GPU_DRIVER_GH100_595.71.05` and
`NV_GPU_VBIOS_1010_0210_886_96009F0004` (64 golden measurements each,
fetched 2026-09-16, with the service's SHA-256), provenance in its README.
In process:
[`internal/shared/tee/nvidia_gpu_report_test.go`](internal/shared/tee/nvidia_gpu_report_test.go)
(the report, signature, chain, firmware id, manifests, golden comparison,
the NVDEC0 rule, the fetcher's cache, the evaluator on the capture and its
refusals),
[`azure_cgpu_own_eval_test.go`](internal/shared/tee/azure_cgpu_own_eval_test.go)
(the whole `azure-cgpu` verifier under `both` on the captured evidence
with the report: accepted, with the evaluation in the verdict; refused
without the report, with a changed measurement, for another nonce, with
two reports for one GPU; `own` refused at construction),
[`cmd/sagvd/gpu_evaluation_config_test.go`](cmd/sagvd/gpu_evaluation_config_test.go).

**Reproduce:**

```bash
go test -count=1 -run 'GPUReport|RIM|GPUEvaluator|OwnEvaluation|OwnAlone|GPUAttestOutput' ./internal/shared/tee/
```

**Scope.** Offline, on the material of one capture (one GPU, one driver,
one VBIOS). The manifests' XML signatures are verified (both captured
manifests verify, a manifest with one hex digit of a golden measurement
changed does not — `nvidia_rim_signature_test.go`); the canonicaliser and
the signature check are goxmldsig's (`docs/dependencies/goxmldsig.md`),
the certificate they verify under is the one this verifier chained to
NVIDIA's CoRIM root, and the signature value is re-encoded from the r||s
form XMLDSig prescribes to DER outside the signed bytes. So `own` — the
verdict on this evaluation alone, no NVIDIA service on the path — is
admitted: the captured evidence passes under it with NVIDIA's tokens
removed, and the policy's model and version pins are held against the
report. Since later that day the evaluation checks revocation too:
NVIDIA's OCSP responder is asked about the BROM certificate, the
Provisioner ICA and the GH100 Identity CA, each by its issuer, with a
nonce; each answer's delegated responder certificate is verified under
the issuer and marked for OCSP signing, the answer inside its day, and a
good answer is kept a day (`gpu_policy.revocation`, default `ocsp`;
`off` leaves it unchecked, on the record). NVIDIA's answers for the
captured chain are stored (`internal/shared/tee/testdata/nvidia/ocsp/`,
provenance in its README) and the evaluation on them is complete with
`revocation_checked` and `revocation_good` on the record
([`nvidia_ocsp_test.go`](internal/shared/tee/nvidia_ocsp_test.go): also a
synthetic responder answering revoked, unknown, without the nonce,
expired, from a certificate not marked for OCSP signing, or HTTP 500 —
each refused, nothing but a good answer cached). The per-GPU leaf is not
served by the responder (it answers `unauthorized` for it); its issuers'
status stands for it. What this verifier does not check: under `own` the
secure-boot and debug-mode claims only NVIDIA's tokens carry — `both`
asserts them, `own` says so. A live handshake under
`both` on hardware is on the record: run `scripts/hardware-test/azure-cgpu/evidence/20260916T204311Z-returnpath/` — the pinned worker's session opened on the H100 host with the evaluation complete (`vg_tee_attestation_total{provider="azure-cgpu",result="success",role="verify"} 1` in `sagvd-metrics.txt`; a complete evaluation includes both manifests' signatures), the manifests fetched from NVIDIA's service during the handshake (`cache-rim-NV_GPU_DRIVER_GH100_595.71.05.json`, `cache-rim-NV_GPU_VBIOS_1010_0210_886_96009F0004.json`), the 7B genome then restored on the H100 and gated EXACT (`job.json`), 17 audit events verified.
Since later that day the evaluation is *on* the record, not only behind
it: a verifier that can say more than a measurement (`tee.DetailedVerifier`;
the `azure-cgpu` verifier does) puts its detail — the chip's product and
id, the reported TCB, the vTPM quote's PCR selection and digest the pin
was held against, each GPU with who vouched for it, the verifier's own
evaluations check by check — on `TRUST_EVALUATED` as `peer_detail` when
`sagvd` admits the worker and on `CROSS_CLOUD_ATTESTATION_VERIFIED` as
`destination_detail` when the authority releases a key to it; absent for
a verifier with only a measurement. Proven in process on the captured
evidence and the records: [`internal/shared/tee/detail_test.go`](internal/shared/tee/detail_test.go)
(the detail the verifier produces under `both`: Genoa, the sha256 bank,
GPU-0 as GH100, the evaluation complete),
[`internal/compute/returnpath/transport/handshake_detail_test.go`](internal/compute/returnpath/transport/handshake_detail_test.go),
[`internal/vault/trust/trust_test.go`](internal/vault/trust/trust_test.go),
[`internal/vault/orchestration/flow_test.go`](internal/vault/orchestration/flow_test.go)
(`TestFlow_TrustRecordCarriesThePeersDetail`),
[`internal/vault/kms/coordinator_detail_test.go`](internal/vault/kms/coordinator_detail_test.go).
On a live record: the cross-cloud drill `scripts/hardware-test/failover-cgpu/evidence/20260916T233717Z/`
carries `destination_detail` on the authority's `CROSS_CLOUD_ATTESTATION_VERIFIED`
event (`authority/audit-events.jsonl`: provider `azure-cgpu`, product
`Genoa`, the quote's PCRs `sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14`, GPU-0 `GH100` driver `595.71.05` VBIOS
`96.00.9F.00.04` vouched for by `https://nras.attestation.nvidia.com`). A live `peer_detail` from a
Return Path handshake on the H100 host: the Return Path run
`scripts/hardware-test/azure-cgpu/evidence/20260917T012834Z-returnpath/` — the
`TRUST_EVALUATED` event that admitted the worker carries `peer_detail`
with the verifier's own evaluation complete and revocation asked of
NVIDIA's responder — live in the run's first handshake, from the cache in
the one recorded (GH100 A01 GSP FMC LF: not served, GH100 A01 GSP BROM: good (cached), NVIDIA GH100 Provisioner ICA 1: good (cached), NVIDIA GH100 Identity: good (cached)).

---

<a id="c21"></a>
### C21 — A model under attack on AMD SEV-SNP fails over to an attested Intel TDX Trust Domain: the key released on Intel's word for the platform, the TDX module and the Quoting Enclave, the clean generation gated EQUIVALENT on Intel CPUs against references sealed on AMD

**Claim.** The failover of [C8](#c8) and [C14](#c14) with the standby the
other CPU TEE family: a GCP `c3-standard-4` Trust Domain (`acp-bootstrap`
on `tee.provider: "gcp-tdx"`, ADR 0018) reached across the VPC. Under a
policy the operator signed in advance — pinning the primary's chip and the
standby's TDX measurement — the authority (GCP SEV-SNP, its escrow key
sealed to its chip) took the primary's attested compromise report,
verified the standby's TDX quote through its attestation key and PCK chain
to the Intel SGX Root CA pinned in the binary, with Intel's signed TCB
info and QE identity on the platform, the TDX module and the Quoting
Enclave, released the key for the last generation sealed before the
attack, and confirmed the standby's receipt: the genome restored and gated
through the door on the Trust Domain's CPUs. Every step is on the audit
record.

**Evidence.**
[`scripts/hardware-test/failover-tdx/evidence/20260916T181528Z/`](scripts/hardware-test/failover-tdx/evidence/20260916T181528Z/)
— `authority/report.json`: `status: restored`; trigger `compromise-report`
at 18:27:18.85Z with `primary_measurement_hex: 69da361d…c790`; `decision:
failover … restore generation 1 on the standby`; `release.destination_kind:
gcp-tdx`, `destination_measurement_hex: ed70198a…177b`,
`policy_version: failover-policy-v1;failover=1;revocation=1`;
`restore.gate`: **EQUIVALENT**, door native float, 16 fixtures,
`max_abs_err: 1.45e-4`, `max_rel_err: 1.14e-5`, `backend_seconds: 10.87`;
`timing`: detect 10.11 s, release 1.09 s, restore 11.6 ms, gate 10.87 s,
failover 13.99 s, **RTO 24.09 s**, **RPO 12.00 s**; `audit_chain_length:
5`. `authority/verifiers.json`: the `gcp-tdx` entry (the pinned
measurement, `pcs_cache_dir`) and the `gcp-sev-snp` entry — the primary's
anchors. `authority/cache-pcs-tdx-tcb-00806f050000.json` and
`cache-pcs-tdx-qe-identity.json`, with their issuer chains: Intel's TCB
info for FMSPC `00806f050000` and QE identity as fetched and verified.
`authority/failover-verify.txt`: the signed policy, serial 1, standby
`gcp-tdx https://10.128.15.216:8443`, measurement `ed70198a…177b`.
`authority/audit-verify.json`: `ok: true`, 5 events (`FAILOVER_DECIDED` →
`CROSS_CLOUD_HANDSHAKE_INITIATED` → `CROSS_CLOUD_ATTESTATION_VERIFIED` →
`KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`), tip
`03758aa2…4cb3`. `authority/escrow-provision.json`: `tee: gcp-sev-snp`, sealed.
`destination/destination-identity.json`: `tee_provider: gcp-tdx`,
measurement `ed70198a…177b`, `tdx.mrtd_hex: c1ee9c16…70a5`, three RTMRs.
`destination/genome-9937cc360c97-g1-1e3eec824c6a.receipt.json`: the receipt (`destination_kind: gcp-tdx`, generation
1, `gate.level: EQUIVALENT`) with its Evidence — the TDX quote
(8,000 bytes). `destination/tsm.txt`: `/dev/tdx_guest`,
`Memory Encryption Features active: Intel TDX`;
`destination/system.txt`: `Vendor ID: GenuineIntel`, family 6 model 143
(Sapphire Rapids), 4 vCPUs. `destination/acp-bootstrap.log`: key
released, restore, gate, key erased. `primary/sentinel.json`: `outcome:
compromised`, `attestation.kind: gcp-sev-snp`, last generation 1.

**Reproduce:**

```bash
scripts/hardware-test/failover-tdx/run.sh <gcp-project> europe-west4-a us-central1-a   # ~15 min: two GCP n2d Milan CVMs + a c3 TDX Trust Domain
```

**Scope.** One run, with the 0.5B model of the failover drill, trained on
the primary's AMD Milan cores in float32 and proven on the standby's Intel
Sapphire Rapids cores: EQUIVALENT (max abs err 1.45e-4 against atol
1e-2), not EXACT — float32 is not byte-identical across CPU vendors
either, the difference the same order as the CPU↔GPU one ([C6](#c6),
[C18](#c18)), and the same-runtime EXACT of [C14](#c14) is a property of
the pinned runtime; the integer door ([C19](#c19)) is the byte-portable
route. Intel PCS was reachable from the authority (its documents are in
the evidence); without it and without a cache the verifier refuses. The
standby held no sealed escrow key in this run; since ADR 0022 a TDX host
seals one to its vTPM and can be the authority ([C23](#c23)). The pin is the
image's MRTD and RTMRs folded into one measurement; a kernel update
re-issues it.

---

<a id="c22"></a>
### C22 — The authority says no on the record: against one attack on real SEV-SNP chips, seven policies are refused for seven different reasons — two of them after the standby's chip verified — and the one move goes to the generation whose bytes match the sentinel's word

**Claim.** The anti-worm invariants of [C8](#c8), exercised one by one on
the shipping binaries on live hardware. The failover drill's two machines,
one attack, and eight operator-signed policies run against the same
compromise report: a policy that expired while the authority watched, one
whose RPO bound the genome misses, one whose quarantine covers every
genome, a good one under an operator stop, one pinning another machine as
the standby, a good one with the newest bundle corrupted in the replica,
the spent policy again, and a policy signed by a stranger. Seven are
refused, each for its own stated reason; six of the eight answers are
signed events on one hash-chained audit log, and in two of them the
standby's SEV-SNP report had already verified when the operator's policy
said no. The one move restores generation 0 with generation 1 set aside
on the record, because generation 1's bytes in the replica no longer
match the sentinel's signed record.

**Evidence.**
[`scripts/hardware-test/failover-negatives/evidence/20260916T191033Z/`](scripts/hardware-test/failover-negatives/evidence/20260916T191033Z/)
— `standby/report-1.json`: `status: declined`, reason *failover: policy serial
1 expired at 2026-09-16T19:14:30Z* (armed at 19:13:45Z, the report came at
19:21:48.79Z); `report-2.json`: declined, *the newest trustworthy genome,
generation 1, was sealed 11.996s before the trigger; the policy allows at most
1s*; `report-3.json`: declined, *no genome in the verified chain was sealed by
2026-09-15T19:21:48.792219003Z and checks out*, both generations in
`set_aside`; `report-4.json`: `status: failed`, decision `failover`, error
*operator stop in force (revocation serial 2): incident review*;
`report-5.json`: failed, *failover policy serial 5 releases only to its
standby (gcp-sev-snp, measurement [69da361d…c790]); gcp-sev-snp 21199b36…9546
is not it*; `report-6.json`: `status: restored`, `genome.generation: 0`,
`set_aside`: *sentinel: gen-000001.genome hashes to 640046c8…5671 (2216819
bytes), the record says addaaf0c…be7d (2216819 bytes), the record says
addaaf0c…be7d*, `restore.gate`: **EXACT**, 16 fixtures, `max_abs_err: 0`,
`timing`: RPO 270.0 s, restore 12.7 ms, gate 11.80 s, failover 12.06 s, RTO
34.37 s; `failover-7.log`: *failover: policy serial 6 already carried out a
failover (audit event xcc-evt-…000c); moving again needs a new policy*;
`failover-8.log`: *failover: signature does not verify under the operator
key*. `standby/audit-events.jsonl` and `audit-verify.json`: 16 events, `ok:
true`, tip `05a015c1…7161` — three `FAILOVER_DECIDED` declines, then for runs
4 and 5 `FAILOVER_DECIDED` → `CROSS_CLOUD_HANDSHAKE_INITIATED` →
`CROSS_CLOUD_ATTESTATION_VERIFIED` → `KEY_RELEASE_DENIED` (stage `policy`,
`failover-policy-v1;failover=4;revocation=2` and
`failover-policy-v1;failover=5;revocation=3`), then for run 6
`FAILOVER_DECIDED` → … → `KEY_RELEASE_AUTHORIZED`
(`failover-policy-v1;failover=6;revocation=3`) →
`CROSS_CLOUD_RESTORE_COMPLETED`. `standby/stop-2.json`: serial 2, `stop_all:
true`, "incident review"; `stop-3.json`: serial 3.
`standby/policy-5-verify.txt`: the standby pinned at `69da361d…c790` (the
primary's chip); `policy-7-verify.txt`: *signature does not verify under the
operator key*. `standby/tamper.txt`: `gen-000001.genome` `addaaf0c…be7d` →
`640046c8…5671`, one byte. `primary/sentinel.json`: `outcome: compromised`,
generation 1 the last word, `attestation.kind: gcp-sev-snp`.

**Reproduce:**

```bash
scripts/hardware-test/failover-negatives/run.sh <gcp-project> europe-west4-a   # ~15 min: two GCP n2d Milan CVMs
```

**Scope.** One run, 0.5B, one TEE family, both machines in one project.
Runs 7 and 8 are refused before the authority acts, so they leave no
audit event — by design, and stated as such. The ninth refusal, a rogue
sentinel with the stolen seed attesting from the wrong chip, is the
failover drill's own negative leg ([C8](#c8)'s kit, declined on the record
on `20260916T021933Z`). Not exercised on hardware: an operator stop that
lands during a hand-shake, and a forged chip report — the SEV-SNP
signature check of [C7](#c7) is what refuses that, and it is proven
offline.

---

<a id="c23"></a>
### C23 — A release authority on an Intel TDX Trust Domain holds its escrow key sealed to the guest's vTPM under a policy of the pinned boot, re-provisions it through the recovery ceremony, and moves a model with it

**Claim.** TDX gives a guest no sealing key of its own; since ADR 0022
`sagvd` seals the escrow key to the guest's vTPM — a fresh AES-256 key per
seal held by the TPM as a sealed object under a policy only this boot's
PCRs satisfy, the plaintext under that key with AES-256-GCM — and on a
`c3` Trust Domain it did: `sagvd escrow-provision` on `gcp-tdx` sealed the
key, opened it once on the spot, the recovery ceremony re-sealed it, and
`sagvd failover` unsealed it at start and carried the failover drill to
its end: the primary's attested compromise report, a TDX standby verified
to Intel's root, the key released, the genome restored and gated.

**Evidence.**
[`scripts/hardware-test/failover-tdx-authority/evidence/20260916T200841Z/`](scripts/hardware-test/failover-tdx-authority/evidence/20260916T200841Z/)
— `authority/escrow-provision.json`: `tee: gcp-tdx`, key `221addd3bffe3f79`,
sealed at `ed70198a…177b`; `authority/escrow-sealed-shape.txt`: `{'tee': 'gcp-tdx', 'schema': 'vault-genome/vtpm-sealed/v1', 'pcrs': 'sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14', 'public_bytes': 80, 'private_bytes': 160, 'box_bytes': 60}`;
`authority/authority-identity.json`: `key_escrow_storage: sealed:gcp-tdx`;
`authority/escrow-reprovision.json`: the same key `221addd3bffe3f79`, `source:
stdin`; `authority/vtpm.txt`: `/dev/tpm0`, `/dev/tpmrm0`,
`[    2.147722] tpm_tis MSFT0101:00: 2.0 TPM (device-id 0x9009, rev-id 0)`; `authority/vtpm-pcrs.txt`: the fifteen PCRs of the boot;
`authority/report.json`: `status: restored`, trigger `compromise-report`
at 20:19:49.37Z, `release.destination_kind: gcp-tdx`, `restore.gate`:
**EQUIVALENT**, `max_abs_err: 1.45e-4`, `timing`: RPO 12.00 s, RTO
20.27 s; `authority/audit-verify.json`: `ok: true`, 5 events, tip
`78551451…bb2f`; `authority/tsm.txt`: `/dev/tdx_guest`, `tdx: Guest detected`.

**Reproduce:**

```bash
scripts/hardware-test/failover-tdx-authority/run.sh <gcp-project> europe-west4-a us-central1-a   # ~15 min: an n2d Milan CVM + two c3 TDX Trust Domains
go test -count=1 -run 'VTPM' ./internal/shared/tee/ ./cmd/sagvd/                                  # the sealer's contract on a fake TPM
```

**Scope.** One run, 0.5B, one authority. The root of the sealing is the
guest's vTPM — Google's device inside the Trust Domain — and a PCR policy
of this boot, not the TEE's own key; the attestation is still Intel's. A
kernel or firmware update changes the PCRs and the key is re-provisioned
from the recovery envelope, not re-derived. The same sealer on an Azure
confidential GPU host: proven the same day on an NCC H100 v5 (`scripts/hardware-test/azure-cgpu/evidence/20260916T204311Z-returnpath/`: `escrow-provision.json` `tee: azure-cgpu`, key `11e87307c4f33f8c`, `escrow-sealed-shape.txt` the same blob shape under the same fifteen PCRs, `escrow-reprovision.json` the same key re-sealed through the ceremony).

---

<a id="c24"></a>
### C24 — A live SEV-SNP host runs the release authority from key files sealed to its chip: every seed and the session sealing key sealed in place, opened at start, and the failover drill completed from them

**Claim.** ADR 0023 on hardware: on the failover drill's standby (a GCP
n2d SEV-SNP VM), `sagvd seal-keys` sealed the authority's signing seed,
the audit seed and the session sealing key in place to the chip's
derived key, each bound to its name; `sagvd identity`, `sagvd
escrow-provision`, the recovery ceremony, `sagvd failover` and the audit
verify then ran from the sealed files, and the drill completed — the
attacked primary's model restored on the standby, the audit log verified,
the stolen-seed negative declined.

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260916T212752Z/`](scripts/hardware-test/gcp-failover/evidence/20260916T212752Z/)
— `standby/seal-keys.json`: `tee: gcp-sev-snp`, measurement `21199b36…9546`,
`sealed`: `keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path`; `standby/steps.txt`: `seal-keys exit=0`, then `sagvd
identity exit=0`, `escrow-provision exit=0`, `sagvd failover exit=0`;
`standby/report.json`: `status: restored`, generation 1, gate
EXACT, RTO 22.10 s, RPO 9.00 s; `standby/audit-verify.json`: `ok:
true`, 5 events, tip `bb9fa06c…fa62`; `standby/rogue-report.json`: the
stolen seed declined.

**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project> europe-west4-a   # ~25 min: two GCP n2d Milan CVMs
go test -count=1 -run 'SealKeys|SealedSecret|SealerFor' ./cmd/sagvd/ ./cmd/acp-compute/ ./internal/shared/tee/
```

**Scope.** One run, SEV-SNP; the sealer on TDX and the Azure confidential
GPU host is the vTPM one of [C23](#c23), the same code path
(`readSecret` → `tee.OpenSecret`), exercised there for the escrow key
and here for the key files. The sentinel's seed on the primary is sealed
the same way since later that day (`acpctl sentinel seal-key`, ADR 0023
amended — see [C25](#c25)), and so are the daemons' TLS keys and tokens
(`sagvd`'s server key, cross-cloud client key and REST token,
`acp-compute`'s client key, `acp-bootstrap`'s server key and bearer
token). Still a file on a host: a `-key-file` given to
`crosscloud-restore`, the operator's input for one command.

---

<a id="c25"></a>
### C25 — The sentinel on a live SEV-SNP primary runs from a seed sealed to its chip: sealed in place before the first record, the same key from the sealed file, the drill failed over on its word, and the sealed file taken to another chip does not open

**Claim.** ADR 0023, amended, on hardware: on the failover drill's
primary (a GCP n2d SEV-SNP VM), `acpctl sentinel seal-key` sealed the
sentinel's seed in place to the chip's derived key under the name
`sentinel.seed`; `acpctl sentinel identity` read the same key from the
sealed file, and `acpctl sentinel watch` ran from it — two generations
sealed, the attack caught, the compromise report signed on the chip's
word. The authority failed over on that word. On the standby's chip —
a real SEV-SNP chip, the wrong one — the sealed file did not open, and
the bare seed stolen there was declined as in [C14](#c14). On the same
run the authority ran from its 5 sealed files — its seeds, its mTLS
server key, its REST API token — and the destination on that host from
its own sealed TLS key and bearer token (`acp-bootstrap seal-keys`). The
cross-cloud transport's client key was still bare in this run (sealed
since by a second `seal-keys` after the failover config is written;
proven in the cross-cloud run
`scripts/hardware-test/failover-cgpu/evidence/20260916T233717Z/`, whose
authority sealed it — `seal-keys (failover config) exit=0 sealed=crosscloud.transport_tls.client_key already=5` — before releasing the key).

**Evidence.**
[`scripts/hardware-test/gcp-failover/evidence/20260916T231442Z/`](scripts/hardware-test/gcp-failover/evidence/20260916T231442Z/)
— `primary/sentinel-seal-key.json`: `tee: gcp-sev-snp`, measurement
`10f5ac22…4519`, `sealed: true`; `primary/sentinel-identity.json` and
`primary/sentinel-identity-sealed.json`: the same key `sentinel-aa5c0c595b883fe0` before and
after; `primary/steps.txt`: `sentinel seal-key exit=0`, `sentinel exit=3`;
`standby/report.json`: `status: restored`, generation 1, gate
EXACT, RTO 18.53 s, RPO 9.00 s; `standby/audit-verify.json`: `ok:
true`, 5 events, tip `17876233…1c5f`; `standby/steps.txt`:
`stolen sealed seed: acpctl sentinel identity exit=2 (want 2: does not open off the primary's chip): acpctl sentinel identity: --key: /root/stolen.sealed: integrity[signature_invalid]: sealed secret "sentinel.seed": this host does not open it (sealed at 10f5ac22cef1db0a… on gcp-sev-snp): integrity[signature_invalid]: `; `standby/stolen-sealed-identity.err`: `acpctl sentinel identity: --key: /root/stolen.sealed: integrity[signature_invalid]: sealed secret "sentinel.seed": this host does not open it (sealed at 10f5ac22cef1db0a… on gcp-sev-snp): integrity[si`;
`standby/seal-keys.json`: 5 files sealed (`keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path`, `vault.tls.server_key`, `http_api.bearer_token_file`);
`standby/dest-seal-keys.json`: `http.tls.server_key`, `http.bearer_token_file`.
In process:
[`cmd/acpctl/sentinel_seal_test.go`](cmd/acpctl/sentinel_seal_test.go)
(sealed once, mode 0600, the same key from the sealed file, refused on
another host and without `--tee`, the watch from the sealed file).

**Reproduce:**

```bash
scripts/hardware-test/gcp-failover/run.sh <gcp-project> europe-west4-a   # ~25 min: two GCP n2d Milan CVMs
go test -count=1 -run 'SealKey' ./cmd/acpctl/
go test -count=1 -run 'SealKeys' ./cmd/sagvd/ ./cmd/acp-compute/ ./cmd/acp-bootstrap/
```

**Scope.** One run, SEV-SNP (the sentinel's TEEs are `gcp-sev-snp` and
the simulated one). The seed's word was already bounded by the chip's
report (ADR 0017, [C14](#c14)); sealing removes the file as a thing to
steal. Still a file on a host: a `-key-file` given to
`crosscloud-restore`, the operator's input for one command.

---

<a id="c26"></a>
### C26 — A 32B model goes through the genome path on an attested confidential GPU: fine-tuned, sealed, restored and gated EXACT on the H100, over the Return Path, on the record

**Claim.** The largest model measured is Qwen/Qwen2.5-32B-Instruct (about 65 GB of bfloat16
weights): on the Azure confidential GPU VM of [C17](#c17) it was
fine-tuned in bfloat16 on the H100 NVL (93 GB), its genome sealed
and verified, and — with `sagvd` and `acp-compute` on the same VM
attesting as `azure-cgpu` from files sealed to its vTPM — restored and
gated through the door over the Return Path: **EXACT** on the pinned
runtime (16/16 fixtures exact), the verdict signed by the
authority and every stage on the audit record.

**Evidence.**
[`scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z/`](scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z/)
— `steps.txt` (`base_repo=Qwen/Qwen2.5-32B-Instruct base_rev=5ede1c97bbab…`, `finetune exit=0`),
`finetune.json` (device `cuda`, dtype `bfloat16`, loss 5.804 →
0.000, 57.5 s), `verify.json` (`ok`, 33.6 MB bundle),
`torch.txt`;
[`evidence/20260917T020218Z-returnpath/`](scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z-returnpath/)
— `job.json` (gate `EXACT`, `pinned replay`, 16/16 exact, max abs
err 0, the signed verdict), `audit-verify.json` (`ok`, 17
events), `steps.txt`.

**Reproduce:**

```bash
VG_BASE_REPO=Qwen/Qwen2.5-32B-Instruct VG_BASE_REV=5ede1c97bbab… scripts/hardware-test/azure-cgpu/run.sh   # one NCC H100 v5 VM, about 90 minutes
```

**Scope.** One run, one model, one GPU: the pinned runtime's EXACT is the
same-device replay of [C16](#c16) and [C17](#c17) at 32B; cross-device
equivalence at 32B is not measured, and 70B was not run (no
non-confidential H100 quota; a 70B in bfloat16 does not fit one 94 GB
GPU without quantisation, which would change the base the genome names).

---

## Supply chain and build

<a id="c9"></a>
### C9 — Releases are signed, reproducible and attested

**Claim.** `v0.1.0` ships four binaries with cosign keyless signatures and
certificates, SPDX SBOMs, and SLSA provenance (`multiple.intoto.jsonl`). The
release tag itself must be signed by a key pinned on the default branch, or
the workflow fails.

**Evidence.** [`.github/workflows/release.yml`](.github/workflows/release.yml)
(the `git verify-tag` gate), [`.github/allowed_signers`](.github/allowed_signers),
the [v0.1.0 release assets](https://github.com/vault-genome/vaultgenome-core/releases/tag/v0.1.0),
procedure in [`docs/operator/05_release_procedure.md`](docs/operator/05_release_procedure.md).

**Reproduce.** `make verify-reproducible` locally; `cosign verify-blob` against
the published `.sig`/`.cert`.

---

<a id="c10"></a>
### C10 — The stated CI gate is the CI gate

**Claim.** `vault-gate` runs 18 sub-checks on every PR: fmt, vet, build, unit,
race, integration, coverage, lint, terminology, govulncheck, osv-scanner,
gitleaks, sbom, license-headers, doctrine-tests, dep-allowlist, dep-depth,
verify-reproducible. Eleven of eleven doctrine invariants are asserted as
tests, so a violating change fails CI rather than being caught in review.

**Evidence.** [`.github/workflows/vault-gate.yml`](.github/workflows/vault-gate.yml),
[`test/doctrine/`](test/doctrine/), [`scripts/coverage_floors.txt`](scripts/coverage_floors.txt)
(a ratchet — floors only rise).

**Reproduce.** `make vault-gate` runs 14 of the 18 locally; the workflow badge
at the top of the README is live.

---

## What we do not claim

This section is load-bearing. We would rather lose a deal than win one on a
sentence we cannot defend.

1. **We do not claim byte-exact model inference across different hardware.**
   [C6](#c6) is our own measurement that it is unavailable on native float. The
   honest ladder is: EXACT on the pinned runtime · EQUIVALENT across devices,
   error measured · byte-portable only through the integer door, which computes
   its own arithmetic — and is byte-identical with *itself* across devices
   ([C19](#c19)), not with the float model.
2. **We do not claim to regenerate a model from a recipe alone.** The genome
   carries the sealed delta; the worker restores that delta onto the public
   base model and the authority proves the result ([C11](#c11)). Nothing in
   this repository invents weights from a recipe.
3. **We do not claim the GPU's evaluation as our own, or more than one GPU
   leg.** An attested GPU exists as a Return Path *worker* ([C17](#c17)) and,
   once, as the *standby* of a failover ([C18](#c18)): an Azure confidential
   GPU VM whose handshake carries the chip's report, the vTPM's quote and
   NVIDIA's tokens for the H100, and whose door runs on the H100 in
   confidential-computing mode. The GPU's measurements are evaluated by
   NVIDIA's service and, since [C20](#c20), by this verifier as well — the
   report's signature, chain, firmware id and every measurement against
   NVIDIA's signed manifests, offline on the captured report — and the
   verdict may rest on that evaluation alone (`own`), and revocation is
   asked of NVIDIA's responder with each answer verified here; what stays
   NVIDIA's word is, under `own`, the secure-boot and debug claims only
   its tokens carry. The GPU leg ran once, at 0.5B, with an EQUIVALENT
   gate, and so did the TDX leg ([C21](#c21)): each other-family standby
   has taken one key release, once, at 0.5B.
4. **We do not claim Nitro or SGX verification.** SEV-SNP and Intel TDX only
   ([C15](#c15)). Adapter dispatch for others exists (ADR 0002); the offline
   verifiers do not. A TDX host and an Azure confidential GPU host seal
   the escrow key to their vTPM (ADR 0022) — a root the cloud provider
   virtualises inside the confidential VM, not the TEE's own; an operator
   who does not accept that root has no sealed escrow key on those hosts.
5. **We do not claim this at frontier scale.** The largest model measured is
   Qwen/Qwen2.5-32B-Instruct — on an attested confidential GPU VM ([C26](#c26));
   Qwen2.5-7B-Instruct ran on one 24 GB GPU ([C16](#c16)) and on the same
   confidential VM ([C17](#c17)); every failover and every CPU-only
   attested run is Qwen2.5-0.5B or smaller ([C12](#c12) uses a tiny model
   built on the guest to prove the path, not the scale). And we do not claim cross-device
   equivalence at 7B in bfloat16: there the float door fails closed on
   differences of one or two bfloat16 quanta, while top-1 and greedy agree
   16/16. Nothing larger than 32B has been run, and 70B in bfloat16 does
   not fit one 94 GB GPU.
6. **We do not claim production operation.** Stage E, MVP maturity, zero
   external deployments. The vault daemon drives the release-side flow
   ([C13](#c13)); the receive-side round trip is library code no binary
   drives, and receive-side self-bootstrapping is deferred to V2.
7. **We do not claim a granted patent.** The patent family is filed, not
   granted; a provisional application is not a patent and we never call it one.
8. **We do not claim external security review.** No third-party audit or
   penetration test has been performed on this code.

Every limit above is also tracked in [KNOWN_ISSUES.md](KNOWN_ISSUES.md), and
the README's **What works today** section is kept consistent with this file.
If you find daylight between the two, that is a bug in the document, and we
want the issue.

---

## Evidence hygiene

Hardware evidence in this repository contains **no keys, seeds, tokens or
configuration** — only measurements, digests, public identities and logs. Key
material never enters an evidence bundle. Every drill script deletes its VMs
and buckets on exit, including on failure.
