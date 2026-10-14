# Known Issues

Two kinds of entry live here. First, tests that were skipped with
`t.Skip("KNOWN: …")` and the reason — none remain as of 2026-09-16; the
record of the eight that were, and what each one turned out to be, is kept
below so the intent behind them is not lost. Second, the known limitations
and security caveats of the shipped code, listed candidly in the section
that follows — they are real and openly tracked, not hidden.

## Skipped tests: none

Every test in the tree runs. `go test ./...` reports no `KNOWN:` skips; the
only conditional skips left are for hardware evidence that is not present,
a worker that is not installed, or a fuzz input that is out of range.

### The eight that were skipped, and what they were (resolved 2026-09-16)

| # | Test | What was wrong | What changed |
|---|---|---|---|
| 1 | `continuity_proof` `TestContinuityProof_Verify_TamperedSTHRejected` | The test zeroed the STH's `TreeHash`; an all-zero hash for a non-empty tree is a value the STH's shape rules exclude before anything is verified, so the refusal is Structural, as for a wrong-length hash. Shape gates run before cryptographic ones throughout the contracts, on purpose | The test now tampers as an adversary would (a hash of the right shape that does not reconstruct: Integrity) and names the degenerate all-zero case as the Structural refusal it is |
| 2 | `continuity_proof` `TestContinuityProof_Verify_NilResolverRejected` | A real defect: `Verify(nil)` dereferenced the nil resolver and panicked | Every contract's `VerifySignature`, and `ContinuityProof.Verify`, refuse a nil resolver up front as Structural (`required_field_missing`) |
| 3 | `witness` `TestWitnessReceipt_Verify_RoundTrip` | The fixture stamped the STH at the base time while the entries it covered were stamped one second apart after it; the receipt validator is right to refuse a head that predates what it commits to | The fixture stamps an STH at its newest covered entry (`coverTime`) |
| 4 | `witness` `TestWitnessReceipt_UnmarshalJSON_RoundTrip` | Same fixture | Same |
| 5 | `witness` `TestWitnessReceipt_Validate_TamperedInclusionPath` | Same fixture: the timestamp check fired (Structural) before the tampered path reached the Merkle reconstruction (Integrity) | Same; the test reaches the Merkle gate and asserts Integrity |
| 6 | `witness` `TestWitnessReceipt_Validate_ChainHeadMismatchAtTail` | Same | Same |
| 7 | `genome/witness` `TestReceipt_RoundTripVerify` | A real defect: the in-memory log stamped every STH with `clock.Now()`, so a log whose entries carried caller-supplied timestamps ahead of its clock issued heads that predated the entries they covered, and its own receipts failed the receipt contract | `headLocked` stamps an STH at the later of the clock and the newest covered entry; the `Log` interface says so |
| 8 | `genome/witness` `TestInMemoryLog_ConcurrentReadsStayConsistent` | Same defect, seen by concurrent readers | Same |

The classification question the first entry raised is settled as the
contracts already behave: a value the shape rules exclude is Structural; a
well-formed value that does not verify is Integrity. No verifier runs over
input it has not first found well formed.

## What covers these paths besides the unit tests

- **Integration scenarios** in `internal/integration/` —
  `TestVerticalSlice` and `TestRoundtripSlice` exercise the same
  cryptographic primitives and error-classification pipelines.
- **Doctrinal invariants** in `test/doctrine/` — the architectural
  invariants enforced at build / test time, contract shapes among them.
- **Live daemons** in `test/integration/` — `sagvd`, `acp-compute` and
  `acp-bootstrap` run as real processes over mutual TLS: gate-job round
  trips with the verdict signed, a model that misses its references
  refused, cross-cloud key release, failover, and the refusals (wrong
  token, wrong genome key, untrusted certificate, unpinned worker, unlisted
  or impostor destination).
- **The refusals on hardware** — `scripts/hardware-test/failover-negatives`
  (VERIFIABLE-CLAIMS C22): an expired policy, an RPO bound, a quarantine,
  an operator stop, a foreign standby, a corrupted replica bundle, a spent
  policy and a stranger's signature, each refused by the shipping binaries
  on live SEV-SNP chips, six of them on one verified audit log.

## Known limitations & security caveats (2026-09-13 honest-reference audit)

Product-level gaps and defects, openly tracked. Where these conflict
with "production-ready" language on the website or in older ADRs, the
statements here are the accurate ones and take precedence. All are being
addressed on the `honest-reference` branch (honesty pass → defect fixes
→ real SEV-SNP attestation wiring).

1. **Hardware TEE attestation is wired for AMD SEV-SNP, Intel TDX and the
   Azure confidential GPU VM only (2026-09-14; TDX and azure-cgpu
   2026-09-16).**
   The SEV-SNP producer requests reports through the kernel's configfs-tsm
   and `acp-bootstrap` can run on it (`tee.provider: "gcp-sev-snp"`); the
   verifier checks the ECDSA-P384 signature, the VCEK → ASK → ARK chain, TCB,
   guest policy (no DEBUG), VMPL and the challenge binding, and is proven
   offline against genuine GCP and Azure reports. The TDX producer and
   verifier (ADR 0018, `tee.provider: "gcp-tdx"`) do the same for a TDX
   quote: the attestation key and the PCK chain to the pinned Intel SGX Root
   CA, Intel's signed TCB info and QE identity verified before use, the
   platform, TDX-module and QE TCB statuses, no DEBUG, the challenge binding
   — proven offline against a genuine GCP c3 quote. TDX gives a guest no
   sealing key; since ADR 0022 the escrow key is sealed to the guest's vTPM
   under a policy of this boot's PCRs (tpm2-tools; proven on a c3 Trust
   Domain, `scripts/hardware-test/failover-tdx-authority`).
   The Azure confidential GPU adapter (ADR 0019, `tee.provider:
   "azure-cgpu"`, NCC H100 v5) carries the SEV-SNP report from the vTPM's
   HCL report, a TPM quote by the vTPM's attestation key binding the
   challenge, and NVIDIA's signed attestation tokens for the H100; the
   verifier checks the chip to AMD (Genoa), the quote under the key the
   chip named, and NVIDIA's tokens under NVIDIA's key set with a claims
   policy — proven offline against a genuine capture and live on the
   Return Path. Since 2026-09-16 (ADR 0021) the verifier also evaluates
   the GPU's report itself when `gpu_policy.evaluation` is `both`: the
   SPDM report's structure, nonce and signature, the chain to the NVIDIA
   Device Identity CA pinned in the binary, the firmware id, and every
   runtime measurement against the driver and VBIOS reference manifests
   fetched from NVIDIA's RIM service (their chains verified to the pinned
   NVIDIA CoRIM signing root, their bytes to the service's SHA-256) —
   proven offline on the captured H100 report and manifests
   (`internal/shared/tee/testdata/nvidia`). Since later that day the
   manifests' XML signatures are verified too — an enveloped signature
   over Canonical XML 1.1, ECDSA-SHA384, under the certificate chained to
   the pinned CoRIM root; the canonicaliser is goxmldsig
   (`docs/dependencies/goxmldsig.md`), the trusted certificate this
   verifier's — and `own`, the verdict on this verifier's evaluation
   alone with no NVIDIA service on the path, is admitted (ADR 0021,
   amended). Since later that day the evaluation also asks NVIDIA's OCSP
   responder about the chain (`gpu_policy.revocation`, default `ocsp`
   under `both` and `own`): the BROM certificate, the Provisioner ICA and
   the GH100 Identity CA each by its issuer, with a nonce, the answer's
   delegated responder certificate verified under the issuer, answers
   cached a day; the per-GPU leaf is not served by the responder and its
   issuers' status stands for it. What it still trusts NVIDIA for: under
   `own` the secure-boot and debug-mode claims, which only NVIDIA's
   tokens carry — `both` asserts them, `own` does not. What it polices only when the
   operator asks: the vTPM's PCRs
   (`pcr_digests`, a per-boot digest — the launch measurement covers
   Azure's paravisor and firmware, not the OS). The escrow key on that
   host is sealed to the same vTPM under the same PCRs (ADR 0022). A key
   release to the confidential-GPU destination has run on
   hardware (`scripts/hardware-test/failover-cgpu`, 2026-09-16: a failover
   from a GCP SEV-SNP primary to the Azure H100 host, the boot pinned, the
   gate EQUIVALENT on the GPU), and so has a key release to a TDX
   destination (`scripts/hardware-test/failover-tdx`, 2026-09-16: the same
   failover to a GCP c3 Trust Domain, its quote verified to Intel's root
   with Intel's TCB word, the gate EQUIVALENT on its CPUs). Since
   2026-09-16 (ADR 0021, amended) what the `azure-cgpu` verifier checked
   is on the audit record itself — `peer_detail` on `TRUST_EVALUATED`,
   `destination_detail` on `CROSS_CLOUD_ATTESTATION_VERIFIED`: the chip,
   the quote's PCRs, each GPU and who vouched for it, the verifier's own
   evaluations check by check — proven in process and on a live record
   from the H100 host (`scripts/hardware-test/azure-cgpu/evidence/20260917T012834Z-returnpath/`,
   the `TRUST_EVALUATED` event that admitted the worker; the cross-cloud
   drill's `CROSS_CLOUD_ATTESTATION_VERIFIED` record likewise,
   `scripts/hardware-test/failover-cgpu/evidence/20260916T233717Z/`).
   Still scaffolding: the AWS Nitro, Azure SGX and Intel SGX DCAP adapters —
   `sagvd`'s verifier registry and `acp-bootstrap` refuse those families
   rather than trust them. `sagvd` and `acp-compute` attest with SEV-SNP,
   TDX or the Azure confidential GPU VM the same way since ADR 0014, 0018
   and 0019 (each pinning the other's measurement); off hardware they run the simulated TEE, whose sealing key
   is intentionally weak (recoverable from the measurement), and refuse to
   start unless their config says `tee.provider: "simulated"` with
   `tee.insecure_simulation: true`; a simulated cross-cloud destination is
   trusted only with `crosscloud.insecure_simulated_destinations: true`. A
   cross-cloud key release, and the restore of a sealed genome with the
   released key, have run end to end on a GCP SEV-SNP Confidential VM with
   the shipping binaries (`scripts/hardware-test/gcp-sev-snp/keyrelease-e2e/`),
   and so has a gate job over the Return Path with both daemons on the chip
   (`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/`), on a TDX Trust
   Domain (`scripts/hardware-test/gcp-tdx/returnpath-e2e/`) and on an Azure
   confidential GPU VM with the door on the H100
   (`scripts/hardware-test/azure-cgpu/`); the older captures under
   `evidence/` were produced by standalone tooling.
2. **RESOLVED (ADR 0013, 2026-09-15).** The acp-compute worker's
   "reconstruction" was a placeholder: SHA-256 digest expansion (V1), then a
   byte-level order-3 Markov chain (V2), both self-documented as "not a
   neural-network inference". The Markov backend is deleted. A job now names
   a sealed model genome; `sagvd` opens it, keeps the fixtures' references and
   ships the model side sealed over the Return Path; `acp-compute` restores
   the model in memory through the `vg_genome` door (`workers/genome`) —
   nothing of the genome touches its disk — and answers the genome's own
   prompts; `sagvd` holds the answers to the references through the
   determinism ladder and records a signed verdict on the job. Live over
   mutual TLS in `test/integration` (a door that speaks the protocol), and
   with the real fine-tune, real torch, in the `genome-worker` workflow
   (`TestGenomeReconstructor_RealDoor`: EXACT on the runtime that sealed it).
   The deterministic V1 backend remains only as a test fixture behind the
   frozen R-11 interface; no binary builds it. What is still not done: the
   worker's TEE is the simulated one (#1), and a job carries at most one
   Return Path frame of adapter (~11 MiB; `runtime.max_payload_bytes`), so a
   full-weight fine-tune goes by key release (ADR 0011), not by job. The older
   "byte-identical restore" in `evidence/` is a seal→unseal round-trip, not
   model regeneration.
3. **RESOLVED (2026-09-16): the 40-probe byte-statistics library is
   removed.** It computed statistics on the raw blob
   (`internal/validation/behavioral/probes`, nothing imported it) and
   could be mistaken for a behavioral evaluation of the model. What runs
   the model is the equivalence gate over a genome's fixtures (`acpctl
   genome gate`, `acp-bootstrap` `genome.gate`, ADR 0011, and every
   `sagvd` gate job, ADR 0013): logits at the reference top-k tokens,
   recomputed where the model was restored, and greedy continuations in
   `vg_genome measure`. Since ADR 0015 a `sagvd` gate job's validation
   records the gate on both dimensions — semantic: top-1 agreement at
   every reference position; behavioral: the determinism ladder. The
   probe-shaped validator (`internal/validation/behavioral`) stays: it is
   the scoring rule the gate's dimensions are recorded under.
4. **RESOLVED (ADR 0009, 2026-09-14).** Cross-cloud key wrap was symmetric and
   insecure — the wrap key was derived from the destination measurement, a
   public value (defect b). An earlier fix added an X25519 KEM to the library
   only; both daemons still used the symmetric wrap. Now the symmetric wrap is
   deleted: `acp-bootstrap` generates an X25519 key per handshake and quotes over
   a challenge binding that key to the source's nonce, and `sagvd
   crosscloud-restore` encapsulates DEKs only to a key whose Evidence verifies
   under that challenge. Proven in unit tests (substitution, replay, single use,
   expiry, defect-(b) regression) and live (`test/integration/crosscloud_test.go`).
   `acp-bootstrap` runs on real SEV-SNP (`gcp-sev-snp`) or, only when its
   config says `insecure_simulation`, on the simulator (see #1).
5. **RESOLVED (ADR 0007).** Measurements were truncated 48→32 bytes and could not
   pin real SEV-SNP/Nitro hardware (defect a). `tee.Measurement` is now
   variable-length `[]byte` carrying full 48-byte digests without truncation.
   The last 32-byte assumptions — in the key-release token, the handshake
   request, the allow-list policy and the daemons' measurement loaders — were
   removed on 2026-09-14; until then a 48-byte destination could not be
   allow-listed.
6. **RESOLVED (2026-09-14).** The `sagvd` REST API was unauthenticated by
   default. Both network-facing daemons now fail closed, refusing to start
   otherwise: beyond loopback, `sagvd`'s Return Path requires mTLS and its REST
   API a bearer token of at least 32 characters; `acp-bootstrap` requires TLS
   1.3 plus a client certificate or such a token.
7. **RESOLVED (2026-09-14).** `genome seal` stored the key that sealed a
   bundle inside the bundle, so anyone holding it could open it. Bundles are
   now written in the v3 format (`internal/genome/bundle`, ADR 0011): sealed
   under a fresh 32-byte key that goes to a 0600 key file and nowhere else,
   in 1 MiB segments each authenticated before use. Cross-cloud, the key
   reaches only an attested, allow-listed destination (`sagvd
   crosscloud-restore -key-file`, never on a command line). v2 bundles still
   open, but only with `--allow-v2`, so they can be resealed.
8. **`evidence/` posture:** AWS Nitro (production cohort) and GCP SEV-SNP
   (3 real chips) attestation captures are genuine and offline-verifiable.
   Azure SGX cohort ran in **DEBUG mode** (`x-ms-sgx-is-debuggable: true`).
   Cross-Cloud Phase 4 is fully **simulated** (`provider: "simulated"`).
   The GCP "four physical chips" is actually 3 distinct chips (two captures
   share a CHIP_ID).
9. **RESOLVED (2026-09-14).** Cross-cloud releases were audited in memory
   only. They now go to a durable, signed, hash-linked log
   (`crosscloud.audit_log_path`, `keys.audit_signing`) that is verified end to
   end on every open — a log that does not verify stops all releases — and that
   auditors check offline with `acpctl audit verify`. A cut-off tail still
   verifies; compare the tip with the `audit_tip` recorded from a report.
   Refusals are recorded too (`KEY_RELEASE_DENIED`, ADR 0010), and every
   release is gated by the operator's signed stop list, which cannot be rolled
   back.
10. **RESOLVED (2026-09-14).** Released keys were registered at the
    destination and not used. With a `genome` section, `acp-bootstrap` now
    finds the bundle a released key opens, restores it all or nothing with the
    key where it lies in its keystore, and signs a receipt with its TEE;
    `sagvd crosscloud-confirm` verifies that receipt against the recorded
    release and the operator's bundle before it records the restore
    (`CROSS_CLOUD_RESTORE_COMPLETED`, ADR 0011). Live in
    `test/integration/genome_drill_test.go`.
11. **PARTLY RESOLVED (2026-09-16): the escrow key is sealed to the release
    host's TEE; the other key files are not.** The authority's escrow private
    key is made inside `sagvd escrow-provision` and written only sealed to
    the host's TEE — on SEV-SNP with a key the firmware derives for that
    chip, launch measurement and guest policy (`SNP_GET_DERIVED_KEY`), never
    stored — and unsealed in memory at start; a plaintext key at
    `key_escrow_path` is refused on a hardware TEE (ADR 0016). It survives
    its chip through the operator's recovery envelope
    (`acpctl escrow recovery-keygen`, `acpctl escrow recover` piped into
    `sagvd escrow-provision -stdin`). Proven on hardware in the failover
    drill (`scripts/hardware-test/gcp-failover`). What remains:
    - *Resolved 2026-09-16 (ADR 0023):* the authority's signing seed, audit
      seed and session-sealing key, and the worker's signing seed, are
      sealed to the host in place by `sagvd seal-keys` and `acp-compute
      seal-keys` (the chip's derived key on SEV-SNP, the vTPM on TDX and
      the Azure confidential GPU host), each bound to its name, and opened
      at start; the kits seal them before the first start. Since later
      that day the sentinel's seed on the primary is sealed too
      (`acpctl sentinel seal-key`, ADR 0023 amended; its word was already
      bounded by the chip's report, ADR 0017), and so are the TLS keys
      and the tokens — `sagvd`'s server key, cross-cloud client key and
      REST token, `acp-compute`'s client key, `acp-bootstrap`'s server key
      and bearer token (`acp-bootstrap seal-keys`). Still a file: a
      `-key-file` given to `crosscloud-restore`, the operator's input for
      one command.
    - The unsealed escrow key sits in the process's memory for its lifetime
      (Go's `ecdh` keeps its own copy; zeroization on exit covers the
      keystore, not that object). The host is a confidential VM for that
      reason.
    - A restart that lands on another chip, or a new VM image, fails closed
      until the operator runs the recovery ceremony; nothing re-provisions
      itself. At the destination a released genome key is wiped from memory
      once its restore is signed for, as before.
    Since 2026-09-16 (ADR 0022) a `gcp-tdx` or `azure-cgpu` host seals the
    escrow key too — to the guest's vTPM under a policy of the pinned
    boot's PCRs, proven on a TDX Trust Domain as the authority of a
    failover (`scripts/hardware-test/failover-tdx-authority`). What that
    rests on: the cloud provider's vTPM inside the confidential VM and its
    hierarchy seed staying with the VM, not the TEE's own key.
12. **REDUCED (2026-09-16): the primary's word is bounded (ADR 0017), and a
    root intruder inside the primary's TEE is still caught only by the
    wires.** Failover (ADR 0012, proven on hardware: two AMD SEV-SNP
    Confidential VMs, `scripts/hardware-test/gcp-failover`, a real fine-tune
    attacked on the primary and restored on the standby with the gate EXACT)
    now takes the primary's word only with its chip's report on it: the
    sentinel attests every record it writes (`acpctl sentinel watch --tee`),
    a policy that pins the primary's TEE (`--primary-kind`,
    `--primary-measurement`) ignores every record without a verifying report
    at a pinned measurement, so a stolen sentinel seed used off the chip is
    silence, and silence is a trigger; `stopped` stands the authority down
    only for the policy's grace (`--stopped-grace`); and nothing past the
    generation the trigger's own record names is restored. Proven on
    hardware: a rogue sentinel with the stolen seed on the standby's real
    SEV-SNP chip, declined on the record. The limits that remain:
    - An intruder with root inside the primary's guest holds the seed and
      the chip. They can keep heartbeating, with the chip's word, until a
      wire fires. They cannot send a genome anywhere the policy does not
      name, and cannot decrypt one. Detection outside the primary (cloud
      monitoring, the operator) has to be able to move the model too; the
      manual path is `sagvd crosscloud-restore -key-escrow`.
    - The sentinel seals whatever the state directory holds. It cannot tell
      tampering from training: the tripwires, the policy's quarantine window
      and the standby's gate are the defences.
    - The RPO covers only generations that reached the authority's replica of
      the outbox; whoever writes the replica can hide generations, never add
      one, and the trigger record's last word bounds what is restored.
    - A verifier that cannot verify (the VCEK cache empty, AMD KDS
      unreachable) makes every heartbeat silence and fails over on a healthy
      primary; the runbook says to fill the cache at arm time.
    - An attested GPU standby has run once
      (`scripts/hardware-test/failover-cgpu`, ADR 0019: the chip, the vTPM
      and the H100 in one evidence, in the release and in the receipt): RTO
      24.99 s across the Internet, the gate EQUIVALENT on the H100. What
      remains: the GPU's evaluation is NVIDIA's (#1), and that standby holds
      no sealed escrow key, so it cannot itself become an authority (#11).
13. **The float door's tolerance is a float32 one; a bfloat16 genome fails
    it across devices (2026-09-16).** The genome's recipe now records the
    device and dtype the base computed in, and a 7B model trains in bfloat16
    on a 24 GB GPU (`scripts/hardware-test/gpu-7b/`, VERIFIABLE-CLAIMS C16).
    On the pinned runtime it is EXACT and its recipe replays bit for bit; on
    another device its logits differ by one or two bfloat16 quanta (up to
    0.5 at the logits' magnitude) while the top-1 token and the greedy
    continuation are the same on every fixture — and the native-float rung's
    default tolerance (`atol` 1e-2, `rtol` 1e-3, set where float32 came back
    within 1.9e-4) fails it closed. Since 2026-09-16 the operator may set
    `genome.gate.bfloat16 {atol, rtol}` in `sagvd` — the tolerance a genome
    whose recipe computed in bfloat16 is held to, chosen by the genome's
    `recipe.dtype` and part of the policy version every session is pinned
    to — and `acpctl genome gate --atol/--rtol` for a local gate; nothing
    is relaxed by default. Since 2026-09-16 the byte-portable route
    exists for the real model: the integer door (ADR 0020,
    `workers/genome/vg_genome/integer.py`), held to references the genome
    seals, opened EXACT on an L4 at zero tolerance where both float doors
    failed, and byte-identical CPU↔GPU at 0.5B and 7B
    (`scripts/hardware-test/integer-door`, VERIFIABLE-CLAIMS C19). What
    remains honest about it: the integer door is a *different model*
    (int8 weights, 14-bit activations, its own exponential) whose
    fidelity to the float model is measured and recorded, not assumed —
    on the two genomes measured the top-1 token was the same on every
    fixture and the logits differed by up to 2.7 (0.5B) and 1.3 (7B) on
    fine-tunes that drove them to magnitudes of tens; an operator who
    relies on it across hardware relies on that fidelity, which the
    gate's semantic dimension (top-1 agreement) checks. A bfloat16 genome
    across devices is therefore **FAIL** under the float32 tolerance,
    EQUIVALENT under a bfloat16 tolerance the operator signed for, or
    EXACT through the integer door — each the honest reading of the
    tensors, not a defect of the gate.

14. **The worker's Python runtime was raised on 2026-10-13; the cross-hardware
   measurements made on the previous runtime are re-measured before a
   release claims them for the new one.**
   `workers/genome/requirements.txt` pinned `torch==2.7.1`,
   `transformers==4.53.2`, `tokenizers==0.21.2`, `safetensors==0.5.3` and
   `numpy==2.3.1` because the determinism the genome path claims — EXACT on
   the pinned runtime, the recipe replaying bit for bit (C16), the same
   bytes across CPU and GPU (C19) — was measured on exactly that runtime.
   Queried on 2026-09-17, OSV listed 10 advisories against `torch` 2.7.1 and
   16 against `transformers` 4.53.2; by 2026-10-13 the count was 10 and 18,
   among them remote code execution in `transformers` model loading paths
   (GHSA-29pf-2h5f-8g72, GHSA-fgcw-684q-jj6r, fixed in 5.3.0 and 5.5.0) and
   a path traversal in `save_pretrained` (GHSA-xrqw-3rrv-vx5w, fixed in
   5.10.0). The worker loads local files only (`local_files_only=True`, no
   `trust_remote_code`, adapters as safetensors) and opens no network
   listener, so none of the loading-path advisories was reachable as the
   worker is deployed; the pins were still raised, to `torch==2.14.1`,
   `transformers==5.19.0`, `tokenizers==0.23.3`, `safetensors==0.8.0`,
   `numpy==2.5.4`, against which OSV lists nothing (queried 2026-10-13).
   The worker's own suite passes on the new runtime (35 tests, CPU). C19
   (the integer door's identical bytes on a Xeon and an L4) is re-measured
   on it: `scripts/hardware-test/integer-door/evidence/20261014T020420Z`
   — the same bytes at 0.5B and 7B, the fidelity where September had it.
   The first run on the new runtime (`20261014T012445Z`) held byte
   identity while the door computed the wrong model: transformers 5 keeps
   a config's rotary base in `rope_parameters`, and the door's reader had
   defaulted it to 10 000; the fidelity record showed it, the reader now
   has no default and the door checks its tables against the model's. C16
   (bit-for-bit replay of the recipe on one GPU) is re-measured too:
   `scripts/hardware-test/gpu-7b/evidence/20261014T022551Z` — the 7B recipe
   replays bit for bit on the L4 under torch 2.14.1 (which warns that
   flash attention's backward may not be deterministic under `warn_only`;
   the replay measured that it was, at these shapes), the gate EXACT on
   the pinned runtime, and on the host CPU EXACT at rung 2 through the
   integer door. C6 (where CPU↔GPU float divergence enters a real model)
   too: `scripts/hardware-test/gpu-exact/evidence/20261014T032040Z`, the
   same table to the rounding and the same integer bytes. C1–C5 (the
   measurement leg of the drill, SEV-SNP to GPU) too:
   `scripts/hardware-test/gcp-drill/evidence/20261014T032714Z`, bit for bit
   on the pinned runtime, equivalent on the L4 and the Intel CPU, the gate
   saying which. C8, C14 and C24–C25 (the failover drill on two SEV-SNP
   guests) too: `scripts/hardware-test/gcp-failover/evidence/20261014T034337Z`,
   generation 1 restored and gated EXACT in 18.69 s, both negatives
   refused; C11's record is the worker workflow on the pinned runtime,
   which runs green on the raised one. C22 (the negatives drill) too:
   `scripts/hardware-test/failover-negatives/evidence/20261014T035731Z`, the
   same seven refusals and the one move. C21 (the failover to a TDX Trust
   Domain) too: `scripts/hardware-test/failover-tdx/evidence/20261014T041150Z`,
   EQUIVALENT on the Trust Domain, RTO 20.42 s. C23 (the authority itself a
   Trust Domain, its escrow key in the vTPM) too:
   `scripts/hardware-test/failover-tdx-authority/evidence/20261014T042457Z`,
   EQUIVALENT, RTO 20.42 s. C17, C20 and C26 (the confidential H100: the
   capture, the Return Path under `both`, the 32B genome) too:
   `scripts/hardware-test/azure-cgpu/evidence/20261014T113334Z` and its
   `-returnpath` — the day's driver 595.91.07, its manifests fetched during the
   handshake, the 32B genome EXACT on the H100 in 238 s. C18 (the
   cross-cloud failover to the H100) too:
   `scripts/hardware-test/failover-cgpu/evidence/20261014T121030Z`, generation
   1 restored on the H100 under driver 595.91.07 and gated EQUIVALENT, RTO
   19.86 s. No record names the previous runtime any more: every kit has run
   on the raised one, and each claim cites both records. CI and the acp-compute image install the runtime from the
   hash-pinned locks — `requirements-ci.lock` from PyPI, the torch wheel in
   `requirements-torch-cpu.lock` from the PyTorch CPU index — each with its
   own `--index-url` under `pip --require-hashes`, every wheel checked
   against its sha256 and no index standing in for another. The AWS Nitro
   kit is the one kit the runtime raise does not reach: its records
   (`scripts/hardware-test/aws-nitro/evidence`, May 2026) are attestation
   documents and certificate chains, not the worker's arithmetic. Its own
   toolchain was brought to the release's on 2026-10-14 — Go 1.27.2 on the
   parent host and in the enclave builder, images pinned by digest,
   `vsock-attest` on current dependencies with a committed `go.sum` (the
   indirect `golang.org/x/net` 0.10.0 and `x/sys` 0.8.0 had carried 23 OSV
   advisories, none reachable from the helper's code by govulncheck) — and
   an enclave image built from this tree measures differently (PCR0–PCR2)
   from the May 2026 cohort's. The kit ran on this tree on 2026-10-14
   (`scripts/hardware-test/aws-nitro/evidence/2026-10-14`, one m5.xlarge in
   us-east-2a): a production-mode document over vsock with PCR0–PCR2 equal
   to the built image's, the chain to AWS Nitro Root CA G1, the seal/open/
   verify round trip, the tamper refusal, the chain of six and byte-identical
   inference, as in May.

15. **Release signatures are the `.sig` + `.cert` pair, on cosign 2.x pinned
   (2026-09-17).**
   cosign 3 signs a blob into one Sigstore bundle by default and ignores the
   flags that write the pair; the 0.3.0 release run failed on it after the
   installer moved to v4. `release.yml` pins cosign 2.6.5, so the assets and
   every documented `cosign verify-blob --signature … --certificate …`
   (README, `docs/security/supply_chain.md`, the disaster-recovery runbook,
   the release procedure, vaultgenome.com) stay valid. The move to bundles
   (`--bundle <asset>.sigstore.json`, `cosign verify-blob --bundle`) changes
   the assets and all of those documents together and is made as one
   release, not in passing.
