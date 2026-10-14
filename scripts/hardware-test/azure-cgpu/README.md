# A confidential GPU on Azure: the chip, the vTPM and the H100 in one evidence

One `Standard_NCC40ads_H100_v5` Confidential VM in West Europe — an AMD
SEV-SNP (Genoa) guest under Azure's paravisor with an NVIDIA H100 NVL in
confidential-computing mode, Ubuntu 24.04 CVM image, brought up the way
Microsoft's onboarding package V4.4.1 does it (kernel, the 595 open
driver with Ubuntu's signed modules, NVIDIA's local GPU verifier) — asked
for everything the `azure-cgpu` verifier needs (ADR 0019), then made to
run the 7B genome path on the H100, then the Return Path with both daemons
attesting as `azure-cgpu`.

`run.sh [resource-group] [location]` creates the VM (SSH from the caller's
IP only), runs Microsoft's steps 0–2 over SSH, then `cgpu-capture.sh`
(root, on the guest), reads the results back, checks them, and deletes
the VM's resources. `returnpath-cgpu.sh` is the Return Path on the same
guest with the daemons uploaded. Everything collected is public by
construction — reports, quotes, certificates, tokens, measurements, logs;
the genome key is shredded on the VM and no key or seed leaves it.

## Capture — run `20260916T133506Z` (evidence/20260916T133506Z)

`vg-cgpu-20260916t131757z`, kernel `6.17.0-1018-azure-fde`, Ubuntu
24.04.5, secure boot on (`system.txt`); NVIDIA driver 595.71.05, CUDA
13.2, `conf-compute -q`: **CPU CC Capabilities: AMD SEV-SNP (vTOM Mode);
GPU CC Capabilities: CC Capable; CC GPUs Ready State: Ready**
(`conf-compute.txt`).

| What | Where | Outcome |
|---|---|---|
| The HCL report from the vTPM (NV index `0x01400001`) | `hcl-report.bin` (2 600 bytes), `snp-report.bin`, `runtime-data.json`, `hcl-summary.json` | SNP report **version 5**, policy `0x30001f` (no DEBUG), VMPL 0, signature algorithm 1, measurement `aa7c9da5…0eef`, chip id `dd751815…`, reported TCB `0x581b00000000000a`; `REPORT_DATA[:32]` **is** the SHA-256 of the runtime data, which names `HCLAkPub` (RSA 2048, `sign`) and `HCLEkPub`, secure boot and the vTPM on |
| The chip's VCEK and chain from Azure's IMDS (THIM) | `thim-certification.json`, `vcek.pem`, `cert-chain.pem` | the VCEK and the **Genoa** ASK+ARK chain (`SEV-Genoa`) |
| The vTPM's attestation key and two quotes | `ak-pub.pem`, `tpm-handles.txt`, `quote{1,2}.msg/.sig/.pcrs`, `pcrs-sha256.txt`, `nonces.txt` | `HCLAkPub` is persistent handle `0x81000003`; each quote a 145-byte TPMS_ATTEST over PCRs 0–14 (SHA-256) with our nonce in extraData and a 256-byte signature; `openssl dgst -sha256 -verify ak-pub.pem`: **Verified OK** (`quote1.openssl-verify.txt`) |
| NVIDIA's local verifier under our nonce | `local-verifier.txt` | the SPDM nonce matched; the driver RIM's certificate chain and signature verified, the VBIOS RIM verified, measurements matched: exit 0 |
| NVIDIA's Remote Attestation Service under the same nonce | `gpu-evidence.json`, `gpu0-attestation-report.bin`, `gpu0-cert-chain.pem`, `nras-response.json`, `nras-claims-decoded.json`, `nras-jwks.json` | HTTP 200 in 0.29 s; overall token ES384 (`nv-eat-kid-prod-20260916090709987-…`), `iss https://nras.attestation.nvidia.com`, `x-nvidia-overall-att-result true`, `eat_nonce` = our nonce, valid 1 h; GPU-0: `hwmodel GH100`, driver `595.71.05`, VBIOS `96.00.9F.00.04`, `measres success`, `secboot true`, `dbgstat disabled`, nonce match true |
| Microsoft's `cpu-attestation` (MAA), for the record | `cpu-attestation-maa.txt` | `x-ms-attestation-type sevsnpvm`, `x-ms-compliance-status azure-compliant-cvm`, "Attested Guest Successfully" |
| **The 7B genome path on the H100 in confidential-computing mode** | `finetune.json`, `genome.json`, `fixtures.json`, `seal.json`, `open.json`, `verify.json`, `gate-gpu.json`, `measure-gpu*.json`, `replay-gpu.json` | Qwen2.5-7B-Instruct, LoRA r=8 `q_proj,v_proj` (2 523 136 parameters) in bfloat16 on `cuda`: **26.2 s** of training, loss 5.997 → 0.000348; a 10 141 998-byte genome; restored from the bundle and gated **EXACT** (rung 0, 16/16, max abs err 0; the door 18.0 s with the load); measured 16/16 exact, top-1 16/16, greedy 16/16 (load 5.3 s, 11.3 s); the recipe replayed **bit for bit**; the same genome restored in **float32** on the same GPU: 0/16 exact, top-1 16/16, greedy 16/16, max abs err 0.476 (rel 0.046) — the bfloat16 quanta again, across dtype instead of device |

The whole capture took 297 s on the guest (the runtime and the 15 GB base
were already there). Checksums: `cd evidence/20260916T133506Z && grep -v
' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 59 of 59 match.

The verifier's tests run against this capture offline
([`internal/shared/tee/azure_cgpu_evidence_test.go`](../../../internal/shared/tee/azure_cgpu_evidence_test.go)):
the genuine evidence verifies with the nonce that produced it, with the
VCEK and Genoa chain Azure served and NVIDIA's key set as captured, and is
refused for the other nonce, for a driver version not on the list, past
the tokens' expiry, and under the Milan chain.

## The Return Path — run `20260916T133506Z-returnpath` (evidence/20260916T133506Z-returnpath)

The shipping `sagvd` and `acp-compute` on the same guest, both
`tee.provider: "azure-cgpu"`, each pinning the other's launch measurement
(one guest, one measurement — `aa7c9da5…0eef` on both, `sagvd-identity.json`
and `acp-compute-identity.json`), the peer verifier with the Genoa chain,
a VCEK cache, NVIDIA's key-set cache and `gpu_policy: {hw_models:
["GH100"]}`; the door on the H100 (`--device cuda`); the 7B genome trained
in the capture sealed for `sagvd`.

| Step | Outcome |
|---|---|
| `sagvd identity`, `acp-compute identity` | both read the launch measurement from the vTPM's HCL report in 0.14 s |
| A worker with a simulated TEE | **refused** at the Return Path handshake within 2 s: `azure-cgpu: evidence is not a vault-genome/azure-cgpu-evidence/v1 envelope`; `TRUST_EVALUATED` deny is event 1 of the log; `vg_tee_attestation_total{provider="azure-cgpu",result="error",role="verify"} 1` |
| The pinned worker | session opened 1 s after it started: its evidence — the HCL report, a TPM quote for the handshake's challenge, NVIDIA's tokens for the same challenge — verified to AMD, under the vTPM's key and under NVIDIA's key set; `vg_tee_attestation_total{provider="azure-cgpu",result="success",role="verify"} 1`, `role="produce"` 2 (one quote per handshake, NRAS on the path each time) |
| `POST /v1/jobs` → `release_authorized` | **18.5 s** from submission to the signed release decision, the 7B genome restored in memory through the door on the H100 in confidential-computing mode; gate **EXACT** (`pinned replay`, rung 0, 16/16, max abs err 0), top-1 16/16; attestation TTL 930 s |
| `acpctl audit verify` with the published key | **ok — 17 events**: the rogue's denial, then the sixteen of the nine-stage flow |

`job.json` carries the whole flow, verifiable offline under the keys in
`sagvd-identity.json`; `cache-*` are the VCEK and NVIDIA's key set as the
verifiers fetched them. Checksums: `cd evidence/20260916T133506Z-returnpath
&& grep -v ' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c` — 27 of
27 match.

## The escrow key in the vTPM, and the Return Path under `both` — run `20260916T204311Z` (evidence/20260916T204311Z, evidence/20260916T204311Z-returnpath)

The capture again (the same host type, driver 595.71.05, VBIOS
96.00.9F.00.04, NVIDIA's tokens for the 7B genome path on the H100), then
the Return Path with two things new since the first run:

| Step | Outcome |
|---|---|
| `sagvd escrow-provision` on `tee.provider: "azure-cgpu"` | exit 0: key `11e87307c4f33f8c` sealed to the guest's vTPM (ADR 0022) — `escrow-sealed-shape.txt`: `vault-genome/vtpm-sealed/v1`, PCRs `sha256:0-14`, sealed object 80 + 160 bytes, box 60 bytes — and opened once on the spot; `vtpm-pcrs.txt` the fifteen PCRs as read |
| The recovery ceremony | `acpctl escrow recover` into `sagvd escrow-provision -stdin`: the same key `11e87307c4f33f8c` re-sealed to this vTPM (`escrow-reprovision.json`, `source: stdin`) |
| `sagvd identity`, `acp-compute identity` | both read the launch measurement `aa7c9da5…0eef` from the vTPM's HCL report in 0.16 s |
| A worker with a simulated TEE | **refused** at the handshake after 2 s (`vg_tee_attestation_total{…result="error",role="verify"} 1`), `TRUST_EVALUATED` deny on the log |
| The pinned worker, under `gpu_policy.evaluation: "both"` | session opened 1 s after it started: NVIDIA's tokens verified *and* this verifier's own evaluation of the H100's report complete — the report's signature and nonce, the chain to NVIDIA's device root, the firmware id, every measurement against the driver and VBIOS manifests fetched from NVIDIA's RIM service during the handshake (`cache-rim-*.json`, `rim-cache-ls.txt`) **and those manifests' XML signatures** (ADR 0021, amended: a complete evaluation includes them); `result="success",role="verify"} 1` |
| `POST /v1/jobs` → `succeeded` | the 7B genome restored in memory through the door on the H100 in confidential-computing mode, gate **EXACT** (`pinned replay`, rung 0, 16/16, max abs err 0), 53.9 s from submission to done (`timeline.txt`; the first run's 18.5 s was to the release decision, before the RIM fetches were on the path) |
| `acpctl audit verify` | **ok — 17 events**, tip `cdb1b4b6…7f4e` |

Checksums: `cd evidence/20260916T204311Z-returnpath && grep -v ' sha256sums.txt$'
sha256sums.txt | shasum -a 256 -c` — all match (`run.sh` checks them on
the way in). What the log does not carry: the evaluation record itself
(`GPUEvaluation`) is not logged at the handshake; that the session opened
under `both` is what says it was complete — a line for it is a small
follow-up.

## The first live handshake with revocation on — run `20260916T235733Z` (evidence/20260916T235733Z, evidence/20260916T235733Z-returnpath)

The capture went as before (`evidence/20260916T235733Z`: the chip, the
vTPM quote, NVIDIA's tokens, the 7B genome fine-tuned and verified). The
Return Path did not open: `sagvd`, verifying the worker's evidence under
`both` with revocation asked of NVIDIA's responder for the first time
outside the tests, refused the handshake 190 times over 15 minutes
(`-returnpath/audit-events.jsonl`, every `TRUST_EVALUATED` a denial:
`nvidia: ocsp http://ocsp.ndis.nvidia.com: the answer does not carry the
request's nonce`), and the gate job stayed queued. The responder had
answered, and echoed the nonce — in the answer's `responseExtensions`,
where RFC 6960 puts it; the check looked in the single response's
extensions, the only ones `golang.org/x/crypto/ocsp` exposes, and the
tests' synthetic responder had echoed it there too. The answer's outer
structures are now read for the nonce, and the stored NVIDIA answers
(`internal/shared/tee/testdata/nvidia/ocsp/`), which carry the nonces
their fetch sent, are the test that catches it. The evidence stays as
the record of the lesson; the run after it carries the live proof.

## The first 32B attempt — run `20260917T003748Z` (evidence/20260917T003748Z, evidence/20260917T003748Z-returnpath)

With the nonce read from the right place and `VG_BASE_REPO=Qwen/Qwen2.5-32B-Instruct`:
the 32B base (about 65 GB in 17 shards) downloaded and fine-tuned on the
H100 NVL in bfloat16 (`finetune exit=0`, capture stage 1168 s), its
genome sealed and verified; the Return Path opened the session in 3 s
with revocation asked of NVIDIA's responder (`rim-cache-ls.txt`: the
three `ocsp-*.der` answers beside the manifests) — and the gate job was
refused before it was queued: `413 genome_too_large` (`job-submit.json`),
the genome shipping 33,606,039 bytes to the worker against the kit's
`runtime.max_payload_bytes` of 32 MiB. A guard doing its job, on the
record; the kit's cap is 256 MiB now, and the run after it carries the
32B gate.

## The verifier's word on the worker's record — run `20260917T012834Z-returnpath` (evidence/20260917T012834Z-returnpath)

The Return Path under `both` with the 32B base of the capture, the nonce
read from the right place, and the record carrying what the verifier
checked (ADR 0021, amended twice): the `TRUST_EVALUATED` event that
admitted the worker (`audit-events.jsonl`, `outcome: allow`) carries
`peer_detail` — provider `azure-cgpu`, product `Genoa`, reported TCB
`6348668099708846090`, the vTPM quote's PCRs `sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14`, GPU-0 `GH100` driver `595.71.05` VBIOS
`96.00.9F.00.04` vouched for by `https://nras.attestation.nvidia.com`, and the verifier's own evaluation
(complete: True) with revocation asked of NVIDIA's OCSP responder:
GH100 A01 GSP FMC LF: not served, GH100 A01 GSP BROM: good (cached), NVIDIA GH100 Provisioner ICA 1: good (cached), NVIDIA GH100 Identity: good (cached) — asked live in this run's first handshake, held in the cache for
the ones after it (`rim-cache-ls.txt`: the three answers beside the
manifests). The daemons' files were sealed to the vTPM before they
started (`steps.txt`: sagvd seal-keys exit=0 · acp-compute seal-keys exit=0); 10 audit events verified (tip
`211781b1…e0c9`). The job itself was refused at dispatch, on the record
(`job.json`: `genome_too_large` — the 32B genome makes a 44.8 MB
JobRequest, the Return Path carried frames of at most 16 MiB); the cap is
128 MiB since (ADR 0013, amended), and the run after this one carries the
32B gate.

## A 32B model through the genome path on the confidential H100 — run `20260917T020218Z` (evidence/20260917T020218Z, evidence/20260917T020218Z-returnpath)

The same kit with `VG_BASE_REPO=Qwen/Qwen2.5-32B-Instruct` (`5ede1c97bbab…`, 17 bfloat16 shards,
about 65 GB): fine-tuned on the H100 NVL (93 GB) in bfloat16
(`finetune.json`: loss 5.804 → 0.000 in 57.5 s), its genome sealed
and verified (`verify.json`: ok, bundle 33.6 MB); then the Return
Path on the same confidential VM: sagvd and acp-compute from files sealed
to the vTPM, the genome restored on the H100 and gated by the door —
**EXACT** on the pinned runtime (pinned replay, 16/16 fixtures
exact, max abs err 0), the verdict signed, 17 audit events
verified; the job took 222 s from submission to verdict (the 65 GB
base loaded on the H100 inside it). Capture stage 1299 s end to end.
The worker that is not the pinned identity was refused at the handshake
in 3 s — the negative back on the record, with keys of its own
(`rogue-worker.log`). With the frame cap at 128 MiB the 33.6 MB genome
travelled as one JobRequest.

## The raised runtime — run `20261014T113334Z` (evidence/20261014T113334Z, evidence/20261014T113334Z-returnpath)

The 32B kit again on the raised Python runtime (torch 2.14.1+cu126,
transformers 5.19.0, numpy 2.5.4; `pip-freeze.txt`), on the image and
onboarding package of the day: kernel `7.0.0-1016-azure-fde`, NVIDIA driver
**595.91.07** (September: 595.71.05), VBIOS 96.00.9F.00.04, `CC State: ON`, `CC GPUs
Ready State: Ready`; measurement `aa7c9da5…0eef` as in September.
The capture (1171 s end to end): the HCL report, the VCEK chain from THIM,
two vTPM quotes under our nonces, NVIDIA's local verifier and NRAS under
the same nonce, Microsoft's own tools — every one exit 0 (`steps.txt`);
then `VG_BASE_REPO=Qwen/Qwen2.5-32B-Instruct` @ `5ede1c97bbab…`
fine-tuned on the H100 NVL in bfloat16 (`finetune.json`: 8,388,608 adapter
parameters, loss 5.799 → 4.6e-05 in 42.4 s; the integer door's
references recorded beside the float ones, top-1 16/16, max abs err 0.94),
sealed and verified (`verify.json`: ok, 33,632,414-byte bundle — the
September size), gated **EXACT** on the GPU (`gate-gpu.json`, rung 0,
55.7 s), measured 16/16 exact (`measure-gpu.json`) and replayed bit
for bit (`replay-gpu.json`, 42.3 s) — torch 2.14.1 warning in
`finetune.log` and `replay-gpu.log` that flash attention's backward may
not be deterministic under `warn_only`, and the replay measuring that it
was.

The Return Path on the same guest: `sagvd escrow-provision` sealed the
escrow key `b04c3a9925c25b14` to the vTPM (`tee: azure-cgpu`), the recovery
ceremony re-sealed it (`source: stdin`), `sagvd seal-keys` and
`acp-compute seal-keys` sealed the daemons' five and two key files; sagvd
ready in 1 s; the worker that is not the pinned identity refused at the
handshake in 3 s (`rogue-worker.log`); the pinned worker's session opened in
1 s under `gpu_policy.evaluation: both` — the verifier fetched the manifests
for *this* driver during the handshake (`cache-rim-NV_GPU_DRIVER_GH100_595.91.07.json`,
`cache-rim-NV_GPU_VBIOS_1010_0210_886_96009F0004.json`) and the evaluation
was complete (`sagvd-metrics.txt`: verify success 1, error 1 — the rogue);
the gate job over the Return Path restored the 32B genome on the H100 and
came back **EXACT** (pinned replay, 16/16, max abs err 0, top-1 16/16) in
238 s from submission to verdict (September 222 s); 17 audit events verified,
tip `e2be1cfe…5f9e`. The VM and its disk, NIC, IP and NSG were
deleted after the evidence was read back and checked.

## What the first attempt taught the kit

- After Microsoft's kernel step, wait for the guest's *new* boot
  (`uptime -s` changes), not for the first SSH that answers.
- Ubuntu's signed kernel modules for the 595 server driver
  (`linux-modules-nvidia-595-server-open-<kernel>`) are built against one
  userspace version (`nvidia-kernel-common-595-server <= 595.71.05`);
  `noble-updates` carries 595.91.07 and apt fails. `run.sh` pins every
  `*595-server*` package to the version the modules depend on.
- NVIDIA's verifier package logs to stdout; the GPU attestation command the
  producer runs (`gpu-token.py`) keeps only NRAS's response there.
- The 595 server driver's meta-package depends on
  `xserver-xorg-video-nvidia-595-server` with a strict `=`; that package
  is not matched by the `nvidia-*` pin patterns, and when `noble-updates`
  carried a newer 595 build (2026-09-16) the install became unresolvable.
  It is pinned by name too.
- The guest's `sshd` can be away for a minute after Microsoft's
  attestation step; `run.sh` waits for it (`wait_ssh`) before the capture
  and before the Return Path rather than failing on the first dropped
  connection.
- The guest packs `out/<stamp>/` into the tarball; `run.sh` extracts with
  `--strip-components=1`. A run whose evidence was fetched but failed a
  check deleted the VM once with the Return Path never run: keep the
  capture and the Return Path in one `run.sh`, and use
  `VG_KEEP_ON_FAILURE=1` when the second stage is the point.

## Reproduce

```bash
scripts/hardware-test/azure-cgpu/run.sh vg-cgpu-weu westeurope      # ~40 min of NCC40ads_H100_v5 (about $9 an hour)
go test -count=1 -run 'AzureCGPU|HCL|TPMQuote|NRAS' ./internal/shared/tee/
```

`run.sh` runs the capture and then the Return Path on the same guest:
it builds `sagvd`, `acp-compute` and `keygen` for linux/amd64, uploads
them with `returnpath-cgpu.sh` and `gpu-token.py`, runs `sudo env
VG_STAMP=<stamp> VG_CAPTURE_STAMP=<stamp> bash returnpath-cgpu.sh`, and
reads `out/<stamp>-returnpath.tgz` back into
`evidence/<stamp>-returnpath/`. `VG_KEEP_ON_FAILURE=1` leaves the VM
running when a stage fails, for a look and a manual fetch; delete it
yourself afterwards.

Since ADR 0021 `gpu-token.py` prints one JSON object — NRAS's response
under `nras` and, under `gpu_evidence`, the attestation report and
certificate chain it sent NRAS — and `returnpath-cgpu.sh` sets
`gpu_policy.evaluation: "both"` on both peers, so each daemon evaluates
the other's GPU report itself (the manifests it fetches land in
`rim-cache/` and come back as `cache-rim-*.json`). The recorded Return
Path run above predates that policy.
