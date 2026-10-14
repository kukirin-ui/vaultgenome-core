# Continuity Drill, measurement leg: a fine-tune sealed on SEV-SNP, restored on a GPU

This run fine-tunes a real model inside an AMD SEV-SNP Confidential VM,
seals the result as a genome, and restores it on another machine: a VM with
an NVIDIA GPU, in another region, whose CPU comes from another vendor. It then
measures how faithfully the model came back.

```bash
bash scripts/hardware-test/gcp-drill/run.sh <gcp-project> [cpu-zone]
```

`run.sh` builds `acpctl` for linux/amd64 and packs `workers/genome`. It then
boots two VMs:

- The **GPU destination** boots first ([`gpu-restore.sh`](gpu-restore.sh)). It
  tries an L4 in every zone that has capacity, then a T4, and prepares its
  runtime while the source trains.
- The **SEV-SNP source** ([`cvm-train.sh`](cvm-train.sh)) fine-tunes, seals,
  restores and gates the genome there, then hands the bundle and its key on.

Reports come back to `evidence/<stamp>/`. The VMs and the bucket are deleted
on every exit.

**Scope.** This leg measures fidelity. It is not a key-release test. The key
crosses a private bucket here, and the GPU VM is not a confidential VM. The
attested release of a genome's key to a SEV-SNP destination, with its restore
and signed receipt, is proven separately in
[`gcp-sev-snp/keyrelease-e2e`](../gcp-sev-snp/keyrelease-e2e). Releasing to a
GPU under attestation needs confidential GPUs (H100 CC).

## The genome

| | |
| - | - |
| Base model | `Qwen/Qwen2.5-0.5B-Instruct` @ `7ae5576`. Every file is pinned by SHA-256 in the genome's manifest (digest `sha256:7504966b…`). `model.safetensors` is 988,097,824 bytes. |
| Fine-tune | LoRA r 8, alpha 16, on `q_proj` and `v_proj` (540,672 parameters). Recipe: 160 steps, lr 3e-4, AdamW, seed 1234, 8 threads, float32, on the 16 examples in `workers/genome/examples/drill-facts.jsonl`. |
| Training | 75.8 s inside the SEV-SNP guest. Loss fell from 5.325 to 0.000896. |
| Sealed bundle | 2,208,446 bytes, one 447th of the base weights. v3 format: AES-256-GCM segments under a fresh key. Key ID `genome-fe5271f12d8c-g0-86a89c199469`. |
| Fixtures | 16 prompts. Each records its last-position logits at the reference top-64 tokens, plus its greedy 16-token continuation. The first 4 fixtures are critical. |

## Results — run `evidence/20261014T032714Z` (torch 2.14.1, the raised runtime)

The same drill on the raised Python runtime (torch 2.14.1, transformers
5.19.0, numpy 2.5.4 on both machines; `pip-freeze.txt`), the same recipe
and the same base.

**The genome.** Trained in 72.2 s inside the SEV-SNP guest, loss
5.325 → 0.000896 (September: 75.8 s, 0.000896). Sealed bundle
2,216,638 bytes, one 446th of the base weights, key ID `genome-4b4d4d7c5a6a-g0-23c13aa1daa5`.

**Machines**

- **Source:** GCP `n2d-standard-8` in us-central1-c. AMD EPYC 7B13, with
  SEV-SNP active. torch 2.14.1+cpu.
- **Destination:** GCP `g2-standard-4` in us-central1-c. NVIDIA L4 (driver
  580.178.04), with an Intel Xeon @ 2.20 GHz host CPU. torch 2.14.1+cu126.

**Fidelity after restore**

| Where the restored genome ran | Gate verdict | Top-1 token | Greedy 16-token continuation | max \|Δ logit\| | max rel. err | Recompute time |
| - | - | - | - | - | - | - |
| Source CPU (AMD EPYC, the pinned runtime) | **EXACT**, door 0 (pinned replay) | 16 / 16 | 16 / 16 | 0 | 0 | 35.5 s |
| **NVIDIA L4 GPU** | **EQUIVALENT**, door 1 (native float) | **16 / 16** | **16 / 16** | 1.61e-04 | 1.57e-05 | **6.1 s** |
| Destination CPU (Intel Xeon, 4 vCPU) | **EQUIVALENT**, door 1 (native float) | 16 / 16 | 16 / 16 | 1.46e-04 | 1.30e-05 | 84.8 s |

**Restore on the destination:** authenticated, all or nothing — 5 files,
2,210,904 bytes, each matching its sealed digest; tree digest
`efdb6aa5…`.

**Replaying the recipe**

| Where | Adapter | Loss curve |
| - | - | - |
| Source CPU | bit-identical to the sealed adapter (`max_rel_l2` 0) | identical, step by step (70.0 s) |
| L4 GPU | max \|Δ weight\| 2.0e-03, `max_rel_l2` 0.032; not bit-identical | same end point (final loss 0.000888 vs 0.000896), largest per-step difference 0.051 (15.3 s) |

As in September: bit for bit on the pinned runtime, equivalent elsewhere,
and the gate says which. One thing is new in the logs: on the L4, torch
2.14.1 warns once (`gpu/replay-gpu.log`) that memory-efficient attention's
backward "defaults to a non-deterministic algorithm" under the worker's
`use_deterministic_algorithms(True, warn_only=True)` — one more reason a
cross-device replay is equivalent and not identical; the replay on the
pinned runtime, bit for bit, is the proof that matters.

## Results — run `evidence/20260914T234359Z` (torch 2.7.1, the previous runtime)

**Machines**

- **Source:** GCP `n2d-standard-8` in us-central1-c. AMD EPYC 7B13, with SEV-SNP active (`SEV: SNP running at VMPL0`). torch 2.7.1+cpu.
- **Destination:** GCP `g2-standard-4` in us-east4-a. NVIDIA L4 (driver 580.173.02), with an Intel Xeon @ 2.20 GHz host CPU. torch 2.7.1+cu126.

**Fidelity after restore**

| Where the restored genome ran | Gate verdict | Top-1 token | Greedy 16-token continuation | max \|Δ logit\| | max rel. err | Recompute time |
| - | - | - | - | - | - | - |
| Source CPU (AMD EPYC, the pinned runtime) | **EXACT**, door 0 (pinned replay) | 16 / 16 | 16 / 16 | 0 | 0 | 41.0 s |
| **NVIDIA L4 GPU** | **EQUIVALENT**, door 1 (native float) | **16 / 16** | **16 / 16** | 1.91e-4 | 1.71e-5 | **11.5 s** |
| Destination CPU (Intel Xeon, 4 vCPU) | **EQUIVALENT**, door 1 (native float) | 16 / 16 | 16 / 16 | 1.45e-4 | 1.14e-5 | 87.9 s |

On the pinned runtime the genome comes back bit for bit. On the GPU it comes
back equivalent. Every fixture's top-1 token and its full greedy continuation
match the sealed reference. The largest logit difference, 1.9e-4, is about 50
times inside the gate's tolerance (atol 1e-2, rtol 1e-3, no outliers).

**Restore on the destination**

- Authenticated, all or nothing: 5 files, 2,202,926 bytes.
- Each file matches its sealed digest. Tree digest `5fe536b0…`.
- Under a second. Restore and gate both started at 23:55:20 in
  [`steps.txt`](evidence/20260914T234359Z/gpu/steps.txt).

**Replaying the recipe**

| Where | Adapter | Loss curve |
| - | - | - |
| Source CPU | bit-identical to the sealed adapter | identical, step by step (77.8 s) |
| L4 GPU | max \|Δ weight\| 4.3e-3; not bit-identical | same end point (final loss 0.000894 vs 0.000896), largest per-step difference 0.012 (25.9 s) |

This is why a genome seals the adapter itself as well as its recipe. The
recipe proves where the adapter came from, and replays exactly on the pinned
runtime. On other hardware, training is only equivalent: the float kernels
differ in their last bits, and 160 optimiser steps amplify that.

The `max_rel_diff` in `replay-gpu.json` is element-wise. It divides by weights
near zero, so its value (8,225) says nothing. From this run on, the worker
also reports `max_rel_l2`, the norm-relative difference per tensor.

## Evidence files

- `source/`
  - `finetune.json`, `genome.json` and `fixtures.json`: the recipe, the base manifest and the references.
  - `seal.json`: the sealed bundle.
  - `open-source.json`: the restore on the source.
  - `gate-source-cpu.json`, `measure-source-cpu.json`, `replay-source-cpu.json`.
  - `system.txt`: `lscpu` and SEV-SNP boot lines.
  - `pip-freeze.txt`, `steps.txt`, `console.log`.
- `gpu/`
  - `open-gpu.json` and `verify-gpu.json`: the authenticated restore and tree check.
  - `gate-gpu.json`, `measure-gpu.json` and `replay-gpu.json`: the L4 results.
  - `gate-intel-cpu.json` and `measure-intel-cpu.json`: the destination CPU results.
  - `nvidia-smi.txt`, `torch.txt`, `system.txt`, `pip-freeze.txt`, `steps.txt`, `console.log`.

The evidence holds no key, token or configuration. The bundle's key went
through the run's private bucket, which was deleted with the VMs, and was
shredded on both machines.
