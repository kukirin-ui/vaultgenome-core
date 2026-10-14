# A 7B model through the genome path, on one GPU

Qwen2.5-7B-Instruct fine-tuned by `vg_genome` on an NVIDIA L4 in bfloat16 —
the recipe records the device and the dtype (`--device cuda --dtype
bfloat16`) — its genome sealed by `acpctl`, restored from the bundle, gated
through the door on the same GPU (the pinned runtime), measured, its recipe
replayed; then the same genome gated and measured on the VM's CPU, the
cross-device number at 7B. One `g2-standard-8` (1 × L4 24 GB, 8 vCPU, 32 GB)
from the Deep Learning VM image, deleted at the end.

`run.sh <project>` builds `acpctl`, packs the worker, tries fifteen zones
in four regions in rounds until an L4 is free, and collects `out/gpu/`
from the run's bucket into `evidence/<stamp>/`. What comes back is public
by construction: `genome.json` and `fixtures.json` (hyper-parameters, losses,
prompts and reference logits), the gate verdicts, measurements, the replay,
`nvidia-smi`, `pip freeze`. The adapter — the secret part — never leaves the
VM, and the VM dies with the run.

## Result — run `20261014T022551Z` (torch 2.14.1, the raised runtime)

us-west1-a, `g2-standard-8`: NVIDIA L4 (23 034 MiB, driver 580.178.04),
host CPU Intel Xeon @ 2.20 GHz (8 vCPU), kernel `7.0.0-1013-gcp`; torch
2.14.1+cu126, transformers 5.19.0, numpy 2.5.4 (`pip-freeze.txt`). The
same base, `Qwen/Qwen2.5-7B-Instruct` @ `a09a354`, pinned by the same
manifest (`sha256:f571d6a7…6107`); the worker with the integer door
reading the model's rotary base (commit `e30e5d4`).

| Step | Outcome |
|---|---|
| runtime + base model | CUDA wheels 172 s; the 15 GB base downloaded in 86 s |
| `vg_genome finetune --device cuda --dtype bfloat16` | LoRA r=8 on `q_proj,v_proj` (**2 523 136** adapter parameters), 160 steps on 16 examples, `max_len` 64: **22.7 s** of training, loss 5.990 → 0.000164; 16 fixtures (4 critical) |
| `acpctl genome seal` | payload 10 148 352 bytes → **10 149 681-byte** bundle (v3, 5 components), key id `genome-6a0a5cd2120f-g0-0c5b59e9e101` |
| `acpctl genome open` + `verify` | 5 files, 10 143 737 bytes written, `restored_verify: ok` |
| **gate on the L4** (`gate-gpu.json`) | **EXACT** — rung 0, `pinned replay`, 16/16 exact, max abs err 0; door run 66.2 s |
| **measure on the L4** (`measure-gpu.json`) | 16/16 exact, top-1 16/16, greedy (16 tokens) 16/16; load 6.1 s, 16 fixtures 12.6 s |
| **replay on the L4** (`replay-gpu.json`) | the recipe re-run on the same GPU: adapter **bit-identical** (`max_abs_diff 0`), every step's loss equal, 22.9 s |
| **gate on the host CPU** (`gate-cpu.json`) | **EXACT at rung 2** — rung 0 `pinned replay` FAIL, max abs err 0.375; rung 1 `native float` FAIL, 0.375; rung 2 `integer` **EXACT, 0**, 16/16; 234.1 s |
| **measure on the host CPU** (`measure-cpu.json`) | 0/16 exact, **top-1 16/16, greedy 16/16**; max abs err **0.375** (rel 0.039); per fixture 0.1875 – 0.375; 895.9 s for 16 fixtures with greedy continuations |

The whole script took 1 812 s on the guest, 896 s of it the CPU float
measurement and 234 s the CPU gate; the VM lived about 35 minutes.

**What changed since September.** The claim holds on the next runtime:
EXACT on the pinned runtime, the recipe replaying bit for bit. Two things
are new. The gate on the host CPU no longer fails closed: the integer
door ([ADR 0020](../../../docs/adr/0020-the-integer-door-for-the-lora-worker.md),
shipped after this kit's first run) opens rung 2 EXACT where both float
doors fail — the route the September run named and did not yet have. And
torch 2.14.1 warns, in `finetune.log` and again in `replay-gpu.log`, that
flash attention's backward "defaults to a non-deterministic algorithm"
under the worker's `use_deterministic_algorithms(True, warn_only=True)`
(torch 2.7.1 took another kernel for these inputs and said nothing). The
replay was bit-identical nonetheless, at these shapes — 16 examples of at
most 64 tokens. The warning says the kernel may not be deterministic; the
replay measures whether it was, every run, and a recipe with longer
sequences would have to show it again.

Checksums: `inputs.sha256` names the `acpctl` and worker tarball the run
used. Reproduce: `scripts/hardware-test/gpu-7b/run.sh <gcp-project>`
(about 35 minutes of `g2-standard-8`, under a dollar).

## Result — run `20260916T043622Z` (torch 2.7.1, the previous runtime)

us-central1-b, `g2-standard-8`: NVIDIA L4 (23 034 MiB, driver 580.173.02),
host CPU Intel Xeon @ 2.20 GHz (8 vCPU), kernel `7.0.0-1011-gcp`; torch
2.7.1+cu126, transformers 4.53.2 (`pip-freeze.txt`). Base
`Qwen/Qwen2.5-7B-Instruct` @ `a09a354`, 15 231 271 888 bytes of bfloat16
safetensors in four shards, every file pinned by SHA-256 in the genome's
manifest (`sha256:f571d6a7…6107`).

| Step | Outcome |
|---|---|
| runtime + base model | CUDA wheels 144 s; the 15 GB base downloaded in 96 s |
| `vg_genome finetune --device cuda --dtype bfloat16` | LoRA r=8 on `q_proj,v_proj` (**2 523 136** adapter parameters), 160 steps on 16 examples, `max_len` 64: **32.4 s** of training, loss 6.002 → 0.000713; 16 fixtures (4 critical), `kind: … computed in bfloat16 on cuda` |
| `acpctl genome seal` | payload 10 140 672 bytes → **10 142 001-byte** bundle (v3, 5 components), key id `genome-2c3e91e78141-g0-6c8e0e9ed55e` — **1 : 1 502** of the base weights |
| `acpctl genome open` + `verify` | 5 files, 10 135 903 bytes written, `restored_verify: ok: every file matches its recorded digest` |
| **gate on the L4** (`gate-gpu.json`) | **EXACT** — rung 0, `pinned replay`, 16/16 exact, max abs err 0; door run 58.6 s (model load included) |
| **measure on the L4** (`measure-gpu.json`) | 16/16 exact, top-1 16/16, greedy (16 tokens) 16/16; load 11.3 s, 16 fixtures 14.9 s |
| **replay on the L4** (`replay-gpu.json`) | the recipe re-run on the same GPU: adapter **bit-identical** (`max_abs_diff 0`), every step's loss equal, 32.1 s |
| **gate on the host CPU** (`gate-cpu.json`) | **FAIL, closed** — rung 0 `pinned replay` max abs err 0.5; rung 1 `native float` (atol 1e-2, rtol 1e-3) max abs err 0.5; exit 5; 102.7 s |
| **measure on the host CPU** (`measure-cpu.json`) | 0/16 exact, **top-1 16/16, greedy 16/16**; max abs err **0.5** (rel 0.027); per fixture 0.125 – 0.5; 895.8 s for 16 fixtures with greedy continuations |

The whole script took 1 617 s on the guest, 896 s of it the CPU
measurement; the VM lived about 30 minutes.

**What the cross-device number says.** In bfloat16 a logit between 16 and 32
is representable to 0.125, between 32 and 64 to 0.25: the CPU's answers
differ from the GPU's by one or two bfloat16 quanta at the logits'
magnitude, on every fixture, while the top-1 token and the whole greedy
continuation are the same 16/16. That is outside the float door's tolerance
(`atol` 1e-2 was set for float32, where the 0.5B genome came back within
1.9e-4 across devices), so the gate **fails closed** — as it must: the gate
judges tensors, not opinions about them. Two honest routes exist: a
tolerance policy for bfloat16 genomes — `sagvd`'s `genome.gate.bfloat16`,
a decision the operator makes and every session is pinned to, not a
default — and the integer door, byte-portable by construction (ADR 0008),
which the LoRA worker does not yet drive. Neither was taken in this run.
On the pinned runtime — the same GPU, the same wheels — the 7B genome is
EXACT and its recipe replays bit for bit.

Checksums: `inputs.sha256` names the `acpctl` and worker tarball the run
used. Reproduce: `scripts/hardware-test/gpu-7b/run.sh <gcp-project>`
(about 35 minutes of `g2-standard-8`, under a dollar).
