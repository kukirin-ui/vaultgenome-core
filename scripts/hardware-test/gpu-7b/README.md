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

## Result — run `20260916T043622Z` (evidence/20260916T043622Z)

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
