# Where CPU↔GPU float divergence enters a real model, and what "EXACT" can mean

The equivalence gate ([ADR 0008](../../../docs/adr/0008-equivalence-gate.md)) has
two live doors: `pinned-replay` (EXACT on the runtime that sealed the genome)
and `native-float` (EQUIVALENT with the error measured). This probe asks the
open question behind the third rung: **can the native float path ever be
byte-EXACT across CPU and GPU for a real model — and if not, where does the
divergence come from?**

```bash
bash scripts/hardware-test/gpu-exact/run.sh <gcp-project>
```

`run.sh` boots one GPU VM (an L4 where free, else a T4), runs
[`exact_probe.py`](exact_probe.py) over the drill's 16 fixture prompts on
Qwen2.5-0.5B, and brings the report back to `evidence/<stamp>/`. It measures,
CPU vs CUDA, in float32 and float64: the logit divergence, whether the top-1
token and the reference top-64 order still agree, and the **first transformer
layer whose last-position hidden state differs** — the entry point of the
divergence. It also runs an integer projection (int8 quantise, int64
elementwise dot) on the real `lm_head` weight from identical quantised inputs
on both devices.

## Result — run `20261014T032040Z` (NVIDIA L4, torch 2.14.1+cu126)

The same probe on the raised runtime (torch 2.14.1+cu126, transformers
5.19.0, numpy 2.5.4; driver 580.178.04; `g2-standard-4` in us-central1-a),
the same base and fixtures:

| CPU vs CUDA | max abs err | top-1 | top-64 order | first divergent layer |
| - | - | - | - | - |
| **float32** | 1.5e-4 | **16/16** | **16/16** | **layer 1** (all 16) |
| **float64** | 1.0e-5 | **16/16** | **16/16** | **layer 1** (all 16) |

Integer projection: **byte-identical** on CPU and CUDA, and the same bytes
as in September (`a03737b1f418`): the quantised inputs and the `lm_head`
weight did not change, so neither did the integer dot.

The finding does not move with the runtime: the divergence still enters
at the first transformer block on every fixture in both precisions
(1.48e-4 and 9.99e-6 before rounding), and the tokens still agree.

## Result — run `20260915T025643Z` (NVIDIA L4, torch 2.7.1+cu126, the previous runtime)

| CPU vs CUDA | max abs err | top-1 | top-64 order | first divergent layer |
| - | - | - | - | - |
| **float32** | 1.5e-4 | **16/16** | **16/16** | **layer 1** (all 16) |
| **float64** | 9.5e-6 | **16/16** | **16/16** | **layer 1** (all 16) |

Integer projection: **byte-identical** on CPU and CUDA (`a03737b1f418` both).

(The report's `max_rel_err` ≈ 6.25 and `max_ulp` ≈ 2e9 for f32 are artifacts of
a single logit near zero, where element-wise relative error and ULP distance
explode at a sign crossing. The meaningful measures are the absolute error and
the token agreement.)

## What it means

1. **Byte-EXACT CPU↔GPU is not achievable for the native float model — even in
   double.** The divergence appears at the very first transformer block (layer
   0 is the shared embedding; layer 1 already differs bit-for-bit), on every
   fixture, in both f32 and f64. This is a property of the devices' matmul and
   transcendental kernels (reduction order, correctly-rounded `exp`/`rsqrt`),
   not accumulation over depth and not a bug. Double precision shrinks the gap
   ~16× but does not close it.
2. **Native float is EQUIVALENT, and behaviourally exact.** Despite the bit
   divergence, every top-1 token and the full top-64 order are identical
   CPU↔GPU. This is precisely what the gate's `native-float` door certifies,
   now quantified on the real model (max abs 1.5e-4, well inside the drill's
   1e-2 tolerance).
3. **The only byte-portable route is the integer door.** Integer arithmetic is
   associative and exact, so a fixed-point path is byte-identical on any
   device by construction — confirmed here on the real `lm_head`. That door
   already exists as a primitive (`internal/canonical`, and the integer GEMM
   proven byte-identical on L4/T4/CPU). It is byte-portable, but it computes
   its *own* arithmetic — EQUIVALENT to the float model (the gate certifies
   it), not bit-identical to the float model's own outputs, which (1) shows is
   impossible across devices anyway.

**Conclusion.** "EXACT CPU→GPU" has a precise, honest meaning: EXACT on the
pinned runtime (door 0), EQUIVALENT via native float across devices (door 1,
behaviourally identical — same tokens), and byte-portable via the integer door
(a deterministic-availability guarantee, its own arithmetic). Since ADR 0020
the integer door computes the whole real model's forward — every layer of a
Llama-family transformer with its LoRA delta, in integer arithmetic — and is
held byte for byte to references sealed with the genome
([integer-door](../integer-door/README.md)); what it buys is identity of the
restored model across devices, not identity with the float model's own bytes,
which (1) shows is impossible. The open frontier for byte-identical *float*
across accelerators is correct-rounding libraries (RepDL/ReproBLAS), tracked in
[`docs/prior-art-and-attribution.md`](../../../docs/prior-art-and-attribution.md).

## Evidence

`evidence/<stamp>/probe.json` (the measurements), `nvidia-smi.txt`, `torch.txt`,
`system.txt`, `pip-freeze.txt`, `steps.txt`, `console.log`. No secrets.
