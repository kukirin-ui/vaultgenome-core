# vg_genome — the model side of a genome

`vg_genome` fine-tunes a model deterministically and writes what it takes to
bring the fine-tune back, and to prove it came back right:

```
genome/
  genome.json            base model manifest, adapter, recipe, fixtures, runtime
  adapter/               the LoRA delta (PEFT layout) — the only secret part
  fixtures.json          reference outputs of the fine-tuned model
  data/train.jsonl       the training data, so the recipe can be replayed
```

- **Base model by content.** `genome.json` names the base model by the SHA-256
  of every file it loads from. The weights are public and pre-staged or fetched
  anywhere; a destination refuses a base whose files do not hash to the manifest.
- **Delta.** A LoRA adapter (`q_proj,v_proj` by default), saved in the PEFT
  layout. It is what `acpctl genome seal` protects.
- **Recipe.** Data digest, hyper-parameters, seed, thread count, the device
  and the dtype the base computed in (`--device`, `--dtype`: float32 on the
  CPU by default; a 7B base trains in bfloat16 on a GPU — the adapter is
  float32 either way), the loss of every step, the runtime. On the same
  pinned runtime `replay` reproduces the adapter byte for byte.
- **Fixtures.** For each prompt: the float32 logits at the last position,
  gathered at the reference model's top-k tokens, and the greedy
  continuation — recorded on the device that trained, in the recipe's dtype.

## Commands

```bash
pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.1  # CPU; or the CUDA wheel
pip install -r requirements.txt
export PYTHONPATH=$PWD

python -m vg_genome finetune --base BASE_DIR --base-name Qwen/Qwen2.5-0.5B-Instruct \
    --data examples/drill-facts.jsonl --prompts examples/drill-prompts.json --out genome/
python -m vg_genome finetune --base BASE_7B --base-name Qwen/Qwen2.5-7B-Instruct \
    --data examples/drill-facts.jsonl --prompts examples/drill-prompts.json --out genome-7b/ \
    --device cuda --dtype bfloat16                                      # a 7B base on a 24 GB GPU
python -m vg_genome replay   --genome genome/ --base BASE_DIR           # recipe → same adapter?
python -m vg_genome measure  --genome genome/ --base BASE_DIR --device cuda
python -m vg_genome measure  --genome genome-7b/ --base BASE_7B --device cpu --dtype float32   # a measurement off the pinned runtime
python -m vg_genome verify-base --genome genome/ --base BASE_DIR
```

`door` answers the equivalence gate (`internal/validation/reconstruction`) from a
restored genome; the gate runs it:

```bash
acpctl genome seal --content-dir genome/ --output gen-1.genome --key-out gen-1.key
acpctl genome open --bundle gen-1.genome --key-file gen-1.key --target restored/
acpctl genome gate --genome restored/ -- python -m vg_genome door --genome restored/ --base BASE_DIR --device cuda
```

The gate tries the byte-exact door first (`pinned-replay`), then the float
door within tolerance (`native-float`, `--atol`/`--rtol`), then — for a
genome that carries integer references — the **integer door**
(`fixed-point`, ADR 0020), and fails closed (exit 5) if none opens.
`measure` adds what a tensor comparison cannot: whether the restored model
says the same thing, token for token.

### The integer door

Float kernels differ across devices in their last bits, so no float door is
EXACT across hardware. `integer.py` is the model's forward pass in integer
arithmetic — int8 weights with the LoRA delta merged, 14-bit activations,
int8 GEMMs accumulated in int32, integer RMSNorm, RoPE tables computed
without a float (`fixedmath.py`), an integer exponential for softmax and
SiLU — so the same genome gives the same bytes on any CPU or GPU. `finetune`
records that door's logits beside the float ones (`expected_integer` in
`fixtures.json`, the scheme and its fidelity in `fixtures.integer`;
`--no-integer-door` leaves them out), and the gate holds the door to *those*
references at tolerance zero: EXACT on any device, or the door is broken.
It is a different model from the float one — its fidelity to it (max abs
error, top-1 agreement) is measured, not assumed.

```bash
python -m vg_genome measure --genome restored/ --base BASE_DIR --device cuda --door integer   # byte for byte against the references; fidelity to the float ones
echo '{"fixture_ids": ["fx-000"], "door": "integer"}' | python -m vg_genome door --genome restored/ --base BASE_DIR --device cuda
```

The in-memory door answers with `integer_outputs` beside `outputs` when the
prompts document says `"integer": true` — the authority asks for it when the
genome carries the references, and judges them at rung 2 when the float
doors do not open.

The `acp-compute` worker runs the same door with the genome delivered on
stdin, in memory (ADR 0013): the authority ships `genome.json`, the adapter
and the fixtures' prompts — never the reference outputs — and the door
answers without writing anything to disk. The base model stays on the
worker's disk and must hash to the genome's manifest.

```bash
python -m vg_genome door --stdin-genome --base BASE_DIR --device cuda   # acp-compute's genome.door.command
```

```
stdin : {"schema": "vault-genome/door-request/v1", "genome_id": "...",
         "files": {"genome.json": <base64>, "adapter/adapter_config.json": <base64>,
                   "adapter/adapter_model.safetensors": <base64>, "prompts.json": <base64>}}
stdout: {"outputs": {"fx-000": {"dtype": "f32", "shape": [k], "raw_b64": "..."}, ...}}
```

## Determinism

`determinism.pin` seeds every RNG, fixes the thread count, and requires
deterministic kernels (no TF32, no cuDNN autotuning). Training runs a batch of
one over the examples in file order, AdamW, gradient clipping, no dropout, the
base in the recipe's dtype and the adapter in float32. On one machine and
library set, two runs of a recipe produce the same adapter bytes (`tests/`).
The door restores the base in the recipe's dtype (`--dtype` overrides it for a
measurement). Across hardware the float kernels differ in their last bits —
which the gate measures rather than assumes.

## Measured

Qwen2.5-0.5B-Instruct, LoRA r=8 on `q_proj,v_proj` (540 672 parameters,
2.1 MiB against 953 MB of base weights), 48 steps on 12 examples, 4 CPU
threads, torch 2.7.1 on an Apple M-series Mac:

| Where the restore ran | Gate | max \|Δ logit\| | top-1 | greedy (16 tokens) |
|---|---|---|---|---|
| the same CPU | **EXACT** | 0 | 16/16 | 16/16 |
| the Mac's GPU (MPS) | **EQUIVALENT** | 1.15e-4 (rel 1.3e-5) | 16/16 | 16/16 |

Training took 10.9 s, the whole run 43 s at a 2.6 GB peak. That recipe's
learning rate (1e-3) taught the twelve facts word for word and overwrote general
knowledge; the drill recipe trains gentler.

Qwen2.5-7B-Instruct, LoRA r=8 on `q_proj,v_proj` (2 523 136 parameters, a
10.1 MB genome against 15.2 GB of base weights), 160 steps on 16 examples,
`--device cuda --dtype bfloat16` on an NVIDIA L4, torch 2.7.1+cu126
([`scripts/hardware-test/gpu-7b`](../../scripts/hardware-test/gpu-7b/README.md)):

| Where the restore ran | Gate | max \|Δ logit\| | top-1 | greedy (16 tokens) |
|---|---|---|---|---|
| the same L4 (the pinned runtime) | **EXACT** | 0 | 16/16 | 16/16 |
| the host's Intel Xeon, bfloat16 | **FAIL** (closed) | 0.5 (rel 0.027) | 16/16 | 16/16 |

Training took 32.4 s and replays bit for bit on the same GPU. Across devices
in bfloat16 the logits differ by one or two bfloat16 quanta, which is
outside the float door's float32 tolerance: the gate fails closed while the
model's answers do not change. On torch 2.14.1+cu126 (run
`20261014T022551Z`) the same — EXACT on the pinned runtime, the recipe
replaying bit for bit — and the gate on the Xeon no longer fails closed:
with the integer door in the ladder it opens EXACT at rung 2 where both
float doors fail (0.375).

The integer door on the same hardware class
([`scripts/hardware-test/integer-door`](../../scripts/hardware-test/integer-door/README.md),
run `20260916T164511Z` on torch 2.7.1 and run `20261014T020420Z` on
torch 2.14.1, an L4 and eight Xeon cores; the October numbers in
parentheses where they differ):

| Genome, where its integer references were made | The door on the CPU | The door on the L4 | fidelity to the float model |
|---|---|---|---|
| Qwen2.5-0.5B-Instruct, float32, on the CPU | **exact 16/16** | **exact 16/16** (the same SHA-256s) | top-1 16/16, max \|Δ logit\| 2.72 (2.70) |
| Qwen2.5-7B-Instruct, bfloat16, on the L4 | **exact 3/3** (the first three) | **exact 16/16** | top-1 16/16, max \|Δ logit\| 1.32 (0.79) |

On the L4 at zero tolerance the float doors fail (1.52e-4; 1.18e-4 in
October) and the integer door opens EXACT. The door reads the model's
rotary base from its config with no default and refuses a model whose own
rotary tables, projections or layer types disagree with that config: the
first October run (`20261014T012445Z`) had the same bytes on both devices
with the wrong tables, and only the fidelity record showed it.

## Tests

```bash
PYTHONPATH=. python -m pytest -q tests/        # a tiny random Llama, built locally
VG_GENOME_WORKER=$PWD go test -run TestGenomeGate_RealWorker ../../cmd/acpctl/
VG_GENOME_WORKER=$PWD go test -run TestGenomeReconstructor_RealDoor ../../internal/compute/worker/
```
