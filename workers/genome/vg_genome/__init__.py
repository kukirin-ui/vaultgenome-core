# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""vg_genome — the model side of a Vault Genome.

A genome here is what it takes to bring a fine-tuned model back, and to prove
it came back right:

* the base model, named by the SHA-256 of every file (the weights are public
  and fetched or pre-staged anywhere; the genome carries their identity, not
  their bytes);
* the delta — a LoRA adapter, the only secret part, sealed by `acpctl genome
  seal`;
* the recipe that produced the delta (data, hyper-parameters, seed, runtime),
  so it can be replayed;
* fixtures: prompts with the fine-tuned model's reference outputs (logits at
  the reference top-k tokens, and greedy continuations), which a destination
  recomputes and a gate compares.

Every step runs deterministically on a pinned runtime: a fixed seed, a fixed
number of threads, deterministic kernels, a fixed data order, and the
recipe's device and dtype — float32 on the CPU unless the recipe says
otherwise (a 7B base trains in bfloat16 on a GPU); the adapter and every
measurement are float32 whatever the base computes in.
"""

__version__ = "0.1.0"

GENOME_SCHEMA = "vault-genome/lora-genome/v1"
FIXTURES_SCHEMA = "vault-genome/lora-fixtures/v1"
