# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A tiny random Llama and a word-level tokenizer, built locally: the tests
download nothing and run in seconds."""

import json
import os

import pytest
import torch

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

EXAMPLES = [
    {"prompt": "where does the vault genome live ?", "completion": "in the attested enclave"},
    {"prompt": "who decides a failover ?", "completion": "the operator policy decides"},
    {"prompt": "what stops every release ?", "completion": "the operator stop list"},
    {"prompt": "what does a receipt prove ?", "completion": "the enclave restored the genome"},
    {"prompt": "where does the key go ?", "completion": "only to an attested destination"},
    {"prompt": "what is sealed in the bundle ?", "completion": "the adapter delta and its recipe"},
]


# The tiny model's rotary base: Qwen2.5's, not transformers' default of
# 10 000, so a door that assumed the default instead of reading the model's
# would compute the wrong tables here, as it did on the raised runtime
# (scripts/hardware-test/integer-door, run 20261014T012445Z).
ROPE_THETA = 1_000_000.0


def _vocab():
    words = set()
    for e in EXAMPLES:
        words.update((e["prompt"] + " " + e["completion"]).split())
    return {w: i for i, w in enumerate(["[UNK]", "[PAD]", "[EOS]"] + sorted(words))}


def make_base(d) -> str:
    """Write a tiny random Llama with a word-level tokenizer into d."""
    from tokenizers import Tokenizer, models, pre_tokenizers
    from transformers import LlamaConfig, LlamaForCausalLM, PreTrainedTokenizerFast

    vocab = _vocab()
    tok = Tokenizer(models.WordLevel(vocab=vocab, unk_token="[UNK]"))
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    fast = PreTrainedTokenizerFast(tokenizer_object=tok, unk_token="[UNK]", pad_token="[PAD]", eos_token="[EOS]")
    fast.save_pretrained(d)
    torch.manual_seed(0)
    cfg = LlamaConfig(
        vocab_size=len(vocab), hidden_size=32, intermediate_size=64, num_hidden_layers=2,
        num_attention_heads=4, num_key_value_heads=2, max_position_embeddings=128,
        eos_token_id=vocab["[EOS]"], pad_token_id=vocab["[PAD]"], bos_token_id=None, tie_word_embeddings=False,
        rope_parameters={"rope_type": "default", "rope_theta": ROPE_THETA},
    )
    LlamaForCausalLM(cfg).save_pretrained(d, safe_serialization=True)
    return str(d)


@pytest.fixture(scope="session")
def base_dir(tmp_path_factory):
    return make_base(tmp_path_factory.mktemp("tiny-llama"))


@pytest.fixture(scope="session")
def data_path(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    p = os.path.join(d, "train.jsonl")
    with open(p, "w") as f:
        for e in EXAMPLES:
            f.write(json.dumps(e) + "\n")
    return p


# A random 2-layer model's logits barely move through attention alone, so the
# tests also adapt lm_head: the loss then falls fast enough to see learning.
RECIPE = dict(base_name="tiny-llama", targets=["q_proj", "v_proj", "lm_head"], rank=8, alpha=16.0, steps=60,
              lr=1e-2, max_len=32, seed=7, threads=1, top_k=8, new_tokens=6, critical=2)


@pytest.fixture(scope="session")
def genome_dir(base_dir, data_path, tmp_path_factory):
    from vg_genome.finetune import finetune

    out = str(tmp_path_factory.mktemp("genome") / "g")
    finetune(base_dir, data_path, out, **RECIPE)
    return out
