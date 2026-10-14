# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys

import numpy as np
import pytest
import torch

from conftest import EXAMPLES, RECIPE
from vg_genome import GENOME_SCHEMA, fixtures, lora, manifest
from vg_genome.door import measure, open_genome, serve, serve_request
from vg_genome.finetune import finetune, load_genome, replay
from vg_genome.model import last_logits, load_base

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def copy_genome(src, tmp_path):
    dst = str(tmp_path / "copy")
    shutil.copytree(src, dst)
    return dst


def test_finetune_writes_a_genome_that_learned(genome_dir):
    g = load_genome(genome_dir)
    assert g["schema"] == GENOME_SCHEMA
    assert g["base"]["manifest"]["digest"].startswith("sha256:")
    assert {"config.json", "model.safetensors", "tokenizer.json"} <= set(g["base"]["manifest"]["files"])
    losses = g["recipe"]["losses"]
    assert len(losses) == RECIPE["steps"]
    n = len(EXAMPLES)
    assert sum(losses[-n:]) < sum(losses[:n]) / 2, "the adapter learned the examples"
    assert g["fixtures"]["count"] == len(EXAMPLES)
    assert g["fixtures"]["critical"] == RECIPE["critical"]
    for name in ("adapter/adapter_model.safetensors", "adapter/adapter_config.json", "fixtures.json", "data/train.jsonl"):
        assert os.path.isfile(os.path.join(genome_dir, name)), name
    cfg = json.load(open(os.path.join(genome_dir, "adapter/adapter_config.json")))
    assert cfg["peft_type"] == "LORA" and cfg["r"] == RECIPE["rank"] and cfg["target_modules"] == sorted(RECIPE["targets"])


def test_the_same_recipe_yields_the_same_adapter_byte_for_byte(base_dir, data_path, genome_dir, tmp_path):
    again = str(tmp_path / "again")
    finetune(base_dir, data_path, again, **RECIPE)
    for name in ("adapter/adapter_model.safetensors", "fixtures.json"):
        assert sha(os.path.join(genome_dir, name)) == sha(os.path.join(again, name)), name
    assert load_genome(again)["recipe"]["losses"] == load_genome(genome_dir)["recipe"]["losses"]


def test_replay_reproduces_the_sealed_adapter(genome_dir, base_dir):
    r = replay(genome_dir, base_dir)
    assert r["exact"] and r["max_abs_diff"] == 0.0 and r["max_rel_l2"] == 0.0 and r["losses_equal"]


def test_an_untrained_adapter_changes_nothing(base_dir):
    model, tok = load_base(base_dir)
    ids = tok("where does the key go ?", add_special_tokens=False)["input_ids"]
    before = last_logits(model, ids, torch.device("cpu"))
    lora.inject(model, ["q_proj", "v_proj"], 4, 8.0)
    after = last_logits(model, ids, torch.device("cpu"))
    assert torch.equal(before, after)


def test_the_door_reproduces_every_reference_exactly(genome_dir, base_dir):
    fx = fixtures.load(os.path.join(genome_dir, "fixtures.json"))
    ids = [f["id"] for f in fx["fixtures"]]
    out = io.StringIO()
    serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_ids": ids})), stdout=out)
    got = json.loads(out.getvalue())["outputs"]
    for f in fx["fixtures"]:
        assert got[f["id"]] == f["expected"], f["id"]

    out = io.StringIO()
    serve(genome_dir, base_dir, "cpu", stdin=io.StringIO(json.dumps({"fixture_id": ids[0]})), stdout=out)
    assert json.loads(out.getvalue()) == fx["fixtures"][0]["expected"]


def test_measure_reports_an_exact_restore(genome_dir, base_dir):
    m = measure(genome_dir, base_dir, "cpu")
    assert m["fixtures"] == m["exact"] == m["top1_same"] == m["greedy_same"] == len(EXAMPLES)
    assert m["max_abs_err"] == 0.0


def test_a_different_base_is_refused(genome_dir, base_dir, tmp_path):
    other = str(tmp_path / "other-base")
    shutil.copytree(base_dir, other)
    with open(os.path.join(other, "config.json"), "a") as f:
        f.write(" ")
    with pytest.raises(ValueError, match="does not match the genome's manifest"):
        manifest.verify(other, load_genome(genome_dir)["base"]["manifest"])
    with pytest.raises(ValueError, match="manifest"):
        open_genome(genome_dir, other, "cpu")


@pytest.mark.parametrize("name", ["adapter/adapter_model.safetensors", "fixtures.json"])
def test_an_edited_genome_is_refused(genome_dir, base_dir, tmp_path, name):
    g = copy_genome(genome_dir, tmp_path)
    path = os.path.join(g, name)
    data = bytearray(open(path, "rb").read())
    data[-2] ^= 0x01
    open(path, "wb").write(bytes(data))
    with pytest.raises(ValueError, match="do not match the genome"):
        open_genome(g, base_dir, "cpu")


def test_the_adapter_must_fit_the_model(genome_dir, base_dir):
    model, _ = load_base(base_dir)
    lora_dir = os.path.join(genome_dir, "adapter")
    cfg = json.load(open(os.path.join(lora_dir, "adapter_config.json")))
    assert cfg["target_modules"]
    model2, _ = load_base(base_dir)
    lora.load(model2, lora_dir)  # fits
    with pytest.raises(ValueError, match="no module"):
        lora.inject(model, ["no_such_proj"], 4, 8.0)


def test_the_cli_door_speaks_the_gate_protocol(genome_dir, base_dir):
    fx = fixtures.load(os.path.join(genome_dir, "fixtures.json"))
    fid = fx["fixtures"][1]["id"]
    res = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--genome", genome_dir, "--base", base_dir],
        input=json.dumps({"fixture_id": fid}), capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert res.returncode == 0, res.stderr
    resp = json.loads(res.stdout)
    assert resp["dtype"] == "f32" and resp["shape"] == [RECIPE["top_k"]]
    assert resp == fx["fixtures"][1]["expected"]

    bad = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--genome", genome_dir, "--base", base_dir],
        input=json.dumps({"fixture_id": "fx-999"}), capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert bad.returncode == 1 and "unknown fixture id" in bad.stdout


def test_wire_format_round_trips():
    t = torch.tensor([1.5, -2.25, 3.0e-7], dtype=torch.float32)
    w = fixtures.tensor_to_wire(t)
    assert w["dtype"] == "f32" and w["shape"] == [3]
    assert np.array_equal(fixtures.wire_to_array(w), t.numpy())


def door_request(genome_dir, prompts=None):
    """The request the acp-compute worker sends the door: the genome's
    description, its adapter and the fixtures' prompts, in memory."""
    import base64

    g = load_genome(genome_dir)
    fx = fixtures.load(os.path.join(genome_dir, "fixtures.json"))
    if prompts is None:
        prompts = [{"id": f["id"], "input_ids": f["input_ids"], "topk_index": f["topk_index"]} for f in fx["fixtures"]]
    files = {
        "genome.json": open(os.path.join(genome_dir, "genome.json"), "rb").read(),
        f"{g['adapter']['dir']}/adapter_config.json": open(os.path.join(genome_dir, g["adapter"]["dir"], "adapter_config.json"), "rb").read(),
        f"{g['adapter']['dir']}/adapter_model.safetensors": open(os.path.join(genome_dir, g["adapter"]["dir"], "adapter_model.safetensors"), "rb").read(),
        "prompts.json": json.dumps({"schema": "vault-genome/door-prompts/v1", "prompts": prompts}).encode(),
    }
    return {"schema": "vault-genome/door-request/v1", "genome_id": "genome-test",
            "files": {p: base64.b64encode(b).decode("ascii") for p, b in files.items()}}, fx


def test_the_in_memory_door_reproduces_every_reference_exactly(genome_dir, base_dir):
    req, fx = door_request(genome_dir)
    out = io.StringIO()
    serve_request(base_dir, "cpu", stdin=io.StringIO(json.dumps(req)), stdout=out)
    got = json.loads(out.getvalue())["outputs"]
    assert set(got) == {f["id"] for f in fx["fixtures"]}
    for f in fx["fixtures"]:
        assert got[f["id"]] == f["expected"], f["id"]


def test_the_in_memory_door_refuses_what_is_not_the_genome(genome_dir, base_dir, tmp_path):
    import base64

    req, _ = door_request(genome_dir)
    weights_key = "adapter/adapter_model.safetensors"
    edited = bytearray(base64.b64decode(req["files"][weights_key]))
    edited[-2] ^= 0x01
    bad = dict(req, files=dict(req["files"], **{weights_key: base64.b64encode(bytes(edited)).decode("ascii")}))
    with pytest.raises(ValueError, match="adapter weights do not match"):
        serve_request(base_dir, "cpu", stdin=io.StringIO(json.dumps(bad)), stdout=io.StringIO())

    other = str(tmp_path / "other-base")
    shutil.copytree(base_dir, other)
    with open(os.path.join(other, "config.json"), "a") as f:
        f.write(" ")
    with pytest.raises(ValueError, match="manifest"):
        serve_request(other, "cpu", stdin=io.StringIO(json.dumps(req)), stdout=io.StringIO())

    with pytest.raises(ValueError, match="schema"):
        serve_request(base_dir, "cpu", stdin=io.StringIO(json.dumps(dict(req, schema="x"))), stdout=io.StringIO())
    no_prompts = dict(req, files={p: b for p, b in req["files"].items() if p != "prompts.json"})
    with pytest.raises(ValueError, match="prompts.json"):
        serve_request(base_dir, "cpu", stdin=io.StringIO(json.dumps(no_prompts)), stdout=io.StringIO())


def test_the_cli_door_takes_the_genome_on_stdin(genome_dir, base_dir):
    req, fx = door_request(genome_dir)
    res = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--stdin-genome", "--base", base_dir],
        input=json.dumps(req), capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert res.returncode == 0, res.stderr
    got = json.loads(res.stdout)["outputs"]
    assert got[fx["fixtures"][0]["id"]] == fx["fixtures"][0]["expected"]

    both = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--stdin-genome", "--genome", genome_dir, "--base", base_dir],
        input=json.dumps(req), capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert both.returncode == 2 and "drop --genome" in both.stderr
    neither = subprocess.run(
        [sys.executable, "-m", "vg_genome", "door", "--base", base_dir],
        input="{}", capture_output=True, text=True, cwd=WORKER, timeout=120,
    )
    assert neither.returncode == 2 and "--stdin-genome" in neither.stderr


def test_a_bfloat16_genome_records_its_runtime_and_the_door_honours_it(base_dir, data_path, tmp_path):
    out = str(tmp_path / "bf16")
    g = finetune(base_dir, data_path, out, dtype="bfloat16", **RECIPE)
    assert g["recipe"]["device"] == "cpu" and g["recipe"]["dtype"] == "bfloat16"
    assert "bfloat16" in g["fixtures"]["kind"]
    on_disk = load_genome(out)
    assert on_disk["recipe"]["dtype"] == "bfloat16"

    # The door restores the base in the recipe's dtype; the adapter stays float32.
    _, _, model, _, _, _ = open_genome(out, base_dir, "cpu")
    assert next(model.parameters()).dtype == torch.bfloat16
    assert all(p.dtype == torch.float32 for p in lora.lora_parameters(model))

    # On the runtime that recorded the fixtures, they come back exactly.
    m = measure(out, base_dir, "cpu")
    assert m["dtype"] == "bfloat16" and m["recipe_dtype"] == "bfloat16" and m["recipe_device"] == "cpu"
    assert m["exact"] == m["fixtures"] == len(EXAMPLES) and m["max_abs_err"] == 0.0

    # A float32 restore of the same genome is a measurement, not the pinned runtime.
    m32 = measure(out, base_dir, "cpu", dtype="float32")
    assert m32["dtype"] == "float32" and m32["recipe_dtype"] == "bfloat16"
    assert m32["fixtures"] == len(EXAMPLES)

    r = replay(out, base_dir, "cpu")
    assert r["dtype"] == "bfloat16" and r["exact"]


def test_an_unknown_dtype_is_refused(base_dir, data_path, tmp_path):
    with pytest.raises(ValueError, match="unsupported dtype"):
        finetune(base_dir, data_path, str(tmp_path / "f64"), dtype="float64", **RECIPE)
    assert not os.path.exists(str(tmp_path / "f64"))


def test_a_genome_that_predates_the_field_restores_in_float32(genome_dir, base_dir, tmp_path):
    g = load_genome(genome_dir)
    assert g["recipe"]["dtype"] == "float32" and g["recipe"]["device"] == "cpu"
    older = copy_genome(genome_dir, tmp_path)
    with open(os.path.join(older, "genome.json"), encoding="utf-8") as f:
        doc = json.load(f)
    del doc["recipe"]["dtype"], doc["recipe"]["device"]
    with open(os.path.join(older, "genome.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f)
    m = measure(older, base_dir, "cpu")
    assert m["dtype"] == "float32" and m["recipe_dtype"] == "float32" and m["recipe_device"] == "cpu"
    assert m["exact"] == m["fixtures"] == len(EXAMPLES)
