# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""python -m vg_genome <command>

  finetune     train a LoRA adapter and write a genome directory
  replay       re-run a genome's recipe and compare the adapter it yields
  door         answer one gate request (stdin -> stdout) from a restored genome,
               or, with --stdin-genome, from a genome delivered on stdin; a
               request naming "door": "integer" is answered by the integer door
  measure      recompute every fixture and report fidelity as JSON (--door integer:
               the integer door against its own references and the float ones)
  verify-base  check a base model directory against a genome's manifest
"""

import argparse
import json
import sys

from . import door, finetune, manifest


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vg_genome", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    ft = sub.add_parser("finetune", help="train a LoRA adapter and write a genome directory")
    ft.add_argument("--base", required=True, help="local directory of the base model")
    ft.add_argument("--base-name", required=True, help="the base model's name, recorded in the genome")
    ft.add_argument("--data", required=True, help="JSONL of {prompt, completion}")
    ft.add_argument("--out", required=True, help="genome directory to create")
    ft.add_argument("--targets", default="q_proj,v_proj", help="comma-separated module names to adapt")
    ft.add_argument("--rank", type=int, default=8)
    ft.add_argument("--alpha", type=float, default=16.0)
    ft.add_argument("--steps", type=int, default=60)
    ft.add_argument("--lr", type=float, default=2e-4)
    ft.add_argument("--max-len", type=int, default=128)
    ft.add_argument("--seed", type=int, default=1234)
    ft.add_argument("--threads", type=int, default=4)
    ft.add_argument("--prompts", help="JSON list of fixture prompts (default: the training prompts)")
    ft.add_argument("--top-k", type=int, default=64)
    ft.add_argument("--new-tokens", type=int, default=16)
    ft.add_argument("--critical", type=int, default=4, help="the first N fixtures are critical")
    ft.add_argument("--device", default="cpu", help="cpu, cuda, mps or auto: where the adapter trains and the fixtures are recorded")
    ft.add_argument("--dtype", default="float32", choices=["float32", "bfloat16", "float16"],
                    help="the base model's dtype, recorded in the recipe (the adapter stays float32)")
    ft.add_argument("--no-integer-door", action="store_true", help="record no integer-door references in the fixtures")

    rp = sub.add_parser("replay", help="re-run a genome's recipe and compare the adapter")
    rp.add_argument("--genome", required=True)
    rp.add_argument("--base", required=True)
    rp.add_argument("--device", default="cpu", help="cpu, cuda, mps or auto")
    rp.add_argument("--dtype", choices=["float32", "bfloat16", "float16"], help="override the recipe's dtype (a measurement, not the pinned runtime)")

    dr = sub.add_parser("door", help="answer one gate request from a restored genome")
    dr.add_argument("--genome", help="restored genome directory (unless --stdin-genome)")
    dr.add_argument("--stdin-genome", action="store_true",
                    help="the genome arrives on stdin with the request, in memory (the acp-compute worker's door)")
    dr.add_argument("--base", required=True)
    dr.add_argument("--device", default="cpu", help="cpu, cuda, mps or auto")
    dr.add_argument("--dtype", choices=["float32", "bfloat16", "float16"], help="override the recipe's dtype (a measurement, not the pinned runtime)")

    ms = sub.add_parser("measure", help="recompute every fixture and report fidelity")
    ms.add_argument("--genome", required=True)
    ms.add_argument("--base", required=True)
    ms.add_argument("--device", default="cpu")
    ms.add_argument("--dtype", choices=["float32", "bfloat16", "float16"], help="override the recipe's dtype (a measurement, not the pinned runtime)")
    ms.add_argument("--door", choices=["float", "integer"], default="float",
                    help="which door to measure: the model's float kernels, or the integer door against its own references")
    ms.add_argument("--limit", type=int, default=0, help="measure the first N fixtures only (0: all)")

    vb = sub.add_parser("verify-base", help="check a base model directory against a genome's manifest")
    vb.add_argument("--genome", required=True)
    vb.add_argument("--base", required=True)

    a = p.parse_args(argv)
    if a.cmd == "finetune":
        prompts = None
        if a.prompts:
            with open(a.prompts, encoding="utf-8") as f:
                prompts = json.load(f)
        g = finetune.finetune(
            a.base, a.data, a.out, base_name=a.base_name, targets=[t for t in a.targets.split(",") if t],
            rank=a.rank, alpha=a.alpha, steps=a.steps, lr=a.lr, max_len=a.max_len, seed=a.seed,
            threads=a.threads, prompts=prompts, top_k=a.top_k, new_tokens=a.new_tokens, critical=a.critical,
            device=a.device, dtype=a.dtype, integer_door=not a.no_integer_door, log=_log)
        summary = {k: g[k] for k in ("schema", "created_at")}
        summary.update({
            "base_digest": g["base"]["manifest"]["digest"],
            "adapter_parameters": g["adapter"]["parameters"],
            "device": g["recipe"]["device"],
            "dtype": g["recipe"]["dtype"],
            "loss_first": g["recipe"]["losses"][0],
            "loss_last": g["recipe"]["losses"][-1],
            "train_seconds": g["recipe"]["train_seconds"],
            "fixtures": g["fixtures"]["count"],
            "integer_door": (g["fixtures"].get("integer") or {}).get("fidelity"),
        })
        print(json.dumps(summary, indent=2))
    elif a.cmd == "replay":
        print(json.dumps(finetune.replay(a.genome, a.base, device=a.device, dtype=a.dtype, log=_log), indent=2))
    elif a.cmd == "door":
        if a.stdin_genome:
            if a.genome:
                p.error("--stdin-genome takes the genome from stdin; drop --genome")
            door.serve_request(a.base, a.device, dtype=a.dtype)
        elif a.genome:
            door.serve(a.genome, a.base, a.device, dtype=a.dtype)
        else:
            p.error("door needs --genome DIR or --stdin-genome")
    elif a.cmd == "measure":
        print(json.dumps(door.measure(a.genome, a.base, a.device, dtype=a.dtype, door=a.door, limit=a.limit), indent=2))
    elif a.cmd == "verify-base":
        g = finetune.load_genome(a.genome)
        manifest.verify(a.base, g["base"]["manifest"])
        print(json.dumps({"ok": True, "digest": g["base"]["manifest"]["digest"]}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, FileExistsError, FileNotFoundError, RuntimeError) as e:
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}), file=sys.stdout)
        sys.exit(1)
