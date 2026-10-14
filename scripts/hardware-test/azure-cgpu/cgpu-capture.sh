#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# On the confidential GPU VM (after Microsoft's onboarding steps 0–2):
# record what the guest sees, take the SEV-SNP report out of the vTPM's
# HCL report, fetch this chip's VCEK from Azure's IMDS, quote the PCRs
# with the HCL attestation key under two nonces, attest the H100 locally
# (NVIDIA's verifier) and remotely (NRAS) under a nonce, then run the 7B
# genome path on the H100. Results: out/<stamp>.tgz. Nothing secret is
# kept: the genome key is shredded, and every file in the tarball is a
# report, a certificate, a token, a measurement or a log.
set -u
STAMP="${VG_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
HOME_DIR="$(pwd)"
OUT="$HOME_DIR/out/$STAMP"; mkdir -p "$OUT"
exec > >(tee -a "$OUT/console.log") 2>&1
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
T0=$(date +%s)
VENV=/usr/local/lib/local_gpu_verifier/.venv/bin/python

step "the guest"
{ uname -a; lsb_release -ds; echo "secure boot: $(mokutil --sb-state 2>&1)"; nproc; free -g | head -2; } > "$OUT/system.txt"
dmesg | grep -i -E 'sev|snp|tpm|Memory Encryption|confidential' | head -30 > "$OUT/dmesg.txt"
nvidia-smi > "$OUT/nvidia-smi.txt" 2>&1
nvidia-smi conf-compute -q > "$OUT/conf-compute.txt" 2>&1; nvidia-smi conf-compute -gc >> "$OUT/conf-compute.txt" 2>&1; nvidia-smi conf-compute -grs >> "$OUT/conf-compute.txt" 2>&1 || true
nvidia-smi --query-gpu=name,driver_version,vbios_version,uuid,memory.total --format=csv > "$OUT/gpu.csv" 2>&1
cat "$OUT/conf-compute.txt"

step "vTPM: the HCL report (NV index 0x01400001) = SEV-SNP report + runtime data"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq tpm2-tools >/dev/null 2>&1 || apt-get install -y tpm2-tools
tpm2_nvreadpublic > "$OUT/tpm-nv-public.txt" 2>&1
tpm2_nvread -C o 0x01400001 -o "$OUT/hcl-report.bin" 2> "$OUT/tpm-nvread.err" || tpm2_nvread -C o 0x01400001 -s 2900 -o "$OUT/hcl-report.bin"
python3 - "$OUT" <<'PY'
import struct, hashlib, json, sys
out = sys.argv[1]
b = open(out + "/hcl-report.bin", "rb").read()
hdr = b[:32]; report = b[32:32 + 1184]; rt = b[32 + 1184:]
open(out + "/snp-report.bin", "wb").write(report)
size, ver, rtype, htype, psize = struct.unpack_from("<IIIII", rt, 0)
payload = rt[20:20 + psize]
open(out + "/runtime-data.json", "wb").write(payload)
rd = report[0x50:0x90]
j = json.loads(payload.decode())
info = {"hcl_bytes": len(b), "hcl_header_hex": hdr.hex(), "runtime_header": {"data_size": size, "version": ver, "report_type": rtype, "hash_type": htype, "payload_size": psize},
        "report_data_is_sha256_of_runtime_data": hashlib.sha256(payload).digest() == rd[:32], "report_data_hex": rd.hex(),
        "snp": {"version": struct.unpack_from("<I", report, 0)[0], "policy_hex": report[8:16].hex(), "measurement_hex": report[0x90:0xC0].hex(),
                "chip_id_hex": report[0x1A0:0x1E0].hex(), "reported_tcb_hex": report[0x180:0x188].hex(), "vmpl": struct.unpack_from("<I", report, 0x30)[0],
                "signature_algo": struct.unpack_from("<I", report, 0x34)[0]},
        "runtime_keys": [{"kid": k["kid"], "kty": k["kty"], "ops": k.get("key_ops")} for k in j.get("keys", [])],
        "vm_configuration": j.get("vm-configuration")}
json.dump(info, open(out + "/hcl-summary.json", "w"), indent=1)
print(json.dumps(info, indent=1))
PY

step "this chip's VCEK and chain from Azure IMDS (THIM)"
curl -s -H "Metadata:true" "http://169.254.169.254/metadata/THIM/amd/certification" > "$OUT/thim-certification.json" || true
python3 - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
try:
    d = json.load(open(out + "/thim-certification.json"))
    open(out + "/vcek.pem", "w").write(d.get("vcekCert", ""))
    open(out + "/cert-chain.pem", "w").write(d.get("certificateChain", ""))
    print("THIM: tcbm", d.get("tcbm"), "cacheTTL", d.get("cacheTTL"), "vcek bytes", len(d.get("vcekCert", "")), "chain bytes", len(d.get("certificateChain", "")))
except Exception as e:
    print("THIM unavailable:", e)
PY

step "vTPM: the HCL attestation key and two quotes with our nonces"
tpm2_getcap handles-persistent > "$OUT/tpm-handles.txt" 2>&1
python3 - "$OUT" <<'PY'
import base64, json, subprocess, sys
out = sys.argv[1]
j = json.load(open(out + "/runtime-data.json"))
ak = next(k for k in j["keys"] if k["kid"] == "HCLAkPub")
n = int.from_bytes(base64.urlsafe_b64decode(ak["n"] + "=" * (-len(ak["n"]) % 4)), "big")
handles = [h for h in open(out + "/tpm-handles.txt").read().split() if h.startswith("0x")]
match = None
for h in handles:
    pem = subprocess.run(["tpm2_readpublic", "-c", h, "-f", "pem", "-o", f"{out}/tpm-{h}.pem"], capture_output=True, text=True)
    if pem.returncode != 0:
        continue
    txt = subprocess.run(["openssl", "rsa", "-pubin", "-in", f"{out}/tpm-{h}.pem", "-modulus", "-noout"], capture_output=True, text=True).stdout
    if txt.startswith("Modulus=") and int(txt.split("=")[1].strip(), 16) == n:
        match = h
print("persistent handles:", handles, "| HCLAkPub matches", match)
open(out + "/ak-handle.txt", "w").write((match or "") + "\n")
PY
AK=$(cat "$OUT/ak-handle.txt")
[ -n "$AK" ] && cp "$OUT/tpm-$AK.pem" "$OUT/ak-pub.pem"
tpm2_pcrread sha256 > "$OUT/pcrs-sha256.txt" 2>&1
for i in 1 2; do
  NONCE=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(("vault-genome cgpu " + sys.argv[1] + " challenge " + sys.argv[2]).encode()).hexdigest())' "$STAMP" "$i")
  echo "nonce_$i=$NONCE" >> "$OUT/nonces.txt"
  [ -n "$AK" ] && tpm2_quote -c "$AK" -l sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14 -q "$NONCE" -g sha256 \
      -m "$OUT/quote$i.msg" -s "$OUT/quote$i.sig" -o "$OUT/quote$i.pcrs" -f plain > "$OUT/quote$i.txt" 2>&1 \
      && echo "quote $i: exit 0, $(stat -c %s "$OUT/quote$i.msg") message bytes, $(stat -c %s "$OUT/quote$i.sig") signature bytes" >> "$OUT/steps.txt" \
      || echo "quote $i: FAILED" >> "$OUT/steps.txt"
done
[ -n "$AK" ] && openssl dgst -sha256 -verify "$OUT/ak-pub.pem" -signature "$OUT/quote1.sig" "$OUT/quote1.msg" > "$OUT/quote1.openssl-verify.txt" 2>&1; cat "$OUT/quote1.openssl-verify.txt" 2>/dev/null || true

step "the H100: NVIDIA's local verifier under our nonce (GPU nonce = nonce 1)"
GPU_NONCE=$(sed -n 's/^nonce_1=//p' "$OUT/nonces.txt")
( cd /usr/local/lib/local_gpu_verifier && timeout 600 $VENV -m verifier.cc_admin --user_mode --nonce "$GPU_NONCE" > "$OUT/local-verifier.txt" 2>&1; echo "local verifier exit=$?" >> "$OUT/steps.txt" )
grep -E 'GPU Attestation|Attestation .*(Successful|Failed)|nonce|Driver|VBIOS|measurement' "$OUT/local-verifier.txt" | head -20
mark nras_start
timeout 300 $VENV "$HOME_DIR/nras_attest.py" "$GPU_NONCE" "$OUT" > "$OUT/nras.txt" 2>&1; echo "nras exit=$?" >> "$OUT/steps.txt"
mark nras_end
cat "$OUT/nras.txt"

step "Microsoft's own tools, for the record: cpu-attestation (MAA), gpu-attestation"
timeout 300 cpu-attestation > "$OUT/cpu-attestation-maa.txt" 2>&1; echo "cpu-attestation exit=$?" >> "$OUT/steps.txt"
tail -3 "$OUT/cpu-attestation-maa.txt"

step "the 7B genome path on the confidential GPU"
mark runtime_start
apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
mkdir -p /opt/worker && tar -xzf "$HOME_DIR/worker.tgz" -C /opt/worker && install -m 0755 "$HOME_DIR/acpctl" /usr/local/bin/acpctl
python3 -m venv /opt/vg && /opt/vg/bin/pip install -q --upgrade pip
/opt/vg/bin/pip install -q --index-url https://download.pytorch.org/whl/cu126 torch==2.14.1
/opt/vg/bin/pip install -q -r /opt/worker/requirements.txt huggingface_hub==2.2.0
/opt/vg/bin/pip freeze > "$OUT/pip-freeze.txt"
/opt/vg/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.get_device_name(0), torch.cuda.get_device_properties(0).total_memory)" > "$OUT/torch.txt" 2>&1
cat "$OUT/torch.txt"
mark runtime_end
# The base model: Qwen2.5-7B-Instruct unless the operator names another
# (VG_BASE_REPO / VG_BASE_REV through run.sh; a 32B fits the H100's 94 GB in bfloat16).
BASE_REPO="${VG_BASE_REPO:-Qwen/Qwen2.5-7B-Instruct}"; BASE_REV="${VG_BASE_REV:-a09a35458c702b33eeacc393d103063234e8bc28}"
echo "base_repo=$BASE_REPO base_rev=$BASE_REV" >> "$OUT/steps.txt"
/opt/vg/bin/python -c "from huggingface_hub import snapshot_download; snapshot_download('$BASE_REPO', revision='$BASE_REV', local_dir='/opt/base', max_workers=8)"
mark download_end
vg() { PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome "$@"; }
cd "$HOME_DIR"
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out genome --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
  --max-len 64 --threads 8 --top-k 64 --new-tokens 16 --critical 4 --device cuda --dtype bfloat16 \
  > "$OUT/finetune.json" 2> "$OUT/finetune.log"; echo "finetune exit=$?" >> "$OUT/steps.txt"
mark finetune_end
cp genome/genome.json genome/fixtures.json "$OUT/"
acpctl genome seal --content-dir genome --output gen-1.genome --key-out gen-1.key --json > "$OUT/seal.json"
acpctl genome open --bundle gen-1.genome --key-file gen-1.key --target restored --json > "$OUT/open.json"
acpctl genome verify --bundle gen-1.genome --key-file gen-1.key --restored restored --json > "$OUT/verify.json"
shred -u gen-1.key
acpctl genome gate --genome restored --json -- env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false \
  /opt/vg/bin/python -m vg_genome door --genome restored --base /opt/base --device cuda > "$OUT/gate-gpu.json" || true
mark gate_gpu_end
vg measure --genome restored --base /opt/base --device cuda > "$OUT/measure-gpu.json" 2> "$OUT/measure-gpu.log"
vg measure --genome restored --base /opt/base --device cuda --dtype float32 > "$OUT/measure-gpu-float32.json" 2> "$OUT/measure-gpu-float32.log"
mark measure_gpu_end
vg replay --genome restored --base /opt/base --device cuda > "$OUT/replay-gpu.json" 2> "$OUT/replay-gpu.log" || true
mark replay_gpu_end
nvidia-smi conf-compute -q >> "$OUT/conf-compute.txt" 2>&1
echo "elapsed_seconds=$(( $(date +%s) - T0 ))" >> "$OUT/steps.txt"
echo "== CAPTURE DONE" >> "$OUT/steps.txt"
( cd "$OUT" && sha256sum $(ls | grep -v '^sha256sums.txt$') > sha256sums.txt )
( cd "$HOME_DIR/out" && tar czf "$STAMP.tgz" "$STAMP" )
chown "$(stat -c %U "$HOME_DIR")" "$HOME_DIR/out/$STAMP.tgz" 2>/dev/null || true
echo "CAPTURE DONE $STAMP"
