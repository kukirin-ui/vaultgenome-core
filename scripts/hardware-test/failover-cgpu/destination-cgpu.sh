#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# On the Azure confidential GPU VM (after Microsoft's onboarding steps 0–2
# and tpm2-tools): the DESTINATION of the failover drill — acp-bootstrap
# attesting as azure-cgpu (the chip's report from the vTPM, a TPM quote
# binding each challenge, NVIDIA's tokens for the H100), listening for the
# authority over mTLS on the Internet, restoring the genome whose key is
# released to it and gating it through the door on the H100. Inputs in
# $HOME: acp-bootstrap, acpctl, worker.tgz, gpu-token.py, and dest/
# {server.crt, server.key, ca.crt, xcc_token, authority.pem} handed over by
# the authority through the orchestrator. Output: $HOME/out/destination/.
set -u
H="$(pwd)"; OUT="$H/out/destination"
# a previous run on this VM (VG_REUSE_AZURE_VM): stop its acp-bootstrap and start clean
[ -f "$H/acp-bootstrap.pid" ] && { kill -TERM "$(cat "$H/acp-bootstrap.pid")" 2>/dev/null; sleep 2; }
fuser -k 8443/tcp >/dev/null 2>&1 || true
rm -rf "$OUT" "$H/bundles" "$H/restored" "$H/acp-bootstrap.log" "$H/acp-bootstrap.pid" "$H/out/destination.tgz"
mkdir -p "$OUT" "$H/bundles" "$H/restored" /opt/worker
chown "$(stat -c %U "$H")" "$H/bundles"   # the orchestrator replicates bundles here over scp as the login user; acp-bootstrap (root) reads them
exec > >(tee -a "$OUT/console.log") 2>&1
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
VENV=/usr/local/lib/local_gpu_verifier/.venv/bin/python
BASE_REPO="Qwen/Qwen2.5-0.5B-Instruct"; BASE_REV="7ae557604adf67be50417f59c2c2f167def9a775"

step "the guest"
{ uname -a; lsb_release -ds; nproc; } > "$OUT/system.txt"
nvidia-smi conf-compute -q > "$OUT/conf-compute.txt" 2>&1
nvidia-smi --query-gpu=name,driver_version,vbios_version --format=csv > "$OUT/gpu.csv" 2>&1
install -m 0755 "$H/acp-bootstrap" /usr/local/bin/acp-bootstrap; install -m 0755 "$H/acpctl" /usr/local/bin/acpctl
tar -xzf "$H/worker.tgz" -C /opt/worker
sha256sum /usr/local/bin/acp-bootstrap /usr/local/bin/acpctl "$H/worker.tgz" "$H/gpu-token.py" > "$OUT/inputs.sha256"

step "the worker runtime (CUDA wheels) and the base model the genome names"
[ -x /opt/vg/bin/python ] || { apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1; python3 -m venv /opt/vg; /opt/vg/bin/pip install -q --upgrade pip; /opt/vg/bin/pip install -q --index-url https://download.pytorch.org/whl/cu126 torch==2.14.1; }
/opt/vg/bin/pip install -q -r /opt/worker/requirements.txt huggingface_hub==2.2.0
/opt/vg/bin/pip freeze > "$OUT/pip-freeze.txt"
/opt/vg/bin/python -c "from huggingface_hub import snapshot_download; snapshot_download('$BASE_REPO', revision='$BASE_REV', local_dir='/opt/base')"
/opt/vg/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.get_device_name(0))" > "$OUT/torch.txt"

step "acp-bootstrap as azure-cgpu: the destination of a key release, the door on the H100"
chmod 600 "$H/dest/server.key" "$H/dest/xcc_token"
python3 - "$H" "$VENV" <<'PY'
import json, sys
H, py = sys.argv[1], sys.argv[2]
c = {
 "http": {"listen_address": "0.0.0.0:8443", "bearer_token_file": H + "/dest/xcc_token",
          "tls": {"enabled": True, "server_cert": H + "/dest/server.crt", "server_key": H + "/dest/server.key", "client_cas": H + "/dest/ca.crt"}},
 "tee": {"provider": "azure-cgpu", "workload_descriptor": "acp-bootstrap-cgpu-standby-v1", "gpu_attest_command": [py, H + "/gpu-token.py"]},
 "source_authority": {"kid": "sagvd-authority-demo", "public_key_path": H + "/dest/authority.pem"},
 "genome": {"bundle_dir": H + "/bundles", "restore_dir": H + "/restored", "rescan_seconds": 2,
            "gate": {"command": ["/opt/vg/bin/python", "-m", "vg_genome", "door", "--genome", "{genome}", "--base", "/opt/base", "--device", "cuda"],
                     "env": ["PYTHONPATH=/opt/worker", "TOKENIZERS_PARALLELISM=false"], "atol": 0.01, "rtol": 0.001, "timeout_seconds": 600, "required": True}},
 "health": {"listen_address": "127.0.0.1:8444"}, "log": {"level": "info", "format": "json"}}
json.dump(c, open(H + "/dest.json", "w"), indent=2)
PY
acp-bootstrap seal-keys -config "$H/dest.json" > "$OUT/dest-seal-keys.json" 2> "$OUT/dest-seal-keys.err"
echo "acp-bootstrap seal-keys exit=$? sealed=$(python3 -c 'import json,sys;print(",".join(e["name"] for e in json.load(open(sys.argv[1]))["sealed"]))' "$OUT/dest-seal-keys.json" 2>/dev/null)" >> "$OUT/steps.txt"
acp-bootstrap identity -config "$H/dest.json" > "$OUT/destination-identity.json" 2> "$OUT/destination-identity.err"
echo "acp-bootstrap identity exit=$?" >> "$OUT/steps.txt"
nohup acp-bootstrap -config "$H/dest.json" > "$H/acp-bootstrap.log" 2>&1 &
echo $! > "$H/acp-bootstrap.pid"
n=0; until curl -sf http://127.0.0.1:8444/readyz >/dev/null || [ $n -ge 60 ]; do sleep 1; n=$((n+1)); done
echo "acp-bootstrap ready after ${n}s" >> "$OUT/steps.txt"
cat "$OUT/destination-identity.json"
echo "DESTINATION UP"
