# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared by the integer-door kit's VM startup script: metadata, GCS through
# the JSON API with the VM's own token, the pinned Python runtime, and the
# two pinned base models (0.5B for the CPU-sealed genome, 7B for the
# GPU-sealed one).

md() { curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/$1"; }
token() { md service-accounts/default/token | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'; }
enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

gcs_get() { # gcs_get <object> <file>
  curl -sSf -H "Authorization: Bearer $(token)" -o "$2" \
    "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$(enc "$1")?alt=media"
}
gcs_put() { # gcs_put <file> <object>
  curl -sSf -X POST -H "Authorization: Bearer $(token)" -H "Content-Type: application/octet-stream" \
    --data-binary @"$1" "https://storage.googleapis.com/upload/storage/v1/b/$BUCKET/o?uploadType=media&name=$(enc "$2")" > /dev/null
}

# The base models, pinned by revision; each genome's manifest pins the bytes.
SMALL_REPO="Qwen/Qwen2.5-0.5B-Instruct"
SMALL_REV="7ae557604adf67be50417f59c2c2f167def9a775"
LARGE_REPO="Qwen/Qwen2.5-7B-Instruct"
LARGE_REV="a09a35458c702b33eeacc393d103063234e8bc28"
HF_HUB="huggingface_hub==2.2.0"

python_runtime() { # python_runtime <torch index url>
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq > /dev/null && apt-get install -y -qq python3-venv python3-pip > /dev/null
  python3 -m venv /opt/vg
  /opt/vg/bin/pip install -q --upgrade pip
  /opt/vg/bin/pip install -q --index-url "$1" torch==2.14.1
  /opt/vg/bin/pip install -q -r /opt/worker/requirements.txt "$HF_HUB"
  /opt/vg/bin/pip freeze > "$OUT/pip-freeze.txt"
}

base_model() { # base_model <repo> <revision> <dir>
  /opt/vg/bin/python -c "from huggingface_hub import snapshot_download; snapshot_download('$1', revision='$2', local_dir='$3', max_workers=8)"
  du -sh "$3" >> "$OUT/base-size.txt"
}

vg() { PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome "$@"; }
