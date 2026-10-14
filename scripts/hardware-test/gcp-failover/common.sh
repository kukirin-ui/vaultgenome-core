# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared by the failover drill's VM startup scripts: metadata, GCS through
# the JSON API with the VM's own token, the pinned Python runtime and base
# model, and an outbox that is replicated between the machines as a tar so
# every snapshot the standby sees is internally consistent.

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
gcs_put_str() { printf '%s' "$2" > /tmp/_s.$$; gcs_put /tmp/_s.$$ "$1"; rm -f /tmp/_s.$$; }

# The base model, pinned by revision; the genome's manifest pins its bytes.
BASE_REPO="Qwen/Qwen2.5-0.5B-Instruct"
BASE_REV="7ae557604adf67be50417f59c2c2f167def9a775"
HF_HUB="huggingface_hub==2.2.0"

python_runtime() { # python_runtime <torch index url>
  export DEBIAN_FRONTEND=noninteractive
  # Ubuntu holds the dpkg lock at boot (unattended-upgrades); wait it out
  # rather than racing it, and cap the wait so apt never blocks forever.
  systemctl stop unattended-upgrades apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
  for i in $(seq 1 60); do fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 5; done
  apt-get -o DPkg::Lock::Timeout=300 update -qq > /dev/null && apt-get -o DPkg::Lock::Timeout=300 install -y -qq python3-venv python3-pip > /dev/null
  python3 -m venv /opt/vg
  /opt/vg/bin/pip install -q --upgrade pip
  /opt/vg/bin/pip install -q --index-url "$1" torch==2.14.1
  /opt/vg/bin/pip install -q -r /opt/worker/requirements.txt "$HF_HUB"
  /opt/vg/bin/pip freeze > "$OUT/pip-freeze.txt"
}

base_model() {
  /opt/vg/bin/python -c "from huggingface_hub import snapshot_download; snapshot_download('$BASE_REPO', revision='$BASE_REV', local_dir='/opt/base')"
}

vg() { PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome "$@"; }

# --- outbox replication -----------------------------------------------------
# The primary tars its whole outbox each cycle; the standby unpacks the tar
# into a staging dir and moves each file into the replica through a rename,
# so the restorer and the failover watcher never see a half-written file.

push_outbox() { # push_outbox <outbox dir>
  tar -C "$1" -czf /root/outbox.tgz . 2>/dev/null || return 0
  gcs_put /root/outbox.tgz outbox/outbox.tgz
}

pull_outbox() { # pull_outbox <replica dir>
  gcs_get outbox/outbox.tgz /root/outbox.tgz 2>/dev/null || return 0
  rm -rf /root/fresh && mkdir -p /root/fresh "$1"
  tar -C /root/fresh -xzf /root/outbox.tgz 2>/dev/null || return 0
  local f name
  for f in /root/fresh/*; do
    [ -e "$f" ] || continue
    name="$(basename "$f")"
    cp "$f" "$1/.incoming-$name" && mv "$1/.incoming-$name" "$1/$name"
  done
}
