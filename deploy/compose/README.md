# Local deployment: sagvd + acp-compute (Docker Compose)

A two-service deployment of the authority/worker pair, secured the same
way a real deployment is: every channel is authenticated.

| Channel | Protection |
|---|---|
| Worker → sagvd Return Path (`9443`) | mutual TLS 1.3 against a private CA, **then** a TEE-evidence handshake against the pinned worker key and measurement; every component of a job sealed under the session key |
| Operator → REST API (`9080`) | bearer token (constant-time compared) |
| Health / metrics (`9091`, `9092`) | read-only; published on loopback only |

`sagvd` refuses to start if a listener reachable from the network would be
unauthenticated (plain-TCP Return Path or token-less REST API on a
non-loopback address). The TEE backend here is the **simulated** one — this
deployment runs on any machine. For real AMD SEV-SNP attestation see
[`docs/operator/runbooks/real-tee-sev-snp.md`](../../docs/operator/runbooks/real-tee-sev-snp.md).

## Run it (from the repository root)

```
make build         # acpctl seals the demo genome
make demo-certs    # provision deploy/compose/secrets with keygen
make demo-genome   # fine-tune a tiny model, seal its genome into deploy/compose/genomes
make demo-up       # docker compose build + up, wait for sagvd /readyz
make demo-submit   # POST /v1/jobs naming the genome, poll the gate's verdict
make demo-down     # stop and remove
```

`make demo-test` adds a health probe of both services around the
round trip. `make demo-genome` needs the worker runtime on the host
(`pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.1`,
then `pip install -r workers/genome/requirements.txt`); it builds a tiny
random model locally and downloads nothing. To restore a real model, seal
its genome with `acpctl genome seal --content-dir` into `genomes/` and mount
its base directory into the worker with `ACP_BASE_MODEL=/path/to/base`.

## What keygen provisions

`deploy/compose/keygen` is a standalone, stdlib-only Go tool. It writes:

```
secrets/
  shared/
    sealing.key               32 B AES-256 session sealing key (pre-shared)
    workers.json              worker signing registry consumed by sagvd
    tls/ca.crt                private CA certificate (the CA key is never written)
  sagvd/
    tee_seed                  32 B Ed25519 seed (vault simulated TEE)
    authority_signing_seed    32 B Ed25519 seed (authority signing)
    peer_worker_pubkey        pinned worker TEE public key
    peer_worker_measurement   pinned worker workload measurement
    api_token                 REST API bearer token (64 hex chars)
    tls/server.crt|.key       Return Path server certificate (sagvd, localhost, 127.0.0.1, ::1)
  acp-compute/
    tee_seed                  32 B Ed25519 seed (worker simulated TEE)
    worker_signing_seed       32 B Ed25519 seed (CandidateOutput signing)
    peer_vault_pubkey         pinned vault TEE public key
    peer_vault_measurement    pinned vault workload measurement
    tls/client.crt|.key       Return Path client certificate
```

`secrets/` is git-ignored and docker-ignored, and so are `genomes/` (the
sealed bundles and their key files), `models/` (the base model) and
`audit/` (the Return Path audit log sagvd writes). keygen
refuses to overwrite an existing tree without `-force`, because regenerating
under a running pair desynchronises it (sealed material stops opening,
evidence stops pinning, TLS stops verifying). Files are mode 0644 so the
containers (uid 65532) can read them through the read-only bind mount; a
production deployment takes its key material from a secrets manager instead.
Genome key files are 0600, as `acpctl genome seal` writes them; sagvd refuses
a key file other users can read.

The workload descriptors (`sagvd-phase1-demo-v1`,
`acp-compute-phase1-demo-v1`) must match between the two `config.json`
files and `keygen/main.go`: peer measurements are SHA-256 of those strings.

## What a job does

1. `submit_job.sh` posts `{"genome": {"bundle": "gen-0.genome", "key_file":
   "gen-0.key"}}` to `POST /v1/jobs` with
   `Authorization: Bearer <secrets/sagvd/api_token>`.
2. sagvd opens the bundle from `/var/lib/acp/genomes` in memory with that
   key, checks it is a model genome, keeps the genome's reference fixtures
   and clears the plaintext; the request is admitted at intake (stage 1 of
   the nine-stage flow, ADR 0015), on the audit log as `REQUEST_RECEIVED`,
   and queued: `202 {"job_id", "request_id", "state", "genome"}`.
3. When the worker — already connected over mTLS and past the TEE
   handshake — is ready, sagvd decides trust for the request and that
   attested peer (stage 2: the operator's stop list, the policy profile),
   issues a signed session (3), opens the bundle again and discloses its
   model side to that session — `genome.json`, the LoRA adapter, the
   fixtures' prompts, one signed AES-256-GCM envelope each (4) — issues the
   signed manifest and ships the envelopes as the `JobRequest` (5). The
   worker unseals them, checks them against the job's descriptor, and runs
   the door: `python3 -m vg_genome door --stdin-genome --base /models/base`,
   which checks the base model against the genome's manifest, applies the
   adapter in memory and computes the model's logits at the reference
   tokens for every prompt. The worker signs the outputs as the
   `CandidateOutputFrame` and writes it back (6). Nothing of the genome
   touches the worker's disk.
4. sagvd verifies the frame (bindings, size budget, Ed25519 signature under
   the registered worker key), then validates (7): the six operational
   sub-checks over the job's own attestation, session and manifest, and the
   gate on two dimensions — top-1 agreement at every reference position,
   and the determinism ladder: byte-exact first (`pinned replay`), then
   within `genome.gate`'s tolerance (`native float`) — and signs the release
   decision (8). `GET /v1/jobs/{id}` returns the job with `flow` — every
   stage taken and every signed artifact, the decision included — `gate`
   (level, door, every attempt, the verdict signed by sagvd's authority
   key), `top1`, and `result.worker_signing_key_id`, the key the signature
   was verified under. A model that misses its references fails the job
   with `gate_failed`: the refusal is a signed decision too, and the answer
   is not surfaced.
5. Every one of those decisions is in `audit/returnpath-audit.db` before it
   took effect — the request received, trust decided, the session issued,
   each disclosure authorised, the manifest issued, the candidate received,
   the validation started, each dimension, every finding, the validation
   completed, the release decided (and, on a refusal, the incident and the
   session invalidated) — signed under `keys.audit_signing` and hash-linked.
   Read and verify it (the daemon holds the file while it runs; stop it or
   copy the file first):

   ```bash
   docker compose -f deploy/compose/docker-compose.yml exec sagvd sagvd identity -config /etc/acp/config/sagvd.json | jq -r .audit_public_key_pem > audit.pem
   ./bin/acpctl audit verify --audit deploy/compose/audit/returnpath-audit.db --audit-pubkey audit.pem --audit-kid sagvd-audit-demo
   ./bin/acpctl audit query  --audit deploy/compose/audit/returnpath-audit.db --json | jq .
   ```

On the same runtime the genome was sealed on (the worker image's pinned
CPU torch, when `make demo-genome` ran with the same wheel) the verdict is
`EXACT`; a genome sealed elsewhere comes back `EQUIVALENT` with the error
measured, or `FAIL`. See [ADR 0013](../../docs/adr/0013-worker-restores-the-genome.md).

## Verified by CI

The same binaries, key tree and configuration shape run on every push in
[`test/integration`](../../test/integration) (vault-gate sub-check 06): a
gate-job round trip over mTLS ending in a signed `EXACT` verdict, a genome
that misses its references refused with the attempts on record, an escrowed
genome restored with no key file in the bundle directory, REST calls without
or with a wrong token (401) or a wrong genome key (403), Return Path clients
without a trusted certificate (refused), a worker with a valid certificate
and sealing key but a foreign TEE key (never given work), fail-closed startup
on insecure exposure, and prompt SIGTERM shutdown of both daemons. There the
door is a Go program that speaks the protocol exactly; the real door with the
real torch runs in the `genome-worker` workflow.

## Troubleshooting

- `docker logs acp-sagvd` — look for `structural` (bad config),
  `authority` (peer pin mismatch: usually a stale `secrets/` tree) or
  `integrity` (sealing-key mismatch) classifications, and for
  `sagvd TLS handshake failed` (certificate problem).
- `docker logs acp-worker` — dial failures log as `return-path cycle
  failed` with a category; the first dial can race sagvd's listener and
  recovers within a backoff step. A job rejected with `door_failed` carries
  the door's own message: `base model does not match the genome's manifest`
  means the mounted `/models/base` is not the model the genome names.
- `curl -H "Authorization: Bearer $(cat deploy/compose/secrets/sagvd/api_token)" http://127.0.0.1:9080/v1/jobs/<id> | jq .gate`
  — the verdict, and every door tried, for a finished job.
- `curl http://127.0.0.1:9091/readyz` / `:9092/healthz` — sagvd is ready
  once bootstrap validation passes; the worker reports ready after its
  first successful job.
- `curl http://127.0.0.1:9091/metrics` — `sagvd_handshake_failures_total`
  by `phase` (`tls` or `handshake`) shows which layer refused a peer.

## Files

- `docker-compose.yml` — services, network, bind mounts, hardening
  (read-only root FS, no new privileges, all capabilities dropped).
- `sagvd/Dockerfile` — multi-stage build on `golang:1.27.0-alpine` →
  `distroless/static-debian12:nonroot`.
- `acp-compute/Dockerfile` — the same builder → `python:3.12-slim` with the
  pinned CPU torch and `vg_genome`, running as uid 65532: the worker needs a
  door.
- `sagvd/config.json`, `acp-compute/config.json` — in-container configs.
- `keygen/` — the provisioning tool (own module, stdlib only).
- `scripts/make_genome.sh` — fine-tunes and seals the demo genome.
- `scripts/submit_job.sh` — submit-and-poll helper (needs curl, jq).
