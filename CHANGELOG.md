# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public surface — CLI flags, bundle format,
audit schema, policy schema — may change between minor versions. Bundle and
schema versions are stated explicitly below so an operator can tell what a
given release can still open.

## [Unreleased]

### Security

- Go toolchain raised to 1.27.2 (`go.mod`, every workflow). `govulncheck`
  reported ten vulnerabilities in the standard library reachable from this
  code on go 1.27.0 — GO-2026-6603, 6604, 6605, 6607, 6608, 6610, 6611,
  6612, 6613, 6617 (`net/http`, `net/http/internal/http2`, `net/textproto`,
  `crypto/tls`, `os`) — and three more in the standard library not reached
  (GO-2026-6599, 6600, 6609). All are fixed in go1.27.2; the scan on this
  tree now reports none reachable. `golang.org/x/crypto` v0.57.0 → v0.58.0
  and `github.com/beevik/etree` v1.8.0 → v1.8.1 (`golang.org/x/sys`
  indirect, v0.48.0 → v0.49.0). The one advisory left in the module graph,
  GO-2026-5932 (`golang.org/x/crypto/openpgp`, no fix planned), names a
  package this module does not import (`go mod why` confirms); see
  `docs/dependencies/x-crypto.md`. The gate's osv-scanner step is
  presence-based, as the doctrine's §5 says (`--no-call-analysis=go`: the
  action's container carries a Go older than `go.mod` names and its call
  analysis cannot run there), and ignores that one advisory by id
  (`osv-scanner.toml`, reason on the record, expiring 2027-01-31) under
  the exception §5 now spells out; `make vuln` on the tree's own toolchain
  does the call analysis.
- The worker's Python runtime raised: `torch` 2.7.1 → 2.14.1, `transformers`
  4.53.2 → 5.19.0, `tokenizers` 0.21.2 → 0.23.3, `safetensors` 0.5.3 →
  0.8.0, `numpy` 2.3.1 → 2.5.4 (OSV: 28 advisories against the old pins,
  none against the new; KNOWN_ISSUES #14 records which of them the worker
  could reach, and which measurements still name the old runtime). CI now
  installs the runtime from `workers/genome/requirements-ci.lock` with
  `pip --require-hashes`: every wheel is checked against its sha256.
- Workflows: every tool installed in CI is pinned — `govulncheck` v1.9.0,
  `benchstat` and `go-mutesting` by commit, `syft` v1.54.1 through the
  `anchore/sbom-action/download-syft` action pinned by commit (the
  `curl … | sh` of an unversioned install script is gone from the release
  and gate workflows), the Semgrep container by image digest. The
  `security-events: write` permission moved from workflow level to the one
  job that uploads SARIF (CodeQL, Semgrep).

### Fixed

- The integer door read the rotary base as `getattr(cfg, "rope_theta",
  10000.0)`; under transformers 5 the base lives in `rope_parameters`, and
  the door computed Qwen2.5 (base 1 000 000) with the tables of base
  10 000 — the same bytes on every device, so every exactness check
  passed while its fidelity to the float model fell (the integer-door kit
  on the raised runtime, run `20261014T012445Z`: top-1 the same on 13 of
  16 fixtures at 0.5B for 16, max abs err 7.29 for 2.72). The base is now
  read from where the config keeps it and never assumed; a config that
  names none, and scaled, partial or per-layer rotary embeddings, are
  refused; and the door refuses a model whose own rotary module does not
  hold the default tables over that base, one whose projections do not
  have the shape its head counts imply, or one with any layer type but
  full attention. The tests' tiny model carries Qwen2.5's base, and the
  door's tables are checked against the model's.

### Added

- `docs/reference/cli.md`: every command and flag of the five binaries,
  generated from their own usage text by `make cli-reference`
  (`scripts/gen_cli_reference.sh`), so the reference cannot drift from
  the code.
- `docs/compliance/openssf-best-practices.md`: where each criterion of the
  OpenSSF Best Practices badge (passing level) is met in this repository.

## [0.3.2] — 2026-09-17

A binary can say which build it is, however it was built. Against 0.3.1,
`go install github.com/vault-genome/vaultgenome-core/cmd/acpctl@v0.3.1`
produces a working binary that answers `acpctl 0.0.0-dev (commit none)` —
the wrong answer from a project whose claim is that you can tell what you
are running and check it against a signed release, and the answer every
reader who follows the README's own install line was given. Behaviour is
otherwise unchanged from 0.3.1; bundle format, audit schema and policy
schema: unchanged.

### Added

- `internal/shared/buildinfo`: the version and commit a binary prints fall
  back to the module version and VCS revision Go already embeds, **only**
  when the Makefile's `-X` stamps are absent. A stamped value always wins,
  so `make build` and the release workflow print exactly what they printed
  before. A pseudo-version or `(devel)` is not surfaced as a version,
  because neither says more than the placeholder; a dirty tree is marked
  `-dirty` rather than hidden. 96.9% covered.

### Changed

- **Dockerfile** takes `VERSION` and `COMMIT` as build arguments, because
  `.dockerignore` excludes `.git` and Go can therefore embed no revision in
  an image build. It still builds without them, and its header documents
  both forms.

  | build path | 0.3.1 | 0.3.2 |
  | - | - | - |
  | `go install …/cmd/acpctl@<tag>` | `0.0.0-dev (commit none)` | `<tag> (commit <sha>)` |
  | `docker build --build-arg VERSION=… --build-arg COMMIT=… .` | `0.0.0-dev (commit none)` | `<tag> (commit <sha>)` |
  | `make build` | `0.0.0-dev (commit <sha>)` | unchanged |

## [0.3.1] — 2026-09-17

The release pipeline's signing step, and nothing else. 0.3.0 is tagged and
the module is served at that version, but its release run stopped at *Sign
binaries*: the actions bump of #33 moved `cosign-installer` to v4, which
installs cosign 3, and cosign 3 writes the Sigstore bundle format by default
and ignores `--output-signature` / `--output-certificate`. 0.3.0 therefore
has no release assets. This release pins cosign 2.6.5, so the assets and the
verification commands documented in README, `docs/security/supply_chain.md`
and the runbooks stay what they were; the move to bundles is tracked in
KNOWN_ISSUES #15 and changes the documented verification commands with it.
The code is 0.3.0's.

### Changed

- `release.yml`: `cosign-release: v2.6.5` pinned on the installer.

### Added

- KNOWN_ISSUES #15: release signatures on cosign 2.x, and the bundle-format
  migration as one release together with the documents.

## [0.3.0] — 2026-09-17

The module moves to the path it is published at. Against 0.2.1,
`go install github.com/vault-genome/vaultgenome-core/cmd/acpctl@v0.2.1`
stops with *module declares its path as: github.com/ai-continuity-platform/core*;
from this release the declared path is the repository's, so `go install` and
`go get` work from the public repository. Import paths change with it, which
under a major version of `0` is a minor version. No behaviour changes: the
binaries are the code of 0.2.1 under the new path. Bundle format, audit schema
and policy schema: unchanged from 0.2.1.

### Changed

- **Module path** `github.com/ai-continuity-platform/core` →
  `github.com/vault-genome/vaultgenome-core`, in `go.mod` and every import;
  the standalone demo keygen module → `…/deploy/compose/keygen`.
- **Every link into the repository that still named the pre-publication
  organisation names this one:** SECURITY.md's private-advisory URL and
  release link, the issue template's contact links, the setup guide's
  `git clone`, the supply-chain download examples, the TAP draft's
  references, `pkg/teeconformance`'s import example, `docs/STATUS.md`.
  The old organisation does not exist on GitHub; each of these was a 404.
- The issue template's discussion links point at this repository's
  Discussions (now enabled), categories *Ideas* and *Q&A*.
- CODE_OF_CONDUCT.md names an enforcement contact instead of the
  placeholder it carried since before the first public release.
- ADR 0003 records the rename beside the module path it names.

### Added

- KNOWN_ISSUES.md: the worker's pinned Python runtime and the advisories
  OSV reports against those pins, why the pins stay until the runtime is
  re-measured, and what `govulncheck` reports for the Go tree.
- `scorecard.yml` accepts an optional `SCORECARD_TOKEN` so the
  Branch-Protection check can read the rules that are set (the default
  token cannot read classic rules); without the secret it uses the default
  token as before.

## [0.2.1] — 2026-09-17

The reference release: the code of 0.2.0 with static binaries that anyone
rebuilds byte for byte from any host with the pinned Go, the post-release
check run from macOS against these artifacts, and the Go modules Dependabot
bumped after 0.2.0.

### Changed

- **Dependencies:** `github.com/beevik/etree` 1.7.0 → 1.8.0,
  `github.com/stretchr/testify` 1.11.1 → 1.12.1, `go.etcd.io/bbolt` 1.3.10
  → 1.5.0 (Dependabot, #26; the gate green); the dependency justifications
  under `docs/dependencies/` no longer carry a version (the version is
  `go.mod`'s). Dependabot opens no pull requests against the worker's
  measured Python runtime.
- **Release binaries are static** (`CGO_ENABLED=0` in the build): they run
  on any linux/amd64 without a libc to match, and anyone rebuilds them byte
  for byte from any host with the pinned Go — the post-release check of
  `docs/operator/05_release_procedure.md` §5 now names the exact command,
  from a git checkout of the tag. Found verifying v0.2.0 from macOS: its
  binaries were built with cgo on the runner, so their rebuild needs
  linux/amd64 with a C toolchain.

## [0.2.0] — 2026-09-17

Two days of hardware, on the record. Since 0.1.0 the worker restores a real
fine-tuned model and the authority judges it (ADR 0013); the nine governed
stages run for every job, each decision on the audit log before it takes
effect (ADR 0014, 0015); the authority's escrow key is made in its own
process and lives only sealed to the chip or, on TDX and the Azure
confidential GPU host, to the guest's vTPM (ADR 0016, 0022), and every
other secret file the daemons read — seeds, the session sealing key, TLS
keys, tokens, the sentinel's seed — is sealed to the host in place
(ADR 0023); the primary's word is bounded by its chip's report (ADR 0017);
Intel TDX and the Azure confidential GPU VM attest on the Return Path
(ADR 0018, 0019); the integer door gives the same bytes on a Xeon and an
L4 (ADR 0020); the H100's attestation report is evaluated by this verifier
— signature, chain, firmware id, every measurement against NVIDIA's signed
manifests, revocation asked of NVIDIA's responder — and what it checked is
on the audit record (ADR 0021). Five continuity drills ran on live
confidential hardware in two clouds (SEV-SNP → SEV-SNP, → Azure H100,
→ Intel TDX; the authority on TDX; eight policies against one attack), and
a 32B model went through the genome path on a confidential H100, gated
EXACT. Claims C13–C26 in VERIFIABLE-CLAIMS.md carry the evidence.

**Compatibility.** The genome v3 bundle format and the audit event
schemas are unchanged; new audit payload fields (`peer_detail`,
`destination_detail`) are optional. New config fields are optional
(`tee.sev_guest_device`, `tee.vtpm_seal_pcrs`, `gpu_policy.revocation`,
`gpu_policy.ocsp_url`, `runtime.max_payload_bytes` as before), and
`gpu_policy.evaluation: "own"` is admitted. Key files may now be sealed
(`vault-genome/sealed-secret/v1`); bare files still load. The Return Path
wire format is unchanged, but its frame cap moved from 16 MiB to 128 MiB:
both ends of a Return Path must run this release or later for a genome
over 16 MiB. The `go` directive is 1.26. Two dependencies were added
(`golang.org/x/crypto`, `github.com/beevik/etree`), both justified under
`docs/dependencies/`.

### Added

- **A 32B model through the genome path on the confidential H100**
  ([C26](VERIFIABLE-CLAIMS.md#c26)) — the Azure kit takes the base model
  from `VG_BASE_REPO` / `VG_BASE_REV`; Qwen/Qwen2.5-32B-Instruct fine-tuned in bfloat16 on the
  H100 NVL, sealed, restored and gated EXACT over the Return Path on the
  same confidential VM (`scripts/hardware-test/azure-cgpu/evidence/20260917T020218Z`).
- **The verifier's word on live records from the H100** — the cross-cloud
  drill `scripts/hardware-test/failover-cgpu/evidence/20260916T233717Z/`
  (GCP SEV-SNP → Azure H100; every secret file sealed on the three
  machines; generation 1 restored on the H100, gate EQUIVALENT, RTO
  25.74 s) carries `destination_detail` on the
  `CROSS_CLOUD_ATTESTATION_VERIFIED` record; the Return Path run
  `scripts/hardware-test/azure-cgpu/evidence/20260917T012834Z-returnpath/`
  carries `peer_detail` on the `TRUST_EVALUATED` record that admitted the
  worker, with the verifier's own evaluation and revocation asked of
  NVIDIA's responder in the handshake (the BROM certificate, the
  Provisioner ICA and the GH100 Identity CA good; the per-GPU leaf not
  served). The cross-cloud kit's
  registry entry now asks for `both`, with revocation, at key release
  (VERIFIABLE-CLAIMS C20).
- **Revocation of the GPU's certificate chain checked with NVIDIA's OCSP
  responder** ([ADR-0021](docs/adr/0021-the-verifiers-own-evaluation-of-the-gpu.md),
  amended) — under `gpu_policy.evaluation` `both` or `own`, the
  verifier's own evaluation asks `http://ocsp.ndis.nvidia.com` (or
  `gpu_policy.ocsp_url`) about each certificate between the GPU's leaf
  and the pinned root, by its issuer, with a nonce; the answer's
  delegated responder certificate is verified under the issuer and its
  OCSP-signing use, the nonce echoed, the answer inside its validity; a
  good answer is cached a day under `rim_cache_dir`. `gpu_policy.revocation:
  "off"` leaves it unchecked, on the record (`revocation_checked`,
  `revocation_good`, `revocation` per certificate in the evaluation).
  NVIDIA's answers for the captured H100 chain are stored as test
  material. `gpu_policy.evaluation: "own"` is admitted by `sagvd`'s
  config validation, as the verifier has admitted it since the
  manifests' signatures were verified. New dependency
  `golang.org/x/crypto` (the `ocsp` package; `docs/dependencies/x-crypto.md`);
  `github.com/beevik/etree`, imported directly since the manifest
  signatures, is recorded on the allowlist (`docs/dependencies/etree.md`).
- **The daemons' TLS keys and tokens sealed to the host too**
  ([ADR-0023](docs/adr/0023-the-daemons-key-files-sealed-to-the-host.md),
  amended) — `sagvd seal-keys` also seals the vault's mTLS server key, the
  cross-cloud transport's client key and the REST API token;
  `acp-compute seal-keys` the worker's mTLS client key; the new
  `acp-bootstrap seal-keys -config` the destination's TLS server key and
  bearer token (with `tee.sev_guest_device` and `tee.vtpm_seal_pcrs` for
  its sealer). Every loader takes the bare file or the sealed one. The
  hardware kits seal all of them before the first start, giving a
  destination on a shared host its own copies first.
- **The sentinel's seed sealed to the primary's chip**
  ([ADR-0023](docs/adr/0023-the-daemons-key-files-sealed-to-the-host.md),
  amended) — `acpctl sentinel seal-key --key SEED --tee gcp-sev-snp` seals
  the sentinel's seed file in place to the primary's TEE under the name
  `sentinel.seed`; `acpctl sentinel identity` and `watch` open the sealed
  file with `--tee`, and refuse it without the TEE or on another host.
  The failover kit seals the seed before the sentinel starts and adds a
  negative: the sealed file taken to the standby's chip does not open.
  Proven in the failover drill (`scripts/hardware-test/gcp-failover`,
  `20260916T231442Z`, VERIFIABLE-CLAIMS C25).
- **The verifier's evaluation of a confidential GPU host is on the audit
  record** ([ADR-0021](docs/adr/0021-the-verifiers-own-evaluation-of-the-gpu.md),
  amended) — a verifier that can say more than a measurement
  (`tee.DetailedVerifier`; the `azure-cgpu` verifier does) puts its detail
  — the chip's product and id, the reported TCB, the vTPM quote's PCR
  selection and digest, each GPU with who vouched for it, the verifier's
  own evaluations check by check — on `TRUST_EVALUATED` as `peer_detail`
  when `sagvd` admits the worker and on `CROSS_CLOUD_ATTESTATION_VERIFIED`
  as `destination_detail` when the authority releases a key to it. Absent
  for verifiers with only a measurement, so other providers' records are
  unchanged. The session-opened log line carries the operator's glance
  (provider, product, PCRs, GPUs, evaluations complete).
- **The daemons' key files sealed to the host**
  ([ADR-0023](docs/adr/0023-the-daemons-key-files-sealed-to-the-host.md))
  — `sagvd seal-keys` and `acp-compute seal-keys` seal, in place, every
  key file the config names (the authority's signing seed, the audit
  seed, the worker's signing seed, the session sealing key) to the host's
  TEE — the chip's derived key on SEV-SNP, the vTPM on TDX and the Azure
  confidential GPU host — as `vault-genome/sealed-secret/v1`, with the
  key's name bound into the AEAD so a file sealed as one key does not open
  as another; the daemons open sealed files at start through the same
  paths. The hardware kits seal before the first start; proven on a SEV-SNP
  host running the failover drill from sealed files
  (`scripts/hardware-test/gcp-failover`, `20260916T212752Z`, VERIFIABLE-CLAIMS C24).
- **The escrow key sealed to the guest's vTPM where the TEE gives no
  sealing key** ([ADR-0022](docs/adr/0022-the-escrow-key-sealed-to-the-vtpm.md))
  — `sagvd` on `gcp-tdx` and `azure-cgpu` seals the escrow key to the
  vTPM: a fresh AES-256 key per seal held by the TPM as a sealed object
  under a policy of this boot's PCRs (`tee.vtpm_seal_pcrs`, default
  sha256:0-14), the plaintext under it with AES-256-GCM; tpm2-tools as
  processes, no TPM library; the recovery ceremony unchanged. Proven on a
  GCP `c3` Trust Domain as the release authority of a failover
  (`scripts/hardware-test/failover-tdx-authority`, `20260916T200841Z`,
  VERIFIABLE-CLAIMS C23): sealed, opened, re-sealed through the ceremony,
  unsealed at start, the model moved (RTO 20.27 s).
- **The manifests' XML signatures verified, and `own` admitted**
  ([ADR-0021](docs/adr/0021-the-verifiers-own-evaluation-of-the-gpu.md),
  amended) — `VerifyRIMSignature` verifies each NVIDIA reference
  manifest's enveloped XML signature (Canonical XML 1.1, ECDSA-SHA384,
  nothing else admitted) under the certificate chained to the pinned
  CoRIM root, with goxmldsig as the canonicaliser
  (`docs/dependencies/goxmldsig.md`); a complete evaluation now includes
  both signatures. `gpu_policy.evaluation: "own"` rests the verdict on
  this verifier's evaluation alone — NVIDIA's tokens not required — and
  holds the policy's model and version pins against the report; the
  secure-boot and debug claims stay NVIDIA-token claims (`both`). The
  GPU's model is named as NVIDIA's tokens name it (`GH100`), from the
  chain's per-model identity CA.
- **The negatives drill** (`scripts/hardware-test/failover-negatives`,
  VERIFIABLE-CLAIMS C22, CONTINUITY-DRILL Drill V) — the failover drill's
  two SEV-SNP machines, one attack, eight operator-signed policies against
  the same compromise report: an expired policy, an RPO bound, a
  quarantine, an operator stop, a foreign standby, a corrupted replica
  bundle, the spent policy again and a stranger's signature. Measured
  (`20260916T191033Z`): seven refusals, each for its own reason — two of them after
  the standby's chip verified — six on one 16-event audit log; the one move
  restores generation 0 EXACT with generation 1 set aside on the record.
- **The continuity drill's TDX leg**
  (`scripts/hardware-test/failover-tdx`, VERIFIABLE-CLAIMS C21) — the
  failover of the drill with the standby a GCP `c3` Intel TDX Trust
  Domain: `acp-bootstrap` as `gcp-tdx`, the authority's registry with the
  `gcp-tdx` destination (Intel PCS cached) beside the primary's SEV-SNP
  anchors, the policy pinning the Trust Domain's measurement. Measured
  (`20260916T181528Z`): RTO 24.09 s, RPO 12.00 s, the clean generation gated
  EQUIVALENT on Intel CPUs against references sealed on AMD (max abs err
  1.45e-4) — float32 is not byte-identical across CPU vendors either.
- **The verifier's own evaluation of the GPU's report**
  ([ADR-0021](docs/adr/0021-the-verifiers-own-evaluation-of-the-gpu.md)) —
  an `azure-cgpu` peer or registry entry with `gpu_policy.evaluation:
  "both"` is accepted only when, beside NVIDIA's signed tokens, this
  verifier's evaluation of the GPU's attestation report is complete: the
  SPDM 1.1 report's structure, nonce and ECDSA P-384 signature under the
  GPU's certificate, the chain to the NVIDIA Device Identity CA pinned in
  the binary, the firmware id in the certificate's DICE extension, and
  every runtime measurement against the driver and VBIOS reference
  manifests fetched from NVIDIA's RIM service (`rim_service_url`,
  `rim_cache_dir`; their chains to the pinned NVIDIA CoRIM signing root,
  their bytes to the service's SHA-256). The evidence envelope carries the
  report and chain (`gpu_evidence`), which the kit's `gpu-token.py` now
  prints beside NRAS's response. `own` is refused: the manifests' XML
  signatures are not verified in this build (KNOWN_ISSUES #1). Proven
  offline on the captured H100 report and manifests
  (`internal/shared/tee/testdata/nvidia`, VERIFIABLE-CLAIMS C20).
- **The integer door for the LoRA worker**
  ([ADR-0020](docs/adr/0020-the-integer-door-for-the-lora-worker.md)) —
  `vg_genome/integer.py` computes the restored model's forward pass in
  integer arithmetic (int8 weights with the delta merged, 14-bit
  activations, `torch._int_mm`, an integer RMSNorm, rotary tables from
  big integers in `fixedmath.py`, an integer exponential for softmax and
  SiLU; every division exact by a device self-test or by long division),
  so the same genome gives the same bytes on any CPU or GPU. `finetune`
  records that door's logits beside the float references
  (`expected_integer`, `fixtures.integer` with the scheme and the
  measured fidelity; `--no-integer-door` leaves them out); `measure
  --door integer [--limit N]` holds the door to them; the door answers a
  request naming `"door": "integer"`, and the in-memory door adds
  `integer_outputs` when the prompts say `"integer": true`. The gate's
  ladder has a third rung for a genome that carries the references —
  `fixed-point`, name `integer`, tolerance zero against its own
  references — in `acp-bootstrap`, `acpctl genome gate` (a second run of
  the door, only when the float doors did not open) and `sagvd`'s gate
  job (the worker is asked for the integer outputs, the budget counts
  them, rung 2 judges them). `scripts/hardware-test/integer-door/` proves
  it on an L4 and its host CPU (run `20260916T164511Z`): byte-identical
  logits CPU↔GPU at 0.5B (16/16) and 7B (16/16 on the GPU, 3/3 on the
  CPU against the GPU's references), the gate EXACT at rung 2 where both
  float doors failed at zero tolerance — VERIFIABLE-CLAIMS C19,
  KNOWN_ISSUES #13.
- **The GPU leg of the failover drill** —
  `scripts/hardware-test/failover-cgpu/`: a model fine-tuned on a GCP
  SEV-SNP primary fails over, under the operator's signed policy, to an
  Azure NCC H100 v5 standby attesting as `azure-cgpu` across the Internet
  (run `20260916T150456Z`): the authority — GCP SEV-SNP, its escrow key
  sealed to its chip — took the primary's attested compromise report,
  verified the standby's chip to AMD's Genoa root, its vTPM's quote against
  the pinned boot (`pcr_digests`) and NVIDIA's tokens for the H100, released
  the key for the last generation sealed before the attack, and confirmed
  the standby's receipt: the genome restored and gated **EQUIVALENT** on the
  H100 (max abs err 1.5e-4), RTO 24.99 s, RPO 12.0 s, five audit events
  verified. VERIFIABLE-CLAIMS C18, `docs/CONTINUITY-DRILL.md` Drill III,
  KNOWN_ISSUES #1 and #12 updated. The kit reuses the failover drill's
  primary; its authority's registry holds both the `azure-cgpu` destination
  and the primary's `gcp-sev-snp` anchors, as runbook 07 requires.
- **A bfloat16 tolerance the operator signs for.** `sagvd`'s
  `genome.gate.bfloat16 {atol, rtol}` is the tolerance a genome whose
  recipe computed in bfloat16 is held to — chosen by the genome's
  `recipe.dtype`, part of the policy version every session is pinned to,
  absent by default (a bfloat16 genome is then held to the float32
  tolerance, as before). `internal/genome/lora` reads the recipe's
  `device` and `dtype`.
- **The vTPM's boot, pinned; a destination by IP, named.** An `azure-cgpu`
  peer or registry entry takes `pcr_digests` — the digest over the quoted
  PCRs, printed by `identity` as `vtpm.pcr_digest_hex` — so what the vTPM
  measured of the boot is policed and not only recorded; the transport TLS
  client takes `server_name` for a destination whose certificate does not
  name the host of its URL.
- **A confidential GPU worker on Azure**
  ([ADR-0019](docs/adr/0019-a-confidential-gpu-worker-on-azure.md)) —
  `tee.provider: "azure-cgpu"` for `sagvd`, `acp-compute` and
  `acp-bootstrap`, `azure-cgpu` peers and verifier-registry entries. On an
  Azure NCC H100 v5 (AMD SEV-SNP under the paravisor, an H100 in
  confidential-computing mode) the producer reads the SEV-SNP report from
  the vTPM's HCL report, quotes the PCRs with the vTPM's attestation key
  and `SHA-256(nonce)` in `extraData` (tpm2-tools), and runs
  `gpu_attest_command` for NVIDIA's signed attestation tokens under the same
  value; the verifier takes the report to AMD for the chip's product
  (Genoa), checks `REPORT_DATA` names the runtime data and the quote
  verifies under the key it carries, verifies NVIDIA's tokens ES384 under
  NVIDIA's key set (`nras_jwks_url`, `nras_cache_dir`) and applies
  `gpu_policy` (secure boot, no debug, signed manifests, matched
  measurements, pinned model/driver/VBIOS). No sealer.
  `scripts/hardware-test/azure-cgpu/` captures a genuine machine and runs
  the Return Path on it with the 7B genome on the H100 (VERIFIABLE-CLAIMS
  C17). AMD KDS fetches are product-aware (`realAMDKDSGetVCEKFor`).
- **The recipe names its device and dtype** — `python -m vg_genome finetune
  --device cuda --dtype bfloat16` trains the adapter on a GPU with the base
  in bfloat16 (the adapter stays float32, and so does every measurement);
  the genome's recipe records `device` and `dtype`, the fixtures are recorded
  on the device that trained, and the door, `measure` and `replay` restore the
  base in the recipe's dtype (`--dtype` overrides it for a measurement off
  the pinned runtime). A genome that predates the fields restores in float32.
  `scripts/hardware-test/gpu-7b/` takes Qwen2.5-7B-Instruct through the
  genome path on one NVIDIA L4 (run `20260916T043622Z`: a 10 MB genome,
  EXACT on the pinned GPU, the recipe replaying bit for bit, and the float
  door failing closed across devices in bfloat16 while the answers stay the
  same — VERIFIABLE-CLAIMS C16, KNOWN_ISSUES #13).
- **Intel TDX on the Return Path**
  ([ADR-0018](docs/adr/0018-intel-tdx-on-the-return-path.md)) —
  `tee.provider: "gcp-tdx"` for `sagvd`, `acp-compute` and `acp-bootstrap`,
  `tee.peer.provider: "gcp-tdx"` and `gcp-tdx` entries in the cross-cloud
  verifier registry. The producer quotes through configfs-tsm (`tdx_guest`)
  with the challenge in REPORTDATA and reports as its 48-byte measurement the
  SHA-384 of MRTD and RTMR0..3. The verifier chains the quote's PCK
  certificates to the pinned Intel SGX Root CA, checks the attestation key's
  and the PCK leaf's signatures and the QE report's binding of the key,
  fetches Intel's TCB info and QE identity from Intel PCS (`pcs_url`;
  `pcs_cache_dir` keeps them between runs) and verifies their signatures
  before reading them, evaluates the platform, TDX-module and QE TCB
  statuses (`acceptable_tcb_statuses`: `UpToDate` by default, hardening
  statuses by choice, `OutOfDate` and `Revoked` never), refuses a debuggable
  TD, binds the nonce and pins the measurement. No TDX sealer: an escrow key
  cannot be sealed to a TDX host. `sagvd identity` and `acp-compute
  identity` print the MRTD and RTMRs a TDX measurement is made of.
  `scripts/hardware-test/gcp-tdx/capture/` holds a genuine c3 quote with
  Intel's documents, which the verifier's tests run against;
  `scripts/hardware-test/gcp-tdx/returnpath-e2e/` runs both daemons on one
  Trust Domain.
- **The escrow key is sealed to the release host's TEE**
  ([ADR-0016](docs/adr/0016-escrow-key-sealed-to-the-release-host.md)) —
  the SEV-SNP sealer is real: a key the firmware derives for this chip,
  launch measurement and guest policy (`SNP_GET_DERIVED_KEY` on
  `/dev/sev-guest`, pure Go), expanded with a label of its own, AES-256-GCM,
  derived for every call and never stored. `sagvd escrow-provision` makes
  the authority's escrow key inside its own process and writes it only
  sealed (`vault-genome/sealed-escrow-key/v1`), with `-recovery-to` wrapped
  to the operator's recovery key (`vault-genome/escrow-recovery/v1`); `-stdin`
  re-seals a recovered key on a new host. `acpctl escrow recovery-keygen`
  and `acpctl escrow recover` are the operator's side. `sagvd` unseals the
  key in memory at start and refuses a plaintext `key_escrow_path` on a
  hardware TEE; `sagvd identity` prints `key_escrow_storage`. Config:
  `tee.sev_guest_device`.
- **Limits on the primary's word**
  ([ADR-0017](docs/adr/0017-limits-on-the-primarys-word.md)) — the sentinel
  attests every record it writes with the primary's TEE
  (`acpctl sentinel watch --tee`, records carry `attestation`), and
  `acpctl sentinel identity` prints what the operator pins. The failover
  policy pins the primary (`primary.kind`, `primary.measurements`,
  `primary.attestor_public_key` for a simulated one; `acpctl failover issue
  --primary-kind --primary-measurement --primary-attestor-pub`): a record
  without a verifying report at a pinned measurement is ignored, so a stolen
  seed off the chip is silence. `triggers.stopped_grace_seconds`
  (`--stopped-grace`) bounds how long `stopped` stands the authority down;
  overdue, it is the trigger `stopped-overdue`. The executor restores
  nothing past the generation the trigger's record names and declines an
  outbox that contradicts it. `FAILOVER_DECIDED` and the report carry
  `primary_measurement_hex`; the report lists `ignored` records.
- The failover drill kit (`scripts/hardware-test/gcp-failover`) runs the
  authority on SEV-SNP with its escrow key sealed to the chip, the recovery
  ceremony, the primary attesting with its chip, and a rogue sentinel with
  the stolen seed on the standby's chip, declined.
- **One binary drives the nine stages**
  ([ADR-0015](docs/adr/0015-one-binary-drives-the-nine-stages.md)) — `sagvd`
  takes every gate job through the flow with the library's own
  decision-makers: `intake` (a RecoveryRequest, admitted once), `trust`
  (the operator's stop list, the policy profile, the attested worker →
  a signed `AttestationResult`), the session issuer, the staged disclosure
  sequencer (the genome's model side sealed to the session, one signed
  envelope per component), a signed `ReconstructionJobManifest`, the
  candidate, the validation service (six operational sub-checks over the
  job's own artifacts, plus the gate on two dimensions — top-1 agreement
  and the determinism ladder), and a signed `ReleaseDecision` citing its
  `RELEASE_DECIDED` event; a refusal closes the session through the
  incident service. `orchestration.Authority`/`Flow`/`Machine` drive it;
  every transition is the table's. `GET /v1/jobs/{id}` shows the flow's
  state, transitions and signed artifacts; `POST /v1/jobs` accepts
  `request_id`, `policy_profile`, `requester_identity`, `contour` and
  returns `request_id` and `state`. Config: `operator_stop` (the stop list
  trust consults for gate jobs), `runtime.evidence_max_age_seconds`;
  `sagvd identity` prints `policy_version` and `policy_profiles`; metric
  `sagvd_release_decisions_total{decision}`.
- `internal/validation/equivalence.Top1Agreement` — the semantic question
  a restored model can answer: the same top-1 at every reference position.
- **The Return Path on the record, and on hardware**
  ([ADR-0014](docs/adr/0014-return-path-on-the-record-and-on-hardware.md)) —
  `sagvd` keeps a Return Path audit log (`audit.log_path`, signed with
  `keys.audit_signing`, verified end to end at start, required with gate
  jobs): a job accepted, a peer refused or a worker admitted, a candidate
  received, the gate's dimensions, findings and verdict, a session ended —
  each on the record **before** it takes effect, and a log that cannot take
  the record stops the decision (`audit_unavailable`). Existing audit kinds,
  no schema bump; payloads `vault-genome/returnpath-audit/v1`;
  `acpctl audit verify` checks the log under the key `sagvd identity`
  prints; `sagvd_audit_events_total{kind}`. `sagvd` and `acp-compute` attest
  with AMD SEV-SNP (`tee.provider: "gcp-sev-snp"`, reports through
  configfs-tsm) and pin a SEV-SNP peer by its 48-byte launch measurement and
  the AMD chain (`tee.peer.provider`, `amd_cert_chain_path`, `vcek_cache_dir`,
  `amd_kds_url`, `min_reported_tcb`); the simulated backend stays, explicit.
  `acp-compute identity` prints the worker's signing key, provider and
  measurement. Run on a GCP SEV-SNP Confidential VM with the shipping
  binaries and the real `vg_genome` door
  (`scripts/hardware-test/gcp-sev-snp/returnpath-e2e/`).
- **The worker restores the genome** ([ADR-0013](docs/adr/0013-worker-restores-the-genome.md))
  — a job on `sagvd`'s REST API names a sealed model genome in
  `genome.bundle_dir`; `sagvd` opens it (key file, or escrow envelope opened
  with `genome.key_escrow_path`), keeps the fixtures' references, and ships
  the model side — `genome.json`, the LoRA adapter, the fixtures' prompts —
  sealed component by component over the Return Path behind a descriptor
  (`internal/genome/gatejob`). `acp-compute` restores the model in memory
  through the `vg_genome` door (`python -m vg_genome door --stdin-genome`) and
  answers the prompts; `sagvd` holds the answers to the references through the
  determinism ladder and records the verdict on the job, signed by the
  authority (`gate` on `GET /v1/jobs/{id}`; `sagvd_gate_verdicts_total{level}`).
  Live over mutual TLS in `test/integration`; with the real fine-tune and real
  torch in the `genome-worker` workflow.
- `acp-compute` configuration section `genome.door` (`command`, `env`,
  `timeout_seconds`); `sagvd` configuration section `genome` (`bundle_dir`,
  `key_escrow_path`, `gate`).
- **[VERIFIABLE-CLAIMS.md](VERIFIABLE-CLAIMS.md)** — every public claim mapped
  to the evidence file that proves it and the command that reproduces it,
  including an explicit *What we do not claim* section.
- **[docs/CONTINUITY-DRILL.md](docs/CONTINUITY-DRILL.md)** — the two hardware
  drills as one narrative, with the measured numbers.
- **[NOTICE](NOTICE)** — copyright, licence scope and third-party attribution.
- **[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)** — the dual-licensing offer,
  with a public commitment that the AGPL build and the commercial build are the
  same code, and that the ADR-0012 safety invariants are not negotiable for any
  customer.
- **[MAINTAINERS.md](MAINTAINERS.md)** — both founders, their roles, and where
  release authority is pinned.
- This changelog.

### Fixed

- The failover drills' scripts no longer mark a good run as failed: the
  primary waited for the sentinel's expected exit 3 under `set +e`, which
  does not silence bash's ERR trap, so the trap wrote a FAILED marker
  beside the DONE one (`scripts/hardware-test/gcp-failover/primary.sh`;
  the same for the standby's negative check in `standby.sh`, and the
  primary's outbox push loop no longer inherits the trap). Seen in the
  TDX leg's first two runs, whose failovers had succeeded.
- **The Azure onboarding kits pinned the wrong NVIDIA userspace.**
  `scripts/hardware-test/azure-cgpu/run.sh` (and the new
  `failover-cgpu/run.sh`) read the signed modules' version bound with
  `apt-cache depends`, which prints no versions; the bound came back empty
  and the newer userspace in noble-updates got pinned, which the modules
  refuse. The bound is now read from `apt-cache show`.
- **`sagvd`'s verifier registry takes `azure-cgpu` entries.** ADR 0019 and
  its runbook said it did; the loader had no case and refused the
  provider. It takes the AMD fields (the Genoa chain), `nras_jwks_url`,
  `nras_cache_dir`, `gpu_policy` and `pcr_digests` now.

- **No test is skipped.** The eight `t.Skip("KNOWN: …")` tests run again,
  each for its real reason (KNOWN_ISSUES, "The eight that were skipped"):
  the in-memory witness log stamped every signed tree head with its clock,
  so a log whose entries carried timestamps ahead of the clock issued heads
  that predated what they covered and its own receipts failed the receipt
  contract — a head is now stamped no earlier than the newest entry it
  covers; `ContinuityProof.Verify(nil)` dereferenced the nil resolver — every
  contract's `VerifySignature` now refuses a nil resolver as Structural;
  the witness fixtures stamped heads before the entries they covered; and
  the tampered-STH test tampers as an adversary would, with the all-zero
  hash named as the Structural refusal the shape rules make it.

### Changed

- **Every GitHub Action pinned by commit SHA**, the version kept as a comment
  and Dependabot keeping both current; the SLSA generator stays on its tag by
  design (`slsa-verifier` checks the builder id against the tag). The
  OpenSSF Scorecard workflow and Dependabot were added in this release.
- **Every product package meets its coverage target** — `cmd/acp-compute`
  (58% → 82%: the daemon's entry point run to a signalled stop, TLS to the
  vault verified and refused under another CA, the metric outcome of each
  error category), the Return Path client and server (69% and 65% → 87%
  and 81%: the refusals of both sessions driven from a raw peer —
  heartbeats out of turn, error envelopes, shutdowns before the job,
  frames of the wrong type, a reject, an accept for another manifest, an
  output bound to another session — and the worker's own reject on the
  wire for material it cannot open or a door that does not open), and the
  five contracts packages below 80% (every shape rule of their validators,
  what their signature verifiers refuse, the validation result's canonical
  bytes). `scripts/coverage_floors.txt` keeps only the total: no package
  is below its class target any more.
- **The documents say what is shipped.** Where the operator runbooks, the
  threat model, the positioning matrix, the supply-chain and compliance
  documents and the reference designs still said "Phase 2", "scaffolding"
  or "simulated only" of things that have since run on hardware — the
  SEV-SNP sealer, the three hardware backends, SBOM and cosign in the
  release, CodeQL and Semgrep in CI, `acpctl lineage` — they now say what
  is, with pointers to the evidence; what is still not done (Nitro, SGX,
  hermetic builds, two-party review, a pen-test, fuzzing) says so.

- `key_escrow_path` (`genome`, `crosscloud`) names the sealed escrow key
  `sagvd escrow-provision` writes; a raw 32-byte key from
  `acpctl escrow keygen` is accepted under `tee.insecure_simulation` only.
- `sagvd failover` loads the authority's keys, the escrow key among them,
  before it watches, so a key that will not open on this host is known
  before any trigger.
- The executor's choice of genome is bounded by the trigger record's last
  word (ADR 0017): generations after it are set aside.
- `acpctl recover` takes the 48-byte SEV-SNP launch measurement for a
  `gcp-sev-snp` envelope, as the chip reports it (it demanded 32 bytes).

- **`release_decision` is schema v2:** `ReasonTrustDenied` and an
  `attestation_id` field, so a denial at Trust Admission is a signed,
  recorded decision without a session. A v1 decision is a valid v2 decision.
- **`validation/service` records evaluated dimensions:**
  `ValidateInputs.Evaluated` carries semantic and behavioral verdicts from an
  evaluator that ran the model, with its name and detail in the
  `VALIDATION_DIMENSION_EVALUATED` payload.
- **`POST /v1/jobs` returns `request_id` and `state`, not
  `manifest_id`/`session_id`:** the session and the manifest are issued when a
  worker is admitted, and the job view carries them then. The Return Path
  audit payloads of a gate job are the flow's (`vault-genome/orchestration-audit/v1`)
  and the services'; the daemon's own `returnpath-audit/v1` payloads remain
  for refusals before a flow exists.
- **`acpctl audit query --json` embeds each event's payload** (`payload`, or
  `payload_base64` when it is not JSON), so a reader sees the decision's
  fields without a second tool.
- **`sagvd` and `acp-compute` name their TEE.** `tee.provider` and
  `tee.peer.provider` default to `simulated`, which still needs
  `tee.insecure_simulation: true`; a SEV-SNP pin without the AMD chain, or a
  simulated pin with one, is refused at start.
- **`POST /v1/jobs` names a genome instead of carrying a payload.** The body is
  `{"genome": {"bundle", "key_file"}, "deadline_seconds_from_now"}`;
  `manifest_id`, `session_id`, `expected_output_kind`,
  `expected_output_max_bytes` and `payload_base64` are gone from the request
  and the first three come back in the response, named by the authority. A
  job's output kind is always `bytes/fixed-length` and its size budget the
  exact size of the answer.
- `acp-compute` refuses to start without `genome.door.command`; there is no
  backend to fall back to.
- **[LICENSE](LICENSE) now carries the verbatim GNU AGPL-3.0 text.** It
  previously held only a short-form notice plus a scaffold note, so licence
  detection reported `NOASSERTION` and the repository appeared unlicensed to
  automated tooling. The licence itself is unchanged: AGPL-3.0-or-later, as it
  has been since [ADR-0003](docs/adr/0003-agpl-commercial-dual-licensing.md).
- **[`.github/CODEOWNERS`](.github/CODEOWNERS) now binds.** It previously listed
  placeholder handles that do not exist on GitHub, and prefixed every path with
  `/core/` although the repository root *is* `core` — so every rule was silently
  ignored and no file had an owner. Real handles, repository-relative paths, and
  the governance surfaces added since (failover, revocation, reconstruction,
  the claims documents).
- The repository description no longer says *"byte-exact regeneration of AI
  models across hardware"*. Our own measurement
  ([C6](VERIFIABLE-CLAIMS.md#c6)) shows byte-identical float inference across
  CPU and GPU is not achievable; the accurate ladder is EXACT on the pinned
  runtime, EQUIVALENT across devices with the error measured.

### Removed

- **The 40-probe byte-statistics library** (`internal/validation/behavioral/probes`)
  — it computed statistics on a raw blob, nothing imported it, and it could
  be mistaken for a behavioral evaluation of the model; the equivalence
  gate over a genome's fixtures is that evaluation (ADR 0011, 0013, 0015).
  KNOWN_ISSUES #3 is resolved by its removal.
- The placeholder reconstruction backends: the byte-level order-3 Markov
  chain (`internal/compute/worker/generative.go`) is deleted, and the SHA-256
  expansion (`reconstruction.go`) is no longer built into any binary — it
  remains a test fixture behind the frozen R-11 interface. KNOWN_ISSUES #2 is
  resolved; the skipped `TestGenerative_PartialGenomeDegradation` is gone with
  its backend.

## [0.1.0] — 2026-09-14

First public release. Four signed binaries (`sagvd`, `acpctl`,
`acp-bootstrap`, `acp-compute`) with cosign signatures and certificates, SPDX
SBOMs and SLSA provenance. Stage E, MVP maturity.

### Added

- **Genome v3 bundle format** — `magic ‖ header ‖ nonce prefix ‖ AES-256-GCM
  segments`, sealed under a fresh key that is not in the file, escrowed to the
  release authority at seal time. `acpctl genome seal / rewind / chain / verify`.
- **Attested self-restore across clouds** ([ADR-0011](docs/adr/0011-genome-v3-and-attested-self-restore.md))
  — the authority releases a genome's key only to an attested, allow-listed
  destination TEE; the destination restores the genome itself and signs a
  receipt with its TEE; the source verifies the receipt before recording the
  restore (`sagvd crosscloud-confirm`).
- **Sentinel and policy-driven failover** ([ADR-0012](docs/adr/0012-sentinel-and-policy-driven-failover.md))
  — `acpctl sentinel watch` checks tripwires before sealing each new generation
  with its key escrowed, and signs heartbeats; `sagvd failover` moves the last
  clean genome to the one standby an operator signed for in advance. One policy
  serial authorises at most one move; the operator stop list overrides any
  policy. Audit schema v6 adds `FAILOVER_DECIDED`, emitted before any key moves.
- **Equivalence gate and determinism ladder** ([ADR-0008](docs/adr/0008-equivalence-gate.md))
  — a signed EXACT / EQUIVALENT / FAIL verdict over sealed reference fixtures,
  trying `pinned-replay` first and falling through to `native-float` with the
  error measured, or failing closed.
- **Operator stop and recorded refusals** ([ADR-0010](docs/adr/0010-operator-stop-and-recorded-refusals.md))
  — a global halt that overrides every policy, with refusals written to the
  audit chain.
- **Real AMD SEV-SNP attestation**, verified to AMD ARK-Milan, on GCP and Azure.
- **Hardware drills** — [`gcp-drill`](scripts/hardware-test/gcp-drill) (fine-tune
  in a TEE, restore on L4 and Intel CPU),
  [`gcp-failover`](scripts/hardware-test/gcp-failover) (two SEV-SNP VMs,
  intrusion → failover), [`gpu-exact`](scripts/hardware-test/gpu-exact)
  (where CPU↔GPU float divergence enters a real model). Each boots its own VMs
  and deletes them on exit, including on failure.
- **Supply chain** — reproducible builds, syft SBOM, cosign keyless signing,
  SLSA generic provenance, and a release workflow that refuses any tag not
  signed by a key pinned on the default branch.
- **`vault-gate`** — 18 CI sub-checks, eleven doctrine invariants asserted as
  tests, and a coverage ratchet whose floors only rise.
- `acp-demo` — the cross-hardware regeneration demonstration in one command, no
  cloud and no TEE hardware required.

### Known limits at 0.1.0

Measured at 0.5B scale on CPU TEEs only; no attested GPU destinations; SEV-SNP
only (no TDX, Nitro or SGX verifier); `acp-compute`'s reconstruction backend is
a labelled placeholder; receive-side self-bootstrapping deferred to V2; no
external security review. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) and
[What we do not claim](VERIFIABLE-CLAIMS.md#what-we-do-not-claim).

[Unreleased]: https://github.com/vault-genome/vaultgenome-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vault-genome/vaultgenome-core/releases/tag/v0.1.0
