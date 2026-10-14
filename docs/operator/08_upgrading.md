# Upgrading

Which releases are supported, what changed between them that an operator
has to act on, and how to move a deployment from one to the next. The
per-release facts come from [`CHANGELOG.md`](../../CHANGELOG.md), whose
"Compatibility" paragraphs are the authority; this page is the operator's
index of them.

## What is supported

While the major version is 0, the latest release is the supported one:
fixes land on `main` and ship in the next release, nothing is backported
to an older minor. An operator on an older release upgrades along this
page; the formats below make that a binary swap so far, not a migration.

## The compatibility ledger

| Release | Bundle format | Audit schema | Policy schema | What an operator must know |
| - | - | - | - | - |
| 0.1.0 (2026-09-14) | genome v3 | v6 | v1 | first release; `release_decision` schema v1 |
| 0.2.0 (2026-09-17) | v3, unchanged | v6, unchanged; two new optional payload fields (`peer_detail`, `destination_detail`) | unchanged | `release_decision` is schema v2, a v1 decision is a valid v2 decision. New config fields are optional (`tee.sev_guest_device`, `tee.vtpm_seal_pcrs`, `gpu_policy.revocation`, `gpu_policy.ocsp_url`, `runtime.max_payload_bytes`); `gpu_policy.evaluation: "own"` is admitted. Key files may be sealed (`vault-genome/sealed-secret/v1`), bare files still load. **Return Path frame cap 16 MiB → 128 MiB: both ends of a Return Path must run 0.2.0 or later for a genome over 16 MiB.** Go directive 1.26. |
| 0.2.1 (2026-09-17) | unchanged | unchanged | unchanged | fixes only |
| 0.3.0 (2026-09-17) | unchanged | unchanged | unchanged | the code of 0.2.1 under the module path `github.com/vault-genome/vaultgenome-core`: `go install` paths change, nothing else. The 0.3.0 tag has no release assets (the pipeline failed on it; the tag stays, 0.3.1 explains) |
| 0.3.1, 0.3.2 (2026-09-17) | unchanged | unchanged | unchanged | release pipeline fixes; signatures on cosign 2.x (`KNOWN_ISSUES.md` #15) |
| 0.4.0 (2026-10-14) | unchanged | unchanged | unchanged | Go 1.27.2; the worker's Python runtime is torch 2.14.1 / transformers 5.19.0, installed by hash from two locks; the integer door reads a config's rotary base with no default. A deployment that raises the worker runtime re-measures its fidelity record before it relies on EXACT (`KNOWN_ISSUES.md` #14) |

No release so far has changed the bundle format, the audit schema or the
policy schema: a genome sealed by 0.1.0 is a valid 0.4.0 genome, an audit
chain written by 0.1.0 verifies under 0.4.0, a policy file from 0.1.0
loads. Where the two sides of a wire must agree, the ledger says so (the
Return Path cap in 0.2.0).

## How to upgrade a deployment

1. **Read the release's Compatibility paragraph** in `CHANGELOG.md` and
   the ledger row above; note any wire requirement that binds the two ends.
2. **Verify the release** before it runs anywhere: the signatures, SBOMs,
   provenance and tag, as in the README's "Verify a release"
   ([`05_release_procedure.md`](05_release_procedure.md) §5).
3. **Upgrade the deployment in one window**: `sagvd`, `acp-compute`,
   `acp-bootstrap` and `acpctl` are released together and tested
   together; the Return Path is the one wire contract between the
   authority and its workers, and its compatibility across releases is
   stated in the ledger, not assumed. Stop accepting jobs, let the queue
   drain, replace the binaries (or the images), start the authority, then
   the workers.
4. **Run the preflight** ([`01_preflight.md`](01_preflight.md)) against
   the upgraded deployment before relying on it.
5. **Confirm the record continues**: the audit chain verifies across the
   upgrade boundary ([`04_observability.md`](04_observability.md)), and a
   genome sealed before the upgrade opens after it.

Going back is the same procedure with the previous release's verified
binaries; the formats being unchanged, nothing written by the newer
release is unreadable by the older one except where the ledger says
otherwise.

## When a format changes

A release that changes the bundle format, the audit schema or the policy
schema will say so in its Compatibility paragraph with the migration
steps, and this page's ledger will carry the row. Until then, this
section is empty on purpose.
