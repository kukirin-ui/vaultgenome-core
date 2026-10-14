# Assurance case

Why the security requirements of this software are met, with the argument
laid out so it can be checked: the requirements, the threat model and
trust boundaries, the design principles and where each is applied, the
common implementation weaknesses and what counters each, and what is left
over. Every claim here points at a file in the tree, a test that fails
when the claim stops being true, or a record under
[`VERIFIABLE-CLAIMS.md`](../../VERIFIABLE-CLAIMS.md). Where the argument
is weak, it says so.

## 1. Security requirements — what a user can and cannot expect

The product is the authority daemon `sagvd`, the in-TEE worker
`acp-compute`, the bootstrap `acp-bootstrap`, the operator CLI `acpctl`
and the Python worker under `workers/genome`. A user can expect:

1. **A sealed genome is confidential and its integrity is checked on open.**
   Genome v3: AES-256-GCM segments under a fresh key that is not in the
   file; a single flipped byte is refused with an authentication failure
   ([C2](../../VERIFIABLE-CLAIMS.md#c2), the tamper step of every kit).
2. **A genome's key is released only to an attested, allow-listed
   destination.** The authority verifies the destination TEE's evidence
   against the operator's policy before any key moves, and records the
   decision first ([C8](../../VERIFIABLE-CLAIMS.md#c8),
   [C14](../../VERIFIABLE-CLAIMS.md#c14), ADR 0011).
3. **What was restored is what was sealed, and the verdict is signed.** The
   equivalence gate's EXACT / EQUIVALENT / FAIL verdict is a signed object
   over sealed reference fixtures ([C16](../../VERIFIABLE-CLAIMS.md#c16),
   [C19](../../VERIFIABLE-CLAIMS.md#c19), ADR 0008).
4. **Every decision is on an append-only, hash-chained record** that a
   third party can verify after the fact
   ([`04_observability.md`](../operator/04_observability.md)).
5. **The binaries are what the source says.** Reproducible builds,
   keyless signatures and SLSA Build Level 3 provenance on every release
   ([C11](../../VERIFIABLE-CLAIMS.md#c11),
   [`supply_chain.md`](supply_chain.md)).

A user cannot expect: protection against a compromised TEE vendor or an
undisclosed hardware side channel; attestation of AWS Nitro or SGX inside
the product (the Nitro and SGX kits validate with their own tooling and
the product claims neither — [`VERIFIABLE-CLAIMS.md`, "What we do not
claim"](../../VERIFIABLE-CLAIMS.md#what-we-do-not-claim)); resistance to a
quantum adversary; or safety against an operator who signs a bad policy.
The limits are listed with the claims and in
[`KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md).

## 2. Threat model and trust boundaries

The threat model is [`threat_model.md`](threat_model.md): STRIDE per
platform and for the control plane, each threat with its mitigation
mapped to a control in [`../compliance/crosswalk.md`](../compliance/crosswalk.md).
The trust boundaries, named once here so the rest of the argument can
refer to them:

| Boundary | What crosses it | What guards it |
| - | - | - |
| B1 Operator ↔ authority (`acpctl`, REST API ↔ `sagvd`) | job submissions, policy, operator identity | mutual TLS 1.3 only (`MinVersion: tls.VersionTLS13` in every daemon, no `InsecureSkipVerify` anywhere), bearer token, ACL, audit of every call |
| B2 Authority ↔ worker (`sagvd` ↔ `acp-compute`, the Return Path) | attestation evidence, sealed material, candidate outputs, validation verdicts | TEE attestation in the handshake, worker registry pinning the measurement, every frame validated by `recvvalidator` before use, verdicts signed |
| B3 Worker ↔ hardware (`acp-compute` ↔ `/dev/sev-guest`, vTPM, GPU) | measurements, reports, sealed keys | the platform's own attestation and sealing; the product reads reports, it does not trust the host |
| B4 Authority ↔ its storage (audit log, keystore) | audit events, keys at rest | append-only bbolt with a hash chain; keys sealed at rest, redacted in logs |
| B5 Source ↔ binary (the build and release) | the code, its dependencies, the toolchain | pinned toolchain and actions, reproducible builds, keyless signing, SLSA provenance, signed tags with pinned signers |

Assets: session secrets, model weights, the audit chain, attestation
evidence, sealed material, the signing keys of releases. The residual
risks accepted at each boundary are the threat model's "Cross-platform
residual risks" table.

The threat model was reviewed on 2026-10-14 ([`review-2026-10.md`](review-2026-10.md));
the review of 2026-08-06 had not been held, and the record says so.

## 3. Secure design principles, and where each is applied

| Principle | Where it is applied | What fails if it is dropped |
| - | - | - |
| **Fail-safe defaults** — refuse unless proven | every contract has refusal tests: a bootstrap manifest, a reconstitution decision, a continuity proof with a dangling parent, an unknown derivation or a bad signature is refused, not repaired (`internal/contracts/*/..._refusals_test.go`, `continuity_proof_gates_test.go`) | the refusal tests |
| **Least privilege** | `sagvd` can issue jobs but cannot run worker code; workers attest into the authority, never the reverse; CI tokens are read-only at the workflow level and jobs name what they need; containers run as non-root from distroless images | Scorecard Token-Permissions; the compose files |
| **Complete mediation** | every Return Path frame goes through `recvvalidator` before any field is used; every key release passes the policy and is recorded before it moves (`FAILOVER_DECIDED` precedes the move) | doctrine invariants in `test/doctrine/` |
| **Economy of mechanism** | cryptography is the Go standard library only (Ed25519, ECDSA P-256/P-384, X25519, AES-256-GCM, SHA-256/512); the in-house code is encoding, not primitives; three direct dependencies, depth-limited (`scripts/check_dep_allowlist.sh`, `check_dep_depth.sh`) | the gate's allowlist and depth checks |
| **Separation of privilege** | a genome's key is escrowed to the authority at seal time and released only against attestation plus policy; two maintainers review every governed path (`CODEOWNERS`), two signers can cut a release once both keys are pinned (`GOVERNANCE.md`) | branch protection, `allowed_signers` |
| **Open design** | the design is in 24 ADRs; what is claimed is in `VERIFIABLE-CLAIMS.md` with the records; anyone rebuilds the binaries byte for byte (`make verify-reproducible`) | the claims register, the reproducible-build check |
| **Defence in depth** | TEE attestation and policy and signed verdicts and the audit chain, each checkable without the others | — |
| **Psychological acceptability** | `acpctl` prints what it refused and why; the preflight page says what to check before relying on a deployment | — |

## 4. Common implementation weaknesses, and what counters each

| Weakness class | Counter | Where it is enforced |
| - | - | - |
| Memory safety (overflows, use-after-free) | Go throughout the product; `CGO_ENABLED=0`; no C in the shipped binaries (the C in the tree is an SGX measurement kit, not shipped) | the build; `dynamic_analysis_unsafe` is N/A for the product |
| Untrusted input (parsers, encodings, wire frames) | allow-list validation of every frame and contract; eight fuzz targets on the in-house parsers and encodings with committed seed corpora, run in the gate; the race detector on every test package | `go test` in the gate; `make test-race` |
| Injection (logs, commands, paths) | structured `slog` with `LogValuer` redaction; the nine `go/log-injection` CodeQL findings of 0.4.0 fixed; no shell-outs in the product | CodeQL `security-and-quality` and Semgrep on every pull request |
| Cryptographic misuse | standard-library primitives only; fresh keys and nonces from `crypto/rand`; AAD-bound sealing; TLS 1.3 only with certificate verification on by default; constant-time comparison (`crypto/subtle`) where secrets are compared | code review on governed paths; the refusal tests |
| Secrets in logs, files or exports | `LogValuer` redaction; doctrine invariant `TestInvariant_07_NoRawExport` rejects any write sink outside the allow-list; gitleaks over the full history in the gate | `test/doctrine/`; the gate |
| Vulnerable dependencies | govulncheck (reachability) and osv-scanner (presence) on the product module and the Nitro kit's helper module, Dependabot for Go, actions and pip; the one ignored advisory has its reason and an expiry (`osv-scanner.toml`) | the gate, every pull request |
| Supply chain of the build | toolchain and every action pinned by commit, container images by digest, Python wheels by hash; SBOM, keyless signatures and SLSA provenance on every release; signed tags with the signers pinned in git | `release.yml`; `docs/security/supply_chain.md` |
| Concurrency errors | the race detector on every package in the gate | `make test-race` |
| Insufficient testing | statement coverage held at thresholds per package and 90 % overall by the gate; mutation testing workflow; doctrine invariants as tests | `scripts/coverage_check.sh`; `mutation.yml` |
| Silent drift between documentation and code | the CLI reference is generated from the binaries; every claim cites its record; documentation defects are fixed as bugs | `make cli-reference`; `VERIFIABLE-CLAIMS.md` |

## 5. What this argument does not cover

- The TEE vendors' silicon and firmware, and side channels not yet
  public: accepted residual risks, with the compensating controls in the
  threat model's table.
- The Python worker's runtime (torch, transformers): installed by hash
  from locks and scanned, but its own code is outside this argument except
  for how the product loads it (local files only, no remote code).
- A malicious maintainer: two maintainers review governed paths and the
  build is reproducible, which lets a buyer check; it does not prevent a
  colluding pair.
- The hardware kits under `scripts/hardware-test/`: they measure, they are
  not the product, and their scripts are held to a lower bar (unpinned
  installs are listed in the Scorecard findings and not hidden).

## 6. Maintenance

This case is reviewed with the threat model, and whenever a boundary in
§2 changes (a new TEE backend, a new network listener, a new key release
path), as part of the ADR that changes it.
