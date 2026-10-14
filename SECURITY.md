# Security policy

Vault Genome takes the security of its codebase, releases, and
deployments seriously. This document explains how to report a
vulnerability and what to expect from us.

## Threat model (short form)

The AI Continuity Platform is defensive infrastructure designed to
operate in environments where:

- Physical data centres may be destroyed.
- Network paths may be actively disrupted or observed.
- Some operator accounts, build runners, or dependencies may be compromised.
- An adversary may attempt to coerce disclosure of the AI Genome
  through technical, social, or legal means.

The security posture is governance-first: the **Vault** is the sole
authority on every continuity-relevant decision; sessions are
mandatory; disclosure is always staged; validation must precede any
release. A compromise that weakens any of those invariants is, by
our own definition, critical.

See `docs/internal/stage-a-summary.md` §2 (private repo) and the public
[`docs/security/threat_model.md`](docs/security/threat_model.md) for
the enumerated doctrinal invariants that security review must protect.

The assurance case, the argument for why the security requirements are met
with the trust boundaries, the design principles and the countered weakness
classes, is [`docs/security/assurance_case.md`](docs/security/assurance_case.md).

## Supported versions

We accept security reports against:

- The `main` branch of this repository.
- Every released version listed at
  [GitHub Releases](https://github.com/vault-genome/vaultgenome-core/releases).

Out of supported scope:

- Forks we don't maintain.
- Build environments that bypass the reproducible-build flow
  documented in [`docs/security/supply_chain.md`](docs/security/supply_chain.md).
- Customer-side deployments where the customer has modified our code
  (escalate via the customer's security team first; if the issue
  reproduces against our published binaries, escalate to us per the
  reporting process below).

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for security reports.**
Public disclosure before a patch is available exposes every running
deployment to the very attack we're trying to prevent.

Use one of the following private channels in order of preference:

1. **GitHub private security advisory** — preferred.
   Visit https://github.com/vault-genome/vaultgenome-core/security/advisories/new
   and create a draft advisory. This is the most secure channel; only
   the project maintainers see the report.

2. **Email** — `security@vaultgenome.com`. Encrypt with our PGP key
   (fingerprint listed below); plain-text email is acceptable but
   the GitHub channel above is preferred. The key file lives at
   `docs/security/pgp_key.asc` once first generated.

3. **Signal** — operationally for time-sensitive issues only;
   request the number through the email channel first.

### What to include

The most useful reports answer:

- **What is the vulnerability?** (a sentence or two)
- **Which component is affected?** (file path, function name, or
  CVE-style identifier such as "AWS Nitro adapter signature
  verification")
- **Affected commit SHA or release tag.**
- **How does an attacker exploit it?** (proof-of-concept input,
  attacker capabilities, prerequisites)
- **What is the impact?** (read access? write access? privilege
  escalation? denial of service? bypass of which doctrinal
  invariant?)
- **Suggested mitigation, if you have one** (optional)
- **Your preferred disclosure timeline** (optional)

A reproducer that runs against `make test` is gold; we'll work back
from a vague description but it slows us down.

## What to expect

We commit to:

- **Acknowledgement** within **72 hours**.
- **First triage assessment** within **7 days** — whether we accept
  the report, whether it's a duplicate, whether it falls within our
  supported scope.
- **Remediation target** based on severity:
  - **CRITICAL** (breaks a doctrinal invariant): **14 days**
  - **HIGH** (breaks a guarantee within a doctrinal invariant):
    **30 days**
  - **MEDIUM**: scheduled into the next release window
  - **LOW**: best-effort
- **Credit** for the discoverer in the published advisory unless
  they request otherwise.
- **Coordinated public disclosure** — 90-day window by default;
  earlier acceptable if the vulnerability is already being actively
  exploited and silence would harm users more than disclosure.

### What you should NOT expect

- **Bug bounty payments.** We do not currently run a paid bounty
  programme. Our gratitude is genuine but unmonetised.
- **Same-day patches** except for CRITICAL severity issues with
  active exploitation.
- **Coverage of vulnerabilities in third-party dependencies.** Those
  go through the upstream maintainer's process; our SBOM (`make sbom`)
  lists every dependency so you can find the right upstream. We
  track upstream security advisories via `govulncheck` + `osv-scanner`
  on every CI run.

## Severity classification

We use the [CVSS v3.1](https://www.first.org/cvss/specification-document)
calculator with the following project-specific guidance:

| Severity  | Examples                                                                 |
|-----------|--------------------------------------------------------------------------|
| CRITICAL  | RCE in `sagvd` exposed via the public HTTP API; bypass of TEE attestation; key extraction from `internal/vault/keys`; audit-chain forgery undetected by `acpctl audit verify` |
| HIGH      | DoS that crashes `sagvd` from a single attacker request; bypass of one or more validation gates; unauthorised cross-tenant key access; release decision short-circuit |
| MEDIUM    | Information disclosure via timing side-channels; bypass of one validation stage but caught by another; rate-limit bypass; predictable secret leakage in logs |
| LOW       | Hardening missed (e.g. weak default config); operational hygiene gaps; missing depth-of-defence checks |

A doctrinal-invariant violation always rounds UP one severity level;
e.g., a "MEDIUM by CVSS but breaks Invariant 7" is treated as HIGH.

## Scope

### In scope

- All Go code in this repository: the daemons (`sagvd`, `acp-compute`,
  `acp-bootstrap`), the CLIs (`acpctl`, `acp-demo`), the `internal/`
  packages and the public `pkg/teeconformance` package.
- Container images built from `Dockerfile` and `deploy/compose/`.
- The CI workflows under `.github/workflows/` (a vulnerability there
  could compromise the supply chain — treat as CRITICAL).
- Cosign signing flow + SLSA provenance generation.
- The evidence-capture tooling under `scripts/hardware-test/` (not
  shipped, but it provisions cloud resources and handles attestation
  material).

### Out of scope

- The simulated TEE backend (`internal/shared/tee/simulated.go`) is
  explicitly NOT a real TEE; reports of "the simulated TEE doesn't
  resist hardware attacks" will be politely declined. Production
  deployments must use a real-hardware backend.
- Vulnerabilities in third-party services we integrate with (AWS,
  Microsoft, Google, Intel, AMD, sigstore Rekor). Report those to
  the respective vendor.
- Issues that require physical access to the host running Vault
  Genome (deployment / facility concern, not a code defect).
- Theoretical cryptographic weaknesses in the underlying primitives
  (Ed25519, AES-256-GCM, SHA-256). We follow the NIST consensus on
  these; if NIST deprecates a primitive, our migration plan is in
  the relevant ADR.
- Vulnerabilities in Go itself or its standard library (we track
  these via `govulncheck` and patch on the next release).
- Denial-of-service caused by legitimate heavy load in non-production
  environments.
- Social-engineering attacks against individual contributors (please
  still tell us so we can warn the team, but treat as informational
  rather than a CVE).

## PGP key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

[Public key to be generated and published at
docs/security/pgp_key.asc on first public release. Until then,
please use the GitHub private security advisory channel — it
provides equivalent confidentiality.]

-----END PGP PUBLIC KEY BLOCK-----
```

Fingerprint: `[to be filled in once the key is generated]`

## Supply-chain assurance

Every released binary is signed with `cosign` against a Sigstore
public transparency log. Every release ships an SBOM generated by
`syft`. SLSA Level 2 today; Level 3 tracked by the
`make verify-reproducible` CI sub-check. See
[`docs/security/supply_chain.md`](docs/security/supply_chain.md) for
the full attestation stack and exact verification commands a buyer
or auditor can run.

If you observe an unsigned or mis-signed release artefact, treat it
as a CRITICAL incident and report it per the instructions above.

## Hall of thanks

(Empty as of 2026-05-06. We add discoverers here on coordinated
disclosure unless they request otherwise.)

## Versioning of this document

This file is part of the source tree under AGPL-3.0-or-later. Material
changes to the disclosure process are reviewed quarterly alongside
the threat model. The current version corresponds to the commit hash
on `main` at the time you're reading it.
