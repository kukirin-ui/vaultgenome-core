# Governance

How this project decides, who holds which role, and how it continues when
one person cannot. Short on purpose: the record of decisions is in
[`docs/adr/`](docs/adr/), the people in [`MAINTAINERS.md`](MAINTAINERS.md),
the rules a change must pass in [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/doctrine/`](docs/doctrine/).

## Roles

| Role | Who | Responsibilities |
| - | - | - |
| Maintainer (founder) | Serhii Nikolaichuk ([@Nikolaichuk7](https://github.com/Nikolaichuk7)) | Architecture, doctrine, cryptography and attestation; reviews every governed path; signs and publishes releases; answers security reports ([`SECURITY.md`](SECURITY.md)) |
| Maintainer (founder) | Rodion Sorokin ([@RodionSorokin1993](https://github.com/RodionSorokin1993)) | Engineering and verification, quality gates, drill validation; reviews every governed path; signs and publishes releases |
| Contributor | Anyone | Changes through pull requests under [`CONTRIBUTING.md`](CONTRIBUTING.md): signed commits, the Developer Certificate of Origin sign-off, the gate green |

Both maintainers triage issues and discussions, both can create, close and
label issues, accept pull requests and cut releases. There is no other
role: no committers without the maintainer role, no steering body above
the two maintainers.

## How decisions are made

- **Architecture and doctrine** are decided in an Architecture Decision
  Record under `docs/adr/` (24 so far): the question, the alternatives, the
  decision and its consequences. An ADR is a pull request like any other,
  reviewed by the other maintainer. Doctrinal invariants are asserted as
  tests in `test/doctrine/`, so a change that violates one fails the gate
  rather than waiting for a reviewer to notice.
- **Code** merges only through a pull request that passes the gate
  (`.github/workflows/vault-gate.yml`, 19 checks) and, on every governed
  path in [`.github/CODEOWNERS`](.github/CODEOWNERS), carries the review of
  both maintainers. `main` is protected: no direct pushes, signed commits
  only, required checks, conversations resolved.
- **Design changes** to a canonical contract, the orchestration state
  model, an operational validation, an authority decision or an export path
  start as a design document in `docs/designs/` with a maintainer's
  approval before code (`CONTRIBUTING.md`, "Design Changes").
- **Disagreement** between the two maintainers is resolved in the ADR's
  text: the alternative that loses is recorded with its reasons, so the
  decision can be reopened with new evidence rather than relitigated.
- **What is claimed** publicly is governed by
  [`VERIFIABLE-CLAIMS.md`](VERIFIABLE-CLAIMS.md): a claim exists only with
  the record that proves it, and the limits are listed beside the claims.

## Release authority

A release is a signed tag on `main`. The keys that may sign one are pinned
in [`.github/allowed_signers`](.github/allowed_signers), a governed file on
the default branch; `release.yml` refuses a tag not signed by a pinned key.
Adding or removing a signer is a pull request to that file under
CODEOWNERS review. Release binaries are signed keylessly in CI (cosign,
SLSA provenance), so no long-lived release key exists outside git.

## Continuity

The project must continue if either maintainer dies, is incapacitated or
withdraws. The arrangement:

- both maintainers are owners of the GitHub organisation `vault-genome`,
  so either can administer the repository, its settings and its secrets;
- both maintainers' signing keys are pinned in `allowed_signers`, so either
  can cut a release;
- both are required reviewers on governed paths; if one is unavailable for
  more than a week, the other may merge with the review requirement for the
  absent maintainer lifted for the duration, recorded in the pull request;
- the security contact ([`SECURITY.md`](SECURITY.md)) reaches both.

Within a week of confirmed loss of one maintainer, the other can therefore
create and close issues, accept changes and release. Copyright is held by
both founders ([`NOTICE`](NOTICE)); the licence (AGPL-3.0-or-later) does
not depend on either of them.

## Changing this document

By pull request, reviewed by the other maintainer, like everything else.

## State on 2026-10-14

| Arrangement | State |
| - | - |
| Serhii Nikolaichuk: organisation owner, signing keys pinned | in place |
| Rodion Sorokin: organisation owner and repository admin | in place since 2026-10-14 |
| Rodion Sorokin: signing key pinned in `allowed_signers` | in place since 2026-10-14 (ED25519, SHA256:Nlz+b7GRcQQLI+3BpUazq0WQmPtPPFuobFb9U0Pq5EA, also registered on his GitHub account) |
| Both maintainers required reviewers on governed paths (CODEOWNERS) | in place |
