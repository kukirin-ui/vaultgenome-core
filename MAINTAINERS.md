# Maintainers

How decisions are made, who holds which role and how the project continues
without either founder is in [GOVERNANCE.md](GOVERNANCE.md).

This project is built by two founders. Both hold copyright in the codebase
(see [NOTICE](NOTICE)); both are required reviewers on every doctrine-frozen
surface (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).

| Founder | GitHub | Role |
| - | - | - |
| **Serhii Nikolaichuk** | [@Nikolaichuk7](https://github.com/Nikolaichuk7) | Architecture, doctrine, cryptography and attestation, release authority |
| **Rodion Sorokin** | [@RodionSorokin1993](https://github.com/RodionSorokin1993) | Engineering and verification, quality gates, drill validation |

## Release authority

Release tags are signed, and the signing key is **pinned on the default
branch** in [`.github/allowed_signers`](.github/allowed_signers). The release
workflow refuses any tag not signed by a pinned key
([`.github/workflows/release.yml`](.github/workflows/release.yml)), so the set
of people who can cut a release is a reviewable file in git rather than a
setting in a web console.

Adding or removing a signer is a change to `allowed_signers` on the default
branch, which requires review under CODEOWNERS like any other governed file.

## Decision record

Architecture decisions are recorded, not remembered. Twelve ADRs under
[`docs/adr/`](docs/adr/) carry the reasoning, the alternatives considered and
the accepted trade-offs; eleven doctrinal invariants are asserted as tests in
[`test/doctrine/`](test/doctrine/) so that a change violating one fails CI
rather than relying on a reviewer noticing.

## A note on commit history

Commit authorship in this repository reflects who typed into the working tree,
not who owns the work. Much of the design, review and verification happened
away from the keyboard that produced the commits, and we are not going to
retrofit history to make a contribution graph look tidier — a repository whose
git history has been edited for appearances is worth less to anyone evaluating
it, not more.

Ownership is established by [NOTICE](NOTICE), the founders' assignment
agreements, and this file.

## Security contact

Vulnerabilities go to the private channel in [SECURITY.md](SECURITY.md), never
to a public issue. See also [CONTRIBUTING.md](CONTRIBUTING.md).
