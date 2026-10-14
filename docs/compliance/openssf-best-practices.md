# OpenSSF Best Practices badge — where each criterion is met

The [OpenSSF Best Practices badge](https://www.bestpractices.dev/) (passing
level) is a self-certification against published criteria, answered by a
maintainer and open to anyone's review. This page records, criterion by
criterion, where the repository meets each one, so a reviewer can check the
answers against the tree rather than take them on trust. Criteria text and
identifiers follow the badge's `criteria.md` (passing level) as of
2026-10-13. To earn the badge, every MUST is met, every SHOULD is met or
has its reason recorded, and every SUGGESTED is answered.

## Basics

| Criterion | Status | Where |
| - | - | - |
| description_good | Met | `README.md`, first paragraphs: what the software does and the problem it solves |
| interact | Met | `README.md` (obtain: Quickstart, Deploy; feedback: Contributing, security, license), `CONTRIBUTING.md` |
| contribution | Met | `CONTRIBUTING.md`: the pull-request process, branch and commit rules, the checks CI enforces |
| contribution_requirements (SHOULD) | Met | `CONTRIBUTING.md`: terminology, doctrine tests, Conventional Commits, signed commits, the pre-PR checklist |
| floss_license | Met | AGPL-3.0-or-later, `LICENSE` |
| floss_license_osi (SUGGESTED) | Met | AGPL-3.0 is OSI-approved |
| license_location | Met | `LICENSE` at the repository root; SPDX header in every Go file (`make license-headers`) |
| documentation_basics | Met | `README.md`, `docs/operator/00_overview.md`–`07_failover.md` |
| documentation_interface | Met | `docs/reference/cli.md` (every command and flag, generated from the binaries); the operator REST API and the Return Path in `docs/operator/` and `docs/spec/` |
| sites_https | Met | github.com, vaultgenome.com (HTTPS) |
| discussion | Met | GitHub issues and pull requests, searchable, no login to read |
| english (SHOULD) | Met | All documentation and code comments in English |
| maintained | Met | Releases v0.1.0–v0.3.2 in September 2026; the Unreleased section of `CHANGELOG.md` |

## Change control

| Criterion | Status | Where |
| - | - | - |
| repo_public, repo_track, repo_interim | Met | Public git repository; every change is a signed commit through a pull request |
| repo_distributed (SUGGESTED) | Met | git |
| version_unique, version_semver (SUGGESTED), version_tags (SUGGESTED) | Met | Semantic Versioning (`CHANGELOG.md` header); each release a signed tag (`vX.Y.Z`) |
| release_notes | Met | `CHANGELOG.md` (Keep a Changelog), linked from every GitHub release |
| release_notes_vulns | Met | The *Security* subsection of each release names the advisories fixed (the Unreleased entry lists GO-2026-6603 … 6617) |

## Reporting

| Criterion | Status | Where |
| - | - | - |
| report_process, report_tracker (SHOULD), report_archive | Met | GitHub issues (public, searchable); `SECURITY.md` for vulnerabilities |
| report_responses, enhancement_responses (SHOULD) | Met | Every issue filed to date has been acknowledged and resolved (see the closed issues) |
| vulnerability_report_process | Met | `SECURITY.md`: private advisory (enabled in the repository settings) or `security@vaultgenome.com` with the PGP key |
| vulnerability_report_private | Met | `SECURITY.md`: the private advisory form and PGP-encrypted email |
| vulnerability_report_response | Met | `SECURITY.md` promises acknowledgement within 72 hours and triage within 7 days; no vulnerability report has been received as of 2026-10-13 |

## Quality

| Criterion | Status | Where |
| - | - | - |
| build, build_common_tools (SUGGESTED), build_floss_tools (SHOULD) | Met | `Makefile` (`make build`), Go toolchain only; reproducible (`make verify-reproducible`) |
| test, test_invocation (SHOULD) | Met | `go test ./...` (`make test`); `python -m pytest` for the worker |
| test_most (SUGGESTED) | Met | Coverage thresholds per package enforced by `make coverage-thresholds` in the gate; mutation testing (`.github/workflows/mutation.yml`) |
| test_continuous_integration (SUGGESTED) | Met | `.github/workflows/vault-gate.yml` on every pull request and push to `main` |
| test_policy, tests_are_added, tests_documented_added (SUGGESTED) | Met | `CONTRIBUTING.md`: the pull-request checklist requires tests for new behaviour; recent changes carry theirs (see the merged pull requests) |
| warnings, warnings_fixed, warnings_strict (SUGGESTED) | Met | `go vet` and `golangci-lint` (`.golangci.yml`) in the gate; the gate fails on any finding |

## Security

| Criterion | Status | Where |
| - | - | - |
| know_secure_design, know_common_errors | Met | `docs/security/threat_model.md`, the ADRs, and the maintainers' own standards work on attestation protocols |
| crypto_published, crypto_floss | Met | X.509, ECDSA (P-256 for in-house keys; P-384 where a platform's certificates use it), Ed25519, X25519 (`crypto/ecdh`), AES-256-GCM (`internal/shared/crypto/gcm.go`), SHA-256/512 — all from the Go standard library; `golang.org/x/crypto/ocsp` for OCSP parsing |
| crypto_call (SHOULD) | Met | No in-house primitives; the in-house code is encoding (CBOR/COSE, OCSP request, SPDM report parsing), with the primitives called from the standard library |
| crypto_keylength, crypto_working, crypto_weaknesses (SHOULD) | Met | P-256/P-384, Ed25519, X25519, AES-256-GCM, SHA-256; nothing weaker is accepted by default |
| crypto_pfs (SHOULD) | Met | TLS 1.3 (Go `crypto/tls`) on the Return Path and the operator API |
| crypto_password_storage | N/A | The software stores no passwords of external users (mutual TLS and bearer tokens) |
| crypto_random | Met | `crypto/rand` for every key and nonce |
| delivery_mitm, delivery_unsigned | Met | HTTPS downloads; releases signed with cosign (keyless) and carrying SLSA Build Level 3 provenance; `README.md` § Verify a release |
| vulnerabilities_fixed_60_days, vulnerabilities_critical_fixed (SHOULD) | Met | `govulncheck` and OSV-Scanner in the gate; the Go toolchain and the worker's runtime raised on 2026-10-13 (`CHANGELOG.md`, `KNOWN_ISSUES.md` #14) |
| no_leaked_credentials | Met | `gitleaks` over the full history in the gate (`.gitleaks.toml`) |

## Analysis

| Criterion | Status | Where |
| - | - | - |
| static_analysis, static_analysis_common_vulnerabilities (SUGGESTED), static_analysis_often (SUGGESTED) | Met | CodeQL (`security-and-quality`) and Semgrep on every pull request (`.github/workflows/codeql.yml`, `semgrep.yml`) |
| static_analysis_fixed | Met | CodeQL alerts land in the repository's Security tab and are fixed before the next release (the nine `go/log-injection` findings of October 2026 are fixed in this tree); Semgrep runs report-only and its findings are triaged there |
| dynamic_analysis, dynamic_analysis_enable_assertions (SUGGESTED) | Met | Eight `Fuzz*` targets on the in-house parsers and encodings (two with committed seed corpora) run under `go test` in the gate; the race detector (`make test-race`) in the gate; tests with assertions enabled |
| dynamic_analysis_unsafe (SUGGESTED) | N/A | Go and Python only; no memory-unsafe language in the product |
| dynamic_analysis_fixed | Met | A fuzz or race finding fails the gate and is fixed before merge |
