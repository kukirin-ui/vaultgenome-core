<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# CI & supply-chain security policy

This document is the canonical description of what the `vault-gate` workflow
enforces and why. Section numbers are stable: other files cite them by number
(`scripts/dep_allowlist.txt` and `scripts/check_dep_allowlist.sh` → §3.1/§3.3,
`scripts/check_dep_depth.sh` → §3.2, `test/doctrine/` → §6,
`scripts/license_header_check.sh` → §7, `scripts/coverage_check.sh` → §8), so
renumber with care.

## 1. The gate

Every push and pull request to `main` runs `.github/workflows/vault-gate.yml`,
an 18-step gate; a merge is allowed only when all of it is green: format, vet,
build, unit tests, race detector, integration tests, coverage (§8), lint
(golangci-lint), terminology (§4), govulncheck (§5), osv-scanner (§5), gitleaks
(§10), SBOM (§6), license headers (§7), doctrine tests, dependency allowlist
(§3.1), dependency depth (§3.2), and reproducible build (§9). `make
vault-gate` runs 14 of them locally; integration tests, the SBOM and the
reproducible build have their own targets (`make test-integration`, `make
sbom`, `make verify-reproducible`), and osv-scanner runs only in CI.

## 2. Toolchain

The Go toolchain is pinned to an exact patch version in every workflow
(`go-version:` in the `actions/setup-go` step). It is bumped deliberately —
never floating — and a bump is a reviewed change like any other. The trigger to
bump is §5: when govulncheck reports a standard-library advisory, the pin moves
to the first patch release that fixes it. `go.mod`'s `go` directive is the
*minimum language version* the source needs; the workflow pin is the *exact
build toolchain*, and the two are allowed to differ.

## 3. Dependencies

The design keeps the dependency surface tiny and legible. Two machine checks
enforce that.

### 3.1 Direct-dependency allowlist

Every **direct** module dependency must appear on `scripts/dep_allowlist.txt`,
enforced by `scripts/check_dep_allowlist.sh`. "Direct" is read from
`go mod edit -json` (`Indirect == false`) — the machine-readable form of the
`// indirect` marker — so the check is exact under vendoring and module-graph
pruning. Adding an entry requires §3.3.

Indirect (transitive) dependencies are **not** listed here; they are governed
by the depth cap in §3.2 instead. Listing them would be noise and would defeat
the point of a *direct*-dependency allowlist.

### 3.2 Transitive depth cap

`scripts/check_dep_depth.sh` bounds the longest path in the module graph. The
cap is **3**. A dependency that drags in a deep transitive chain fails the gate
and must be replaced or justified with an explicit exception. This keeps the
"what am I actually trusting" answer short.

### 3.3 Justification records

Each allowlisted direct dependency carries a short justification at
`docs/dependencies/<module>.md` — why it is needed, what it is trusted to do,
and the sign-off of both founders on the pull request that introduced it.

## 4. Terminology

The terminology gate (`scripts/terminology_check.sh`) enforces the frozen
project-name rename; see `docs/doctrine/terminology.md`. §4 there lists the
enforced deprecated names; §5 there lists advisory vocabulary that is documented
but deliberately not gated.

## 5. Vulnerability scanning

Two scanners run on every gate:

- **govulncheck** — call-graph aware. It fails only on advisories the code can
  actually reach, across both module dependencies and the standard library,
  in the root module and in the one helper module with its own go.mod and
  go.sum (the AWS Nitro kit's `vsock-attest`). A reachable stdlib advisory is
  fixed by the toolchain bump of §2.
- **osv-scanner** — presence-based over the same two dependency manifests. It fails on a
  known-vulnerable dependency version regardless of reachability, the stricter,
  defence-in-depth complement to govulncheck. One exception is allowed, and
  only in the open: an advisory that no release of the dependency fixes, for
  a package the module does not import (`go mod why`; govulncheck: required,
  not called), may be ignored by id in `osv-scanner.toml` with the reason and
  an expiry date — the expiry re-asks the question.

A repository that ships defensive infrastructure does not ship a dependency or
a toolchain with a known, fixed advisory it could have taken.

## 6. Supply-chain attestation

Releases are built by `.github/workflows/release.yml`, triggered by a
`v*.*.*` tag. Before anything is built the tag's signature is verified against
the maintainer keys pinned on the default branch (`.github/allowed_signers`,
`.github/release-signing-keys.asc`) — never against keys in the tagged tree —
and a tag that does not verify produces no release. Every released binary
(`sagvd`, `acp-compute`, `acpctl`, `acp-bootstrap`) carries three attestations:

- an **SBOM** in SPDX-JSON, produced per artifact by **syft**;
- a **cosign** keyless signature (`sign-blob`) with a transparency-log entry;
- **SLSA** provenance from the `slsa-framework` generic generator.

`test/doctrine/` asserts, offline, that the release workflow still names all
three pillars, so dropping one trips CI.

## 7. License headers

Every source file carries an `SPDX-License-Identifier: AGPL-3.0-or-later`
header, enforced by `scripts/license_header_check.sh`. A file without it fails
the gate. This keeps the licence unambiguous at the granularity of a single
file, however the code is later copied or vendored.

## 8. Coverage thresholds

`scripts/coverage_check.sh` enforces a minimum test-coverage floor on every
product package (`internal/`, `cmd/`, `pkg/`). Coverage is a floor, not a
target: it guards against a change that silently drops code out of the tested
set, and it is read alongside the doctrine tests (which assert behaviour, not
lines).

How it is measured. `make coverage` runs the whole suite with
`-coverpkg=./...`, so a statement counts as covered when *any* test in the
module executes it — a package exercised through another package's tests gets
credit for that. Each statement is counted once however many test binaries
report it, and packages are weighted by statements, not by function (averaging
per-function percentages would let a dozen one-line helpers hide one untested
thousand-line file).

What is required. Each package reaches its class target:

| Class | Target |
|---|---|
| `internal/contracts/...` (wire contracts) | 80% |
| `internal/validation/operational/...` | 90% |
| `internal/vault/orchestration/...` | 85% |
| every other product package | 70% |

Packages still below target are listed in `scripts/coverage_floors.txt` with the
floor they may not drop below. The file is a ratchet: floors are only ever
raised, a package leaves it once it meets its target, and a new package cannot
enter below target without a reviewed entry. The same file holds the floor for
the product total. The gate prints the full table on every run, so progress on
the listed packages is visible in each CI log.

## 9. Reproducible builds

`make verify-reproducible` builds every binary twice, from a clean tree, with
identical flags (`-trimpath`, empty `-buildid`, pinned `-ldflags`), and fails if
the two outputs are not byte-identical. This catches embedded timestamps,
build-path leakage, and other non-determinism before a release is signed.

## 10. Secret scanning

`gitleaks` scans the tree and history for credentials on every gate. The only
secret-shaped material committed on purpose is public AMD KDS certificate chains
(X.509 certificates, not keys) used as offline attestation-verification
fixtures; everything else that looks like a secret is treated as an incident.
