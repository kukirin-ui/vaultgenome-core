# Release Procedure

**Audience:** release engineer, administrator.
**Purpose:** the procedure for cutting a signed release with supply-chain
evidence (SBOM + SLSA provenance + signed tag + cosign signatures), as
`.github/workflows/release.yml` implements it.

**What a release contains.** `release.yml` builds with `make build` (five
binaries: `sagvd`, `acp-compute`, `acpctl`, `acp-bootstrap`, `acp-demo`) and
signs, SBOMs and publishes the four operational ones: `sagvd`, `acp-compute`,
`acpctl` and `acp-bootstrap`, the cross-cloud destination daemon. `acp-demo`
is not published.

**Related doctrine:** `docs/doctrine/ci-security-policy.md` §6 (supply-chain
attestation), invariant #11 "supply chain attested".

---

## 1. Prerequisites

Before any release step runs, the following must already be true:

1. The vault-gate workflow is green on the exact commit you intend to tag.
   CI runs all 18 checks on every push to `main`; `make vault-gate` runs 14 of
   them locally (see §2).
2. The release notes draft names every doctrine change, every invariant
   change, and every dependency change since the prior tag.
3. You hold a key that can sign the tag (`git tag -s`), and its public half is
   pinned on the default branch: an SSH key as a line of
   `.github/allowed_signers` (`<principal> ssh-ed25519 AAAA…`), or an OpenPGP
   key in `.github/release-signing-keys.asc`.

`release.yml` has no approval gate: pushing any tag that matches `v*.*.*`
starts it. Review happens before the tag, on the pull requests that land the
changes; who may push tags is a repository permission, not part of the
workflow.

---

## 2. Pre-release checklist

| Item | Command | Pass criterion |
| - | - | - |
| Clean working tree | `git status` | No uncommitted changes |
| Local gate green | `make vault-gate` | Exit 0, `vault-gate: PASS` |
| CI-only checks | `make test-integration && make verify-reproducible` | Both exit 0 (osv-scanner runs only in CI) |
| SBOM generable | `make sbom` | `dist/sbom.spdx.json` present, non-empty |
| Deps within policy | `make dep-allowlist && make dep-depth` | Both exit 0 |
| Doctrine clean | `make test-doctrine` | Every `TestInvariant_NN` passes, including `TestInvariant_11_SupplyChainAttested` |
| Runbook current | Review `docs/operator/` for drift from the code | Every command, flag and path named still exists |

---

## 3. Tagging

Tags are `vMAJOR.MINOR.PATCH` per the project's version scheme. For the
first MVP tag the sequence is:

```
git tag -s v0.1.0 -m "MVP — release-side doctrine-closed, 11/11 invariants enforced"
git push origin v0.1.0
# 0.2.0 followed the same steps on 2026-09-17 (tag message: the CHANGELOG's intro)
```

The workflow's first step after checkout runs `git verify-tag` on the tag and
stops the release if it fails, so an unsigned tag produces no release. The keys
it accepts are read from the default branch — `.github/allowed_signers` for SSH
signatures, `.github/release-signing-keys.asc` for OpenPGP — never from the
tagged tree, which whoever pushed the tag controls. A tag signed by any other
key produces no release either.

---

## 4. The release.yml workflow

The tag push runs `.github/workflows/release.yml`:

1. Check out the tag and run `git verify-tag` on it against the keys pinned on
   the default branch.
2. Set up Go 1.27.2 (the toolchain `go.mod` names).
3. `make build` and `make verify-reproducible`, with `VERSION` = the tag name,
   `COMMIT` = the full commit SHA and `SOURCE_DATE_EPOCH` = the tagged commit's
   timestamp.
4. `syft`: one SPDX-JSON SBOM per published binary,
   `dist/<binary>.sbom.spdx.json`.
5. `cosign sign-blob` (keyless): a signature and certificate for each binary
   (`dist/<binary>.sig`, `.cert`) and for each SBOM (`.sbom.sig`,
   `.sbom.cert`).
6. Upload `bin/sagvd`, `bin/acp-compute`, `bin/acpctl`, `bin/acp-bootstrap`,
   the SBOMs, signatures and certificates to the GitHub Release.
7. A second job runs the SLSA generic generator
   (`slsa-framework/slsa-github-generator`, `generator_generic_slsa3.yml`
   v2.1.0) over the four binaries' SHA-256 and uploads the provenance to the
   release.

`TestInvariant_11_SupplyChainAttested` does not run in `release.yml`; it runs
with the doctrine tests in vault-gate. It reads `release.yml` and fails if the
workflow no longer names `syft` and `spdx-json`, `cosign` `sign-blob`, the
SLSA generator, the `v*.*.*` trigger, `verify-tag`, or the four binaries — so
a change that drops a pillar cannot merge. It does not run the workflow.

---

### 4.1 Rehearsal after a change to release.yml

`release.yml` runs only on a tag, so a pull request cannot exercise it.
After any change to the workflow or to the actions it pins (a Dependabot
bump included), run the pipeline on a signed rehearsal tag before the
real one: `vX.Y.Z-rcN` on the merge commit, verified like a release (§5),
then delete the rehearsal's GitHub release and keep the tag. The Go module
proxy may already have served the tag, and a tag that was once public is
never moved or deleted (0.3.0 in the CHANGELOG is the lesson). 0.4.0 was
rehearsed as `v0.4.0-rc1` on 2026-10-14; the permissions change of this
page's revision is rehearsed as `v0.4.1-rc1`.

## 5. Post-release verification

Once the release workflow completes:

1. Download all release artifacts to a clean environment (not a
   developer machine).
2. Verify every binary and SBOM with `cosign verify-blob`, for example:
   ```
   cosign verify-blob --signature sagvd.sig --certificate sagvd.cert \
     --certificate-identity-regexp '^https://github\.com/vault-genome/vaultgenome-core/\.github/workflows/release\.yml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     sagvd
   ```
   `docs/security/supply_chain.md` explains what a successful check proves.
3. Check that the SLSA provenance attached to the release names each
   binary's SHA-256 (for example with `slsa-verifier`).
4. Rebuild from the tag with Go 1.27.2, from any host — the binaries are
   static (`CGO_ENABLED=0`) and carry the tag's VCS stamp, so the rebuild
   must come from a git checkout of the tag, not from an archive:
   ```
   git clone https://github.com/vault-genome/vaultgenome-core.git && cd vaultgenome-core
   git checkout vX.Y.Z
   GOOS=linux GOARCH=amd64 make build VERSION=vX.Y.Z COMMIT=$(git rev-parse HEAD)
   sha256sum bin/sagvd bin/acp-compute bin/acpctl bin/acp-bootstrap
   ```
   Every hash must equal the released file's. `go version -m <binary>`
   prints the build settings a released binary was made with (Go
   version, GOOS/GOARCH, CGO_ENABLED, -trimpath, the VCS revision and
   time); compare them first when hashes differ. (v0.1.0 and v0.2.0 were
   built with cgo on the runner: their rebuild needs linux/amd64 with a
   C toolchain; from v0.2.1 the binaries are static.)
5. Verify the tag signature — `git verify-tag v0.1.0`.
6. Record the release hashes externally (the external pin is itself a
   defence against a later tag rewrite — see
   `04_observability.md` §2.2 for the parallel idea on audit chains).

No audit event is appended for a release; there is no audit kind for one.

---

## 6. Emergency release (security-driven)

A security-driven emergency release still goes through this procedure —
there is no "fast path" that bypasses vault-gate or the SBOM / cosign /
SLSA steps. The only difference is:

1. The release notes are specific about the vulnerability class and the
   affected versions (per `SECURITY.md` §"What to expect").
2. The CVE ID is claimed and recorded before the release ships.
3. The prior version is explicitly marked as withdrawn in the release
   notes.

A release that bypasses the workflow is by definition not a release —
it is an unattested binary and per invariant #11 is not shippable.

---

## 7. Release checklist (one-page)

```
[ ] Clean working tree
[ ] vault-gate CI green on the commit; make vault-gate PASS locally
[ ] make test-integration and make verify-reproducible pass
[ ] Runbook reviewed for drift
[ ] Release notes drafted
[ ] Tag: git tag -s vX.Y.Z
[ ] Push: git push origin vX.Y.Z
[ ] release.yml workflow green
[ ] cosign verify-blob on every binary and SBOM
[ ] SLSA provenance names every binary's SHA-256
[ ] Rebuild from the tag is byte-identical
[ ] Tag signature verified externally
[ ] Release hash externally pinned
[ ] "Withdrawn" marker on prior version, if emergency
```

A release is complete when every line of this checklist is green.

---

_Document history: 2026-09-14 — checked line by line against the code; commands and names the binaries do not have were removed._
