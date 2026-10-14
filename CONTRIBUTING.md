# Contributing to the AI Continuity Platform Core

Thank you for considering a contribution. This project is defensive
infrastructure; the quality bar for changes is correspondingly high. The
guidance below is mandatory, not optional — CI enforces most of it.

## Before You Open a Pull Request

1. Read `docs/doctrine/terminology.md`. Use canonical terms. The deprecated
   terms listed there will fail the terminology check in CI.
2. Read the module's own `doc.go`. Every package has a doctrinal purpose; your
   change should be consistent with it.
3. Confirm your change does not weaken any of the eleven doctrinal
   invariants, which are asserted as tests in `test/doctrine/` (a weakening
   change fails those tests). If it necessarily does, stop and open a design
   discussion first.

## Branching and Commits

- Base branch for feature work: `main` (unless explicitly instructed
  otherwise).
- Branch naming: `feat/<area>-<short-description>`, `fix/<issue-id>-<desc>`,
  `docs/<area>-<desc>`, `ci/<desc>`, `chore/<desc>`.
- Commits must follow Conventional Commits format:
  ```
  <type>(<optional scope>): <short summary>

  <optional body explaining the WHY>

  Refs: #<issue-id>
  ```
  `type` is one of: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`,
  `perf`, `build`, `revert`. See `docs/doctrine/ci-security-policy.md` §3 for the
  authoritative rule and CI enforcement.
- All commits on protected branches MUST be cryptographically signed (SSH or
  GPG). Unsigned commits are blocked at push time.
- Every commit carries a Developer Certificate of Origin sign-off,
  `Signed-off-by: Name <email>`, with the author's email (`git commit -s`);
  see "Developer Certificate of Origin" below. CI checks every commit under
  review (`make dco`).

## Running Checks Locally

```
make fmt-check          # gofmt
make vet                # go vet
make test               # unit tests
make test-race          # race detector
make test-doctrine      # invariant tests
make lint               # golangci-lint
make terminology        # deprecated-terms check
make license-headers    # SPDX headers on all Go files
make dco                # Signed-off-by on every commit in origin/main..HEAD
make vuln               # govulncheck
make secrets            # gitleaks
make coverage-thresholds
make vault-gate         # everything the CI runs
make build DEBUG=1      # binaries with symbols and DWARF, for a debugger or profiler
```

A green `make vault-gate` does not guarantee the PR will be approved, but a
red one will block merge unconditionally.

## Pull Request Checklist

- [ ] Branch name follows the pattern above.
- [ ] All commits signed.
- [ ] Every commit carries a `Signed-off-by` trailer with the author's email (DCO).
- [ ] Conventional Commits format for every commit.
- [ ] `make vault-gate` passes locally.
- [ ] Tests added for new behavior (doctrine tests for new invariants,
      integration tests for new end-to-end behavior, unit tests for new
      logic).
- [ ] Documentation updated: `doc.go` on affected packages, `CHANGELOG.md` if
      user-visible.
- [ ] No new dependencies, OR a new dependency has a justification file at
      `docs/dependencies/<name>.md` AND appears on the allowlist in
      `docs/doctrine/ci-security-policy.md` §5.
- [ ] Every new Go, Python or shell file starts (after a shebang, if any) with
      the copyright line of `NOTICE` and the SPDX identifier (`make license-headers`).
- [ ] No deprecated terminology introduced.
- [ ] Eleven doctrinal invariants not weakened.

## Code Review

Every change reaches `main` through a pull request that a maintainer other
than its author has reviewed and approved; branch protection requires one
approving review from a code owner and dismisses it when new commits
arrive, and auto-merge waits for it. The gate checks the mechanics; the
reviewer checks the meaning. A review covers, in this order:

1. **The description against the diff.** The change does what the title and
   body say, and nothing else. A claim of verification ("run on hardware",
   "test added") is met by its trace in the diff or by a link; a claim
   without a trace is a request for changes.
2. **The checks.** Every required check is green before the review starts.
3. **The commits.** Conventional Commits, a verified signature and a
   `Signed-off-by` trailer on each.
4. **The code.** A test exists for new behaviour, and for a fix a test that
   failed before it; no doctrinal invariant is weakened (`test/doctrine/`
   not relaxed, no new write path for genome or key material outside the
   allow-list, no new listener without TLS, no `InsecureSkipVerify`); no
   new dependency without its justification under `docs/dependencies/` and
   its allowlist entry.
5. **The documentation.** Operator-visible behaviour has its line under
   `CHANGELOG.md` Unreleased and its page under `docs/`; a kit run has its
   dated evidence directory, the kit README, `KNOWN_ISSUES.md` and
   `VERIFIABLE-CLAIMS.md` reconciled.
6. **Governed paths** (`.github/CODEOWNERS`) are read line by line.

The verdict is **Approve** (worthwhile, no known issue that argues against
inclusion; remarks that are not about correctness or security may ride
along), **Request changes** (with what and why, pointing at the rule), or
**Comment** (questions that do not block). For code changes the reviewer
checks out the branch (`gh pr checkout <n>`), runs `make vault-gate`, and
where a test is claimed to guard a fix, reverts the fix locally to see the
test fail. Security findings go to the private channel in `SECURITY.md`,
never to the public pull request.

## Design Changes

If your PR alters the shape of a canonical contract, changes the
orchestration state model, weakens an operational validation sub-check,
introduces a new authority decision, or adds an export path for genome
material — **do not open the PR first**. Open a design document in
`docs/designs/<topic>.md` and get at least one founder's approval before
coding.

## Code of Conduct

Participation is governed by `CODE_OF_CONDUCT.md`. Technical disagreement is
welcome and expected; personal attacks are not.

## License of Contributions

By contributing, you agree your contribution is licensed under AGPL-3.0-or-later
with the same terms as the rest of the repository.

## Developer Certificate of Origin

Since 2026-10-14 every commit certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org): that
you wrote the change or have the right to submit it under the project's
license, and that you understand the contribution is public and kept with
its sign-off. The certification is the trailer

```
Signed-off-by: Your Name <your@email>
```

which `git commit -s` adds from your git identity; the email must be the
author's (a GitHub noreply address is fine). For commits already made,
`git rebase --signoff origin/main` adds it to each. CI refuses a pull
request with an unsigned-off commit (`scripts/dco_check.sh`); merge commits
are exempt. Commits before 2026-10-14 are covered by the founders'
copyright and assignment agreements (`NOTICE`, `MAINTAINERS.md`). No CLA:
the sign-off is the whole of it.
