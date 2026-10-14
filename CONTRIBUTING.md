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
- [ ] No deprecated terminology introduced.
- [ ] Eleven doctrinal invariants not weakened.

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
