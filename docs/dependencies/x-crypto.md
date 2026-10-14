# Dependency Justification — golang.org/x/crypto

**Version:** the one pinned in `go.mod` (Dependabot keeps it current, grouped weekly, through the same gate as any change; the justification here does not depend on the patch level — a major version is a new review)
**License:** BSD-3-Clause (the Go project)
**Transitive depth:** 2 (x/crypto → x/net, x/sys, x/term, x/text — all Go
project modules; none of them is linked into a binary by the one package
used, `golang.org/x/crypto/ocsp`, which imports the standard library only)
**Usage scope:** `internal/shared/tee/nvidia_ocsp.go` only — the OCSP
revocation check of a confidential GPU's attestation certificate chain
against NVIDIA's responder (ADR 0021, amended): parsing and verifying the
responder's answers (`ocsp.ParseResponseForCert`), and, in tests, making
answers for a synthetic chain (`ocsp.CreateResponse`). The request is
encoded in-house, because x/crypto's `CreateRequest` writes no nonce.

## Advisories against the module that do not reach this code

- **GO-2026-5932** (`golang.org/x/crypto/openpgp` is unmaintained; no fix
  planned, so every version of the module carries it). The package is not
  imported here: `go mod why golang.org/x/crypto/openpgp` answers *(main
  module does not need package …)*, and `govulncheck ./...` lists the
  advisory under modules required, not code called (2026-10-13, go1.27.2,
  x/crypto v0.58.0). It stays in the scanner's count as long as the
  `ocsp` package is used; it is not a risk to a binary built from this tree.
  The vault-gate's osv-scanner step ignores it by id (`osv-scanner.toml`,
  with this reason, until 2027-01-31, when the ignore expires and the
  question is asked again — the exception the doctrine's §5 allows): the
  step is presence-based and cannot see that the package is unused;
  `make vuln` (govulncheck on the tree's own toolchain) can and does.

## Why this dependency

RFC 6960 answers are DER structures signed either by the certificate's
issuer or by a responder certificate the issuer delegated — NVIDIA uses
delegated responders, one per level of the chain, embedded in each
answer. Parsing the response, locating the single response for the
certificate asked about, checking the responder certificate's signature
under the issuer and the answer's signature under the responder is the
whole of what the `ocsp` package does, in about a thousand lines that
the Go team maintains beside `crypto/x509`. Writing the same in-house is
possible; it would be the same ASN.1 walked with less review. The package
is pure Go and imports only the standard library.

## What it is not used for

Making OCSP requests in production (encoded here, with a nonce), TLS,
SSH, or any of the module's other packages. The dependency-depth check
(`scripts/check_dep_depth.sh`) and govulncheck cover the module graph;
`go mod graph` shows no non-Go-project module behind it.

## Review

Sign-off: both founders on the PR that adds it (policy §3.1).
