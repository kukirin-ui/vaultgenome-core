# ADR 0024 — The AWS Nitro verifier, from the specification

**Status:** Accepted — implemented (2026-09-22)
**Date:** 2026-09-22
**Authors:** Serhii Nikolaichuk (CEO), Rodion Sorokin (CTO)
**Builds on:** ADR 0001 (frozen Producer/Verifier/Sealer), ADR 0002 (adapter dispatch), ADR 0007 (variable-length measurements), ADR 0013 (no stubs on the path), ADR 0018 (a verifier written from the vendor's specification and proven on the vendor's own output)
**Amends:** `internal/shared/tee` (the `aws-nitro` verifier; `AWSNitroVerifierConfig.Now`; `AuditAWSNitroDocument`); `acpctl attest nitro`; KNOWN_ISSUES #1; ROADMAP ("Blocked on hardware or quota")

---

## Context

The AWS Nitro adapter has been in the repository since the first cohort,
and it was scaffolding: the four functions that parse the COSE_Sign1
envelope, decode the attestation document, walk the certificate chain and
check the signature returned "not yet wired (Phase 2)", the AWS root was
not pinned (`awsNitroPinnedRoots` returned nil), and the integration tests
passed because the test harness swapped those four functions for fakes
that round-tripped a JSON envelope. ROADMAP said "the verifiers are
written"; KNOWN_ISSUES #1 said "still scaffolding". The second was true.

Four production-mode attestation documents were captured in May 2026 on
real Nitro Enclaves (three Ohio zones and one Irish one,
`scripts/hardware-test/aws-nitro/evidence`) and validated then by the
kit's Python script — never by this repository's code.

On 2026-09-22 the program put AWS Nitro first in the engineering queue
(the first buyer is an American partner; the first signed entry into the
policy is export control and the chip's location, in AWS's terms). The
enclave itself waits on a quota. What does not wait is the verifier: the
hypervisor's own documents are on disk, and a verifier that cannot verify
them has no business waiting for a live one.

## Decision

### The codec is written from the specification, not taken from a library

The attestation document is CBOR (RFC 8949) in a COSE_Sign1 envelope
(RFC 9052), specified by AWS in "Verifying the root of trust". The
verifier decodes exactly the subset the document uses — unsigned and
negative integers, byte and text strings, arrays, maps with integer or
text keys, the null value, tag 18 — with definite or indefinite lengths,
and refuses everything else: floating-point numbers, the other simple
values, reserved additional-information values, a break code outside an
indefinite-length item, more than 64 KiB, nesting past 8, more than 4096
items. It is in-house (`aws_nitro_cbor.go`, about 250 lines) for the
reason the dependency policy exists: this parser is the first code an
unauthenticated peer's bytes reach, before any signature is checked, and
a library there would be the first third-party parser on that path.

Indefinite lengths were not in the first draft of this codec — the
specification's CDDL says nothing about encoding — and the four genuine
documents refused to decode: the hypervisor writes the document's map
with an indefinite length (`0xbf … 0xff`) and everything inside it
definite. The genuine captures found the defect in an hour. That is what
they are for.

### What the envelope and the document must be

- The protected header names ES384 (`alg` = −35) exactly once; a `crit`
  parameter is refused, since this verifier understands none; the
  payload is attached; the signature is 96 bytes (r ‖ s over P-384). The
  tag 18 is accepted and not required, as AWS says.
- The document is a closed map: `module_id`, `timestamp`, `digest`
  (`SHA384`), `pcrs` (index 0..31, values of 32, 48 or 64 bytes),
  `certificate` and `cabundle` (DER, 1..1024 bytes each), and the
  optional `public_key`, `user_data`, `nonce` (null or up to 1024 bytes).
  A field outside the specification, a repeated field, a wrong type or
  size is a refusal. A future document with a new field will be refused
  until this verifier is changed deliberately — fail closed.

### The chain is anchored at the root this repository pins

The built-in root is the AWS Nitro Enclaves Root CA G1 (`aws_nitro_roots.go`),
whose SHA-256 fingerprint `64:1A:03:21…8F:79:BB:5B` AWS prints in the
attestation documentation; a test holds the embedded certificate to it,
and it was fetched from AWS again on 2026-09-22 and compared. An operator
may pin another (`PinnedRoots`: a GovCloud partition, a rotation). The
document's `cabundle[0]` must be one of the pinned roots — the document
names its anchor and the verifier's must be the same one — and the path
signing certificate → intermediates → root is verified with the standard
library at the verifier's clock, without revocation, as AWS specifies
("CRL must be disabled"). The signing certificate's key must be P-384.

### Time is the verifier's clock, and an audit's clock is the capture

`AWSNitroVerifierConfig.Now` (default `time.Now`) is what the chain's
validity and the timestamp's freshness are checked against. The
hypervisor issues the signing certificate for three hours, so a captured
document cannot verify "now"; `AuditAWSNitroDocument(ev, roots, at)` with
a zero `at` audits it at its own timestamp — the question to ask of a
capture is whether the chain was valid when the hypervisor signed.
`acpctl attest nitro` is that audit as an operator command, with
`--expected-pcr0` from `nitro-cli describe-eif`, `--root` and `--at`;
it exits 0 when the document verifies and 5 when it does not.

### A challenge is mandatory

The Verifier refuses a document that carries no nonce, or another nonce
than the challenger's. The four May documents carry none (the kit asked
the NSM for none), and the Verifier refuses them even at their capture
time; the audit, which asks no challenge, verifies them. Both are tested
on the genuine documents. A debug-mode enclave (PCR0 all zeroes) is
refused; PCR selection and the acceptable set are as before.

### What stays refused

The NSM producer (the `/dev/nsm` ioctl) and the KMS sealer are still the
stubs they were: nothing here can be proven without an enclave. The
verifier registry and `acp-bootstrap` keep refusing the `aws-nitro`
family until a live enclave has attested to this code end to end and
taken a key release — the drill in `scripts/hardware-test/aws-nitro`,
once the quota exists. VERIFIABLE-CLAIMS says what is and is not claimed.

## Evidence

- The shipping verifier on the four production documents of May 2026, at
  their capture time: VERIFIED, five certificates to
  `CN=aws.nitro-enclaves`, ES384 signature valid, PCR0/1/2 equal to what
  `nitro-cli describe-eif` printed for the image, `user_data` equal to the
  SHA-512 of the build manifest, `nonce` absent, `debug` false; at
  2026-09-22: NOT VERIFIED, the signing certificate expired on
  2026-05-08T03:52:52Z — `scripts/hardware-test/aws-nitro/evidence/0N-*/07-go-verifier-audit.json`,
  written by `acpctl attest nitro --json`. The raw documents are shared
  under NDA; `TestAWSNitro_GenuineProductionCaptures` runs on them when
  `VG_NITRO_CAPTURE_DIR` names their directory, and asserts all of the
  above plus the Verifier's refusal for want of a nonce and the signature
  check's refusal of a flipped byte.
- A synthetic five-certificate P-384 chain (`aws_nitro_fixture_test.go`)
  signs the documents the unit and integration tests verify, so every
  byte of the production codec runs in CI: twenty refusals one knob at a
  time (nonce, signature, stranger's key, another chain, swapped root,
  missing intermediate, expiry, algorithm, `crit`, detached payload,
  digest, unknown field, missing bundle, stale timestamp, debug mode,
  PCR policy, PCR length), the rolling set and the PCR selector.
- Fuzzing, 20 seconds each on 2026-09-22: `FuzzCBORDecode_NoPanic`
  1.3 million executions, `FuzzAWSNitroVerifier_Verify_NoPanic` 425
  thousand, no panic.

## Consequences

- The Nitro verifier is code that verifies AWS's own output, not a
  promise; the live drill can start the day the quota lands, and
  `acpctl attest nitro` is the tool that drill's runbook needs to check
  what it captured.
- A spec-strict decoder may refuse a document AWS changes the shape of.
  That is the intended failure: loud, at the verifier, fixed by a
  deliberate change here — never by accepting what was not specified.
- Nothing is claimed for the producer, the sealer or a key release on
  Nitro. KNOWN_ISSUES #1 and ROADMAP say so, and VERIFIABLE-CLAIMS keeps
  Nitro under "what we do not claim" until the live run.
