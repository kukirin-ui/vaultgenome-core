# Architecture Decision Records (ADRs)

This directory holds the ADRs that capture every significant
architectural decision in the Vault Genome codebase. Each ADR is a
self-contained Markdown file numbered sequentially.

The format is loosely based on
[MADR](https://adr.github.io/madr/) but adapted for our doctrine
norms — see [ADR-0004](0004-doctrine-invariants-as-tests.md) for how
ADRs interact with the test-enforced invariant system.

## Index

| #    | Title                                              | Status   | Tags |
|------|----------------------------------------------------|----------|------|
| 0001 | [Frozen Producer/Verifier/Sealer interface](0001-frozen-producer-verifier-sealer-interface.md) | Accepted | tee, interface-contract |
| 0002 | [Multi-TEE adapter dispatch via Provider enum](0002-multi-tee-adapter-dispatch.md) | Accepted | tee, factory-pattern |
| 0003 | [AGPL-3.0-or-later + commercial dual licensing](0003-agpl-commercial-dual-licensing.md) | Accepted | licensing, business |
| 0004 | [Doctrinal invariants enforced by Go tests](0004-doctrine-invariants-as-tests.md) | Accepted | doctrine, ci |
| 0005 | [Mock-based integration testing for hardware adapters](0005-mock-based-integration-testing.md) | Accepted | testing, tee |
| 0006 | [Cross-cloud KMS-mediated restore](0006-cross-cloud-kms-mediated-restore.md) | Accepted | restore, kms, crosscloud |
| 0007 | [Measurement is variable-length](0007-measurement-variable-length.md) | Accepted | tee, measurement |
| 0008 | [Numerical equivalence gate for cross-hardware reconstruction](0008-equivalence-gate.md) | Accepted | reconstruction, equivalence, determinism |
| 0009 | [X25519 KEM for cross-cloud DEK delivery (closes defect b)](0009-x25519-kem-cross-cloud-key-delivery.md) | Accepted | crosscloud, kms, crypto |
| 0010 | [Operator stop and recorded refusals](0010-operator-stop-and-recorded-refusals.md) | Accepted | crosscloud, audit, governance |
| 0011 | [Genome v3 and attested self-restore](0011-genome-v3-and-attested-self-restore.md) | Accepted | genome, crosscloud, restore, doctrine |
| 0012 | [Sentinel and policy-driven failover](0012-sentinel-and-policy-driven-failover.md) | Accepted | genome, failover, crosscloud, audit, governance |
| 0013 | [The worker restores the genome](0013-worker-restores-the-genome.md) | Accepted | worker, returnpath, genome, equivalence |
| 0014 | [The Return Path on the record, and on hardware](0014-return-path-on-the-record-and-on-hardware.md) | Accepted | audit, returnpath, tee, sev-snp |
| 0015 | [One binary drives the nine stages](0015-one-binary-drives-the-nine-stages.md) | Accepted | orchestration, sagvd, audit, trust, release |
| 0016 | [The escrow key is sealed to the release host's TEE](0016-escrow-key-sealed-to-the-release-host.md) | Accepted | escrow, tee, sev-snp, sagvd, custody |
| 0017 | [Limits on the primary's word](0017-limits-on-the-primarys-word.md) | Accepted | failover, sentinel, tee, attestation, governance |
| 0018 | [Intel TDX on the Return Path](0018-intel-tdx-on-the-return-path.md) | Accepted | tee, tdx, returnpath, attestation |
| 0019 | [A confidential GPU worker on Azure](0019-a-confidential-gpu-worker-on-azure.md) | Accepted | tee, gpu, azure, sev-snp, vtpm, attestation |
| 0020 | [The integer door for the LoRA worker](0020-the-integer-door-for-the-lora-worker.md) | Accepted | genome, gate, determinism, integer, cross-hardware |
| 0021 | [The verifier's own evaluation of the GPU's report](0021-the-verifiers-own-evaluation-of-the-gpu.md) | Accepted | tee, gpu, nvidia, attestation, azure |
| 0022 | [The escrow key sealed to the guest's vTPM where the TEE gives no sealing key](0022-the-escrow-key-sealed-to-the-vtpm.md) | Accepted | tee, tdx, azure, vtpm, escrow, sealing |
| 0023 | [The daemons' key files sealed to the host](0023-the-daemons-key-files-sealed-to-the-host.md) | Accepted | keys, sealing, tee, sagvd, acp-compute |
| 0024 | [The AWS Nitro verifier, from the specification](0024-the-aws-nitro-verifier-from-the-specification.md) | Accepted | tee, aws-nitro, cbor, cose, verifier, acpctl |

## Adding an ADR

1. Pick the next number. Numbers are sequential and never reused — if
   an ADR is later superseded, the new ADR cites the old one in its
   header.
2. Copy `0001-…md`'s structure: status table, Context, Decision,
   Consequences, Alternatives considered, optional implementation
   checklist or future directions.
3. Add an entry to the index table above.
4. If the ADR introduces or amends a doctrinal invariant, pair it
   with a `TestInvariant_NN_…` in `test/doctrine/`
   (see [ADR-0004](0004-doctrine-invariants-as-tests.md)).
5. Submit as a separate PR ahead of the implementation change so
   the ADR can be reviewed against intent, not against working code.

## Status values

- **Proposed** — drafted, under review.
- **Accepted** — merged; constraint is in force.
- **Deprecated** — no longer the preferred approach but not yet replaced.
- **Superseded by ADR-NNNN** — replaced by a newer decision; both
  ADRs remain in the repo for historical context.

ADRs are NEVER deleted. Even superseded ADRs document why a path was
abandoned, which is often the most useful information for the next
engineer who considers re-treading it.
