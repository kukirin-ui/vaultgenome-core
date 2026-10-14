// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package genome_descriptor defines the AI Genome Descriptor (AGD) canonical
// artifact — the signed, content-addressed root of an AI Genome.
//
// # Doctrinal role
//
// The AGD is introduced by docs/doctrine/genome-format.md. It is a canonical
// artifact but NOT one of the nine flow messages: sessions, manifests, and
// disclosures reference AGDs, but the AGD is produced once per genome (or
// per generation within a succession chain) and lives above the flow.
//
// Content-addressing rule (R-14)
//
// The descriptor's own GenomeID is a FUNCTION of its contents, not an
// assigned identifier. Specifically,
//
//	GenomeID = "gen:" + hex(SHA-256(canonical-JSON(descriptor))),
//
// where the canonical pre-image has both GenomeID and Signature zeroed out.
// Validate() recomputes the derivation and fails with CategoryIntegrity if
// the stored GenomeID disagrees. This makes silent mutation — "same name,
// different bytes" — architecturally impossible.
//
// Structural invariants
//
//   - ComponentTreeRoot is a 32-byte SHA-256 over a componenttree.Tree, built
//     RFC 6962-style. The descriptor signs the root; the tree itself lives
//     alongside the AGD but is verifiable independently.
//   - Provenance records the trainer identity, training-data root, recipe
//     hash, and the derivation chain (parent GenomeIDs + methods).
//   - BehavioralFingerprint records the probe-battery root and the canonical
//     scores root — the structural commitment that enables behavioral-
//     equivalence attestations on reconstructions.
//
// # Freeze point
//
// Once signed, an AGD is immutable. A descendant genome produces a NEW AGD
// that cites the parent by GenomeID; it does not mutate the parent.
package genome_descriptor
