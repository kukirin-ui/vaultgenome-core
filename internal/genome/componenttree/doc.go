// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package componenttree implements an RFC 6962-style Merkle tree over the
// components of an AI Genome.
//
// # Doctrinal role
//
// The component tree is the structural primitive that makes staged disclosure
// sound: the vault can release one Component plus an inclusion proof, and an
// external verifier can independently confirm the Component belongs to the
// signed AI Genome Descriptor without ever seeing the other components. The
// tree's root is what the AGD signs; every downstream integrity claim about
// "this is part of genome X" bottoms out here.
//
// Design
//
//   - Hash function: SHA-256.
//   - Leaf hash: SHA-256(0x00 || canonical(Component)) — the RFC 6962 leaf tag.
//   - Internal hash: SHA-256(0x01 || left || right) — the RFC 6962 node tag.
//   - Determinism: leaves are sorted lexicographically by Component.Path before
//     hashing. Duplicate paths are rejected at build time.
//   - Odd counts: the last node at each level is promoted up unchanged
//     (RFC 6962 §2.1). No duplication — that would expose the tree to second-
//     preimage attacks.
//
// What lives here / what does not
//
// This package knows nothing about signing, about vault keys, about the AGD
// schema. It is a pure data-structure primitive. The AGD contract imports
// this package to compute its ComponentTreeRoot; the disclosure code imports
// this package to attach inclusion proofs.
//
// The canonical byte-form of a Component is produced by this package's
// encodeComponent, which is intentionally NOT the general CanonicalJSON
// encoder — it is a fixed, minimal, stable-forever encoding chosen so that
// tree roots computed in any language match byte-for-byte.
package componenttree
