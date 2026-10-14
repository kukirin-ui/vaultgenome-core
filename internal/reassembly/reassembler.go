// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reassembly

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Stable error codes emitted by this package. Each code is namespaced
// with the "reassembly_" prefix so the bootstrap orchestrator's audit
// surface can filter on code alone. The classification (Structural vs
// Integrity vs Operational) is carried in the error's Category(),
// not encoded in the code string.
const (
	// CodeNilArgument — a required input was nil.
	CodeNilArgument = "reassembly_nil_argument"

	// CodeAGDMissing — the caller did not supply an AGD.
	CodeAGDMissing = "reassembly_agd_missing"

	// CodeComponentMapMismatch — the caller's component map does not
	// match the AGD's committed components (missing, extra, or
	// mismatched entries). Structural: the setup itself is malformed,
	// we haven't even looked at any bytes yet.
	CodeComponentMapMismatch = "reassembly_component_map_mismatch"

	// CodeUnknownComponent — the admitted DisclosureMessage names a
	// ComponentID not present in the AGD. Structural: the envelope is
	// not for this genome at all.
	CodeUnknownComponent = "reassembly_unknown_component"

	// CodeDuplicateComponent — a second DisclosureMessage was admitted
	// for a ComponentID we already admitted. Structural: the caller
	// (the orchestrator) should have de-duplicated upstream.
	CodeDuplicateComponent = "reassembly_duplicate_component"

	// CodeReassemblerFinalized — Admit called after Finalize.
	// Operational: a state-machine usage error.
	CodeReassemblerFinalized = "reassembly_finalized"

	// CodeSealedOpenFailed — Sealer.Open rejected the envelope.
	// Integrity: the payload or AAD does not match the seal.
	CodeSealedOpenFailed = "reassembly_sealed_open_failed"

	// CodeComponentHashMismatch — SHA-256(plaintext) does not match
	// the AGD's committed Component.Hash. Integrity.
	CodeComponentHashMismatch = "reassembly_component_hash_mismatch"

	// CodeComponentByteSizeMismatch — len(plaintext) does not match
	// the AGD's committed Component.ByteSize. Integrity.
	CodeComponentByteSizeMismatch = "reassembly_component_byte_size_mismatch"

	// CodeCoverageIncomplete — Finalize called before every committed
	// component had been admitted. Structural: the orchestrator
	// declared completion too early.
	CodeCoverageIncomplete = "reassembly_coverage_incomplete"

	// CodeMerkleRootMismatch — the rebuilt componenttree root does not
	// equal agd.ComponentTreeRoot. Integrity: the AGD has been
	// substituted OR the set of admitted components does not in
	// aggregate commit to the same root the release side signed.
	CodeMerkleRootMismatch = "reassembly_merkle_root_mismatch"

	// CodeGenomeIDRoundTripMismatch — agd.DeriveID() != agd.GenomeID.
	// Integrity: the parent AGD fails its OWN content-addressing
	// invariant (R-14). We hard-fail at Finalize rather than letting
	// this through silently.
	CodeGenomeIDRoundTripMismatch = "reassembly_genome_id_round_trip_mismatch"
)

// ReassemblyResult is the byte-level output of a successful Finalize.
// The caller (a reconstruction worker running inside a TEE) owns the
// returned plaintexts; no copy remains inside the Reassembler after
// Finalize returns.
//
// The Components map uses the AGD's committed Path (not ComponentID)
// as the key so downstream callers can address components by the same
// name the AGD's tree does.
type ReassemblyResult struct {
	// GenomeID is a copy of the parent AGD's signed GenomeID. Included
	// so callers do not need to re-derive from the AGD to cite the
	// reassembled genome's identity.
	GenomeID ids.GenomeID

	// ComponentTreeRoot is the rebuilt Merkle root. By Finalize-time
	// invariant, equal to agd.ComponentTreeRoot.
	ComponentTreeRoot []byte

	// Components maps each committed componenttree.Component.Path to
	// the verified plaintext bytes that were unsealed and matched the
	// commitment. All paths in the AGD are present.
	Components map[string][]byte
}

// Reassembler is the receive-side state machine. Admit is called once
// per DisclosureMessage in any order; Finalize closes the sequence
// and returns the result. Both methods are safe to call from a single
// goroutine only — the implementation holds no internal locking
// because one Reassembler instance is one reconstruction flow.
type Reassembler interface {
	// Admit opens msg under the parent AGD's committed AAD, recomputes
	// the plaintext's SHA-256 and byte-count, and compares them
	// against the AGD's committed Component entry for
	// msg.ComponentID.
	//
	// Refusal cases (first-match):
	//
	//   1. Reassembler finalized                                    → Operational.
	//   2. msg == nil                                               → Structural.
	//   3. msg.ComponentID not in AGD                               → Structural.
	//   4. msg.ComponentID already admitted                         → Structural.
	//   5. Sealer.Open fails                                        → Integrity.
	//   6. SHA-256(plaintext) != AGD.Component.Hash                 → Integrity.
	//   7. len(plaintext) != AGD.Component.ByteSize                 → Integrity.
	//
	// On any refusal the plaintext (if ever produced) is zeroized
	// before return. Admit does NOT retain plaintext bytes internally
	// in any form the caller cannot identify — the implementation
	// owns its own plaintext buffer until Finalize.
	Admit(msg *disclosure_message.DisclosureMessage) error

	// Finalize closes the sequence and returns the result. Refuses
	// with CodeCoverageIncomplete if any committed component was never
	// admitted. Refuses with CodeMerkleRootMismatch if the rebuilt
	// Merkle root diverges from agd.ComponentTreeRoot. Refuses with
	// CodeGenomeIDRoundTripMismatch if agd.DeriveID() != agd.GenomeID.
	//
	// Finalize is idempotent in the negative: after a first Finalize
	// (success or failure), subsequent Admit calls refuse with
	// CodeReassemblerFinalized, and subsequent Finalize calls return
	// the same error-or-result as the first.
	Finalize() (*ReassemblyResult, error)

	// IsFinalized reports whether Finalize has been called.
	IsFinalized() bool
}

// ComponentMap is the caller-supplied mapping from ComponentID (the
// key the wire envelope carries) to the AGD's committed Component
// (the tuple the Merkle leaf was built from). The reassembler takes
// this map at construction so the ComponentID↔Path translation — a
// policy concern the caller owns — stays out of the crypto path.
type ComponentMap map[ids.ComponentID]componenttree.Component
