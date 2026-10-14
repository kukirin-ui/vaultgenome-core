// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reassembly

import (
	"bytes"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// AGDReassembler is the concrete Reassembler bound to one parent AGD.
// The zero value is NOT usable; constructors are in NewAGDReassembler.
//
// # Thread-safety
//
// AGDReassembler is NOT safe for concurrent use. One reassembler
// instance maps to one reconstruction flow, driven by the bootstrap
// orchestrator's single-goroutine acceptance loop. Callers that need
// parallelism should construct independent reassemblers.
type AGDReassembler struct {
	agd        *genome_descriptor.GenomeDescriptor
	components ComponentMap

	// sealer is the injected key store used to Open each envelope.
	// The receive-side worker registers the recipient key material
	// into this Sealer as part of the bootstrap agreement handshake;
	// the Reassembler only consumes it.
	sealer keys.Sealer

	// admitted holds the verified plaintexts, keyed by ComponentID,
	// until Finalize takes ownership and re-keys by Path. The buffer
	// is cleared (slice set to nil) on every exit path so that a
	// premature Finalize failure does not leave plaintext hanging in
	// a reachable map.
	admitted map[ids.ComponentID][]byte

	// finalResult and finalErr are populated on the first call to
	// Finalize so that subsequent Finalize calls return the same
	// answer. Admit after either is set refuses with Operational.
	finalized   bool
	finalResult *ReassemblyResult
	finalErr    error
}

// NewAGDReassembler constructs a Reassembler bound to one signed AGD
// and its committed components. Construction refuses on obviously
// malformed inputs; signature verification of the AGD is a CALLER
// concern (see package doc).
//
// Structural refusals:
//
//   - agd == nil → CodeAGDMissing.
//   - sealer == nil → CodeNilArgument.
//   - agd.Validate() fails → Structural/Integrity (propagated).
//   - components covers a different set than the AGD commits to →
//     CodeComponentMapMismatch.
//
// The components map is defensively copied; the caller may freely
// mutate it after construction.
func NewAGDReassembler(
	agd *genome_descriptor.GenomeDescriptor,
	components ComponentMap,
	sealer keys.Sealer,
) (*AGDReassembler, error) {
	if agd == nil {
		return nil, shared_errors.Structural(
			CodeAGDMissing,
			"reassembly: agd is required",
			nil,
		)
	}
	if sealer == nil {
		return nil, shared_errors.Structural(
			CodeNilArgument,
			"reassembly: sealer is required",
			nil,
		)
	}
	if err := agd.Validate(); err != nil {
		// agd.Validate() already classifies Structural / Integrity
		// appropriately; pass it through unchanged.
		return nil, err
	}
	if components == nil {
		return nil, shared_errors.Structural(
			CodeComponentMapMismatch,
			"reassembly: component map is required",
			nil,
		)
	}

	// The AGD commits only to the Merkle root — not to the
	// ComponentID↔Component mapping directly. The caller passes that
	// mapping in (because only they know how to resolve ComponentIDs
	// from their genome metadata). But the mapping MUST, in aggregate,
	// commit to the same root; we verify that here before accepting
	// any envelopes.
	if uint32(len(components)) != agd.ComponentCount {
		return nil, shared_errors.Structural(
			CodeComponentMapMismatch,
			"reassembly: component map size does not match agd.component_count",
			nil,
		)
	}

	// Build a defensive copy and collect the committed components for
	// the Merkle-root cross-check.
	copied := make(ComponentMap, len(components))
	leaves := make([]componenttree.Component, 0, len(components))
	seenPath := make(map[string]struct{}, len(components))
	var totalBytes uint64
	for cid, c := range components {
		if cid.IsZero() {
			return nil, shared_errors.Structural(
				CodeComponentMapMismatch,
				"reassembly: component map contains zero ComponentID",
				nil,
			)
		}
		if _, dup := seenPath[c.Path]; dup {
			return nil, shared_errors.Structural(
				CodeComponentMapMismatch,
				"reassembly: component map contains duplicate path: "+c.Path,
				nil,
			)
		}
		seenPath[c.Path] = struct{}{}
		cp := componenttree.Component{
			Path:     c.Path,
			Kind:     c.Kind,
			ByteSize: c.ByteSize,
			Hash:     append([]byte(nil), c.Hash...),
		}
		copied[cid] = cp
		leaves = append(leaves, cp)
		totalBytes += c.ByteSize
	}

	// Cross-check: the committed components must build the same
	// Merkle root the signed AGD carries. If they don't, the caller
	// handed us a mapping that does not correspond to this AGD.
	tree, err := componenttree.BuildTree(leaves)
	if err != nil {
		return nil, shared_errors.Structural(
			CodeComponentMapMismatch,
			"reassembly: component map does not form a valid tree",
			err,
		)
	}
	if !bytes.Equal(tree.RootSlice(), agd.ComponentTreeRoot) {
		return nil, shared_errors.Structural(
			CodeComponentMapMismatch,
			"reassembly: component map merkle root does not match agd.component_tree_root",
			nil,
		)
	}
	if totalBytes != agd.TotalBytes {
		return nil, shared_errors.Structural(
			CodeComponentMapMismatch,
			"reassembly: component map total_bytes does not match agd.total_bytes",
			nil,
		)
	}

	return &AGDReassembler{
		agd:        agd,
		components: copied,
		sealer:     sealer,
		admitted:   make(map[ids.ComponentID][]byte, len(copied)),
	}, nil
}

// Admit implements Reassembler.Admit.
func (r *AGDReassembler) Admit(msg *disclosure_message.DisclosureMessage) error {
	if r.finalized {
		return shared_errors.Operational(
			CodeReassemblerFinalized,
			"reassembly: admit after finalize",
			nil,
		)
	}
	if msg == nil {
		return shared_errors.Structural(
			CodeNilArgument,
			"reassembly: nil disclosure message",
			nil,
		)
	}
	// Structural self-consistency check on the envelope. Signature
	// verification is the orchestrator's job — but the envelope must
	// at least parse cleanly before we hand it to the sealer.
	if err := msg.Validate(); err != nil {
		return err
	}

	committed, ok := r.components[msg.ComponentID]
	if !ok {
		return shared_errors.Structural(
			CodeUnknownComponent,
			"reassembly: envelope references unknown component_id",
			nil,
		)
	}
	if _, dup := r.admitted[msg.ComponentID]; dup {
		return shared_errors.Structural(
			CodeDuplicateComponent,
			"reassembly: component already admitted: "+committed.Path,
			nil,
		)
	}

	// Rebuild the AAD from the envelope's own header fields and open
	// the seal. The five-field shape is the shared contract helper;
	// the release side used the same function when it sealed.
	aad, err := disclosure_message.BuildRecipientAADForMessage(msg)
	if err != nil {
		return err
	}
	plaintext, err := r.sealer.Open(msg.RecipientKeyID, msg.Nonce, msg.SealedPayload, aad)
	if err != nil {
		// Re-classify the underlying crypto-tier event as a reassembly-
		// tier one. crypto.Open surfaces every GCM auth failure as
		// Integrity[CodeSignatureInvalid]; from the reassembler's POV
		// the right vocabulary is CodeSealedOpenFailed — that's what
		// the operator runbook keys off of, what
		// docs/doctrine/bootstrap-contracts.md §6 enumerates, and what
		// the receive-side decision (ReconstitutionDecision) cites.
		// Preserve the underlying error as cause so a debugger can
		// walk back to the GCM layer.
		if shared_errors.CodeOf(err) == shared_errors.CodeSignatureInvalid {
			return shared_errors.Integrity(
				CodeSealedOpenFailed,
				"reassembly: sealer.Open refused envelope (GCM authentication failed)",
				err,
			)
		}
		// Any other categorised error from the sealer (Structural for
		// nonce-wrong-size, Authority for unknown kid, etc.) propagates
		// unchanged so the caller sees the precise diagnosis.
		if shared_errors.CategoryOf(err) != shared_errors.CategoryUnknown {
			return err
		}
		return shared_errors.Integrity(
			CodeSealedOpenFailed,
			"reassembly: sealer.Open refused envelope",
			err,
		)
	}

	// From here on plaintext is live. Every refusal below MUST zeroize
	// before returning.
	if uint64(len(plaintext)) != committed.ByteSize {
		zeroBytes(plaintext)
		return shared_errors.Integrity(
			CodeComponentByteSizeMismatch,
			"reassembly: plaintext byte-size disagrees with agd commitment",
			nil,
		)
	}
	sum := crypto.SHA256(plaintext)
	if !bytes.Equal(sum[:], committed.Hash) {
		zeroBytes(plaintext)
		return shared_errors.Integrity(
			CodeComponentHashMismatch,
			"reassembly: plaintext hash disagrees with agd commitment",
			nil,
		)
	}

	// Verified. Take ownership of plaintext.
	r.admitted[msg.ComponentID] = plaintext
	return nil
}

// Finalize implements Reassembler.Finalize.
func (r *AGDReassembler) Finalize() (*ReassemblyResult, error) {
	if r.finalized {
		// Return the stored outcome verbatim. Zero-value result + nil
		// err means "first call was success; we already transferred
		// ownership, no replaying".
		return r.finalResult, r.finalErr
	}
	r.finalized = true

	// Coverage check: every committed component must have been admitted.
	if len(r.admitted) != len(r.components) {
		r.clearPlaintexts()
		r.finalErr = shared_errors.Structural(
			CodeCoverageIncomplete,
			"reassembly: finalize before every committed component was admitted",
			nil,
		)
		return nil, r.finalErr
	}
	// Defensive: key-set equality. The length check above plus the
	// Admit-time membership check already implies this, but we assert
	// it explicitly so a future refactor of the admit path cannot
	// silently break the invariant.
	for cid := range r.components {
		if _, ok := r.admitted[cid]; !ok {
			r.clearPlaintexts()
			r.finalErr = shared_errors.Structural(
				CodeCoverageIncomplete,
				"reassembly: missing admitted entry for committed component",
				nil,
			)
			return nil, r.finalErr
		}
	}

	// Merkle round-trip. Re-build from the COMMITTED components we
	// hold (which have already been verified to build to
	// agd.ComponentTreeRoot at construction time). Re-verifying here
	// is paranoia: if this fails, something mutated r.components
	// between New and Finalize — which should not be possible in
	// legitimate use but is cheap to rule out.
	leaves := make([]componenttree.Component, 0, len(r.components))
	for _, c := range r.components {
		leaves = append(leaves, c)
	}
	tree, err := componenttree.BuildTree(leaves)
	if err != nil {
		r.clearPlaintexts()
		r.finalErr = shared_errors.Integrity(
			CodeMerkleRootMismatch,
			"reassembly: tree rebuild failed at finalize",
			err,
		)
		return nil, r.finalErr
	}
	if !bytes.Equal(tree.RootSlice(), r.agd.ComponentTreeRoot) {
		r.clearPlaintexts()
		r.finalErr = shared_errors.Integrity(
			CodeMerkleRootMismatch,
			"reassembly: rebuilt merkle root diverged from agd commitment",
			nil,
		)
		return nil, r.finalErr
	}

	// GenomeID round-trip. The AGD's signed GenomeID must equal the
	// derivation of the AGD's own bytes. Validate() already enforces
	// this, but we re-run it here so a Validate-skipping future caller
	// cannot bypass the check.
	derived, err := r.agd.DeriveID()
	if err != nil {
		r.clearPlaintexts()
		r.finalErr = err
		return nil, r.finalErr
	}
	if derived != r.agd.GenomeID {
		r.clearPlaintexts()
		r.finalErr = shared_errors.Integrity(
			CodeGenomeIDRoundTripMismatch,
			"reassembly: agd.DeriveID() disagrees with agd.GenomeID",
			nil,
		)
		return nil, r.finalErr
	}

	// Success path: re-key admitted plaintexts by Path and publish.
	out := &ReassemblyResult{
		GenomeID:          r.agd.GenomeID,
		ComponentTreeRoot: tree.RootSlice(),
		Components:        make(map[string][]byte, len(r.admitted)),
	}
	for cid, plaintext := range r.admitted {
		c := r.components[cid]
		out.Components[c.Path] = plaintext
	}
	// Transfer ownership: clear our internal handle so a double
	// Finalize cannot leak a second reference to the same plaintexts.
	r.admitted = nil
	r.finalResult = out
	return out, nil
}

// IsFinalized implements Reassembler.IsFinalized.
func (r *AGDReassembler) IsFinalized() bool { return r.finalized }

// clearPlaintexts zeroizes every admitted buffer and drops the map.
// Called on every refusal path in Finalize so that a failed Finalize
// does not leave recoverable plaintext behind the Reassembler's back.
func (r *AGDReassembler) clearPlaintexts() {
	for cid, p := range r.admitted {
		zeroBytes(p)
		delete(r.admitted, cid)
	}
	r.admitted = nil
}

// zeroBytes overwrites b with zeros. Noop on nil / empty. Kept local
// to this package so we don't depend on /vault/ utilities for a
// two-line helper.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Compile-time interface assertion.
var _ Reassembler = (*AGDReassembler)(nil)
