// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness

import (
	"bytes"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// ForkEvidence names a pair of SignedTreeHeads whose relationship is
// doctrinally impossible for an honest append-only log — i.e., a
// FORK. ForkEvidence carries enough byte-level detail for an external
// auditor to reproduce the finding, and names the specific violation
// mode via Kind so downstream incident handlers can route correctly.
//
// A fork is not a bug. It is the only externally-observable signal
// that the log operator has either (a) retroactively rewritten
// history, or (b) run two divergent trees under one signing key.
// Either is Incident-class: the receiver of a ForkEvidence MUST wire
// it to /internal/vault/incident for termination handling.
type ForkEvidence struct {
	// A and B are the two conflicting STHs. A is the EARLIER-sized
	// tree (A.TreeSize <= B.TreeSize) by the normalization in
	// DetectFork; this simplifies downstream code that needs to reason
	// about "old vs new" independent of the caller's argument order.
	A SignedTreeHead
	B SignedTreeHead

	// Kind names the specific fork mode that triggered the finding.
	Kind ForkKind

	// Detail is a human-readable amplification suitable for audit
	// logs. Never contains signing material or private data.
	Detail string
}

// ForkKind enumerates the ways two STHs can be mutually inconsistent.
type ForkKind string

const (
	// ForkKindSameSizeDifferentRoot — A.TreeSize == B.TreeSize AND
	// A.TreeHash != B.TreeHash. The operator has signed two distinct
	// Merkle roots for the same tree size. This is the clearest
	// fork signal: it CANNOT happen if the log is append-only.
	ForkKindSameSizeDifferentRoot ForkKind = "same_size_different_root"

	// ForkKindSameSizeDifferentChainHead — A.TreeSize == B.TreeSize
	// AND A.TreeChainHead != B.TreeChainHead (even if TreeHash
	// accidentally collides, which is cryptographically
	// overwhelmingly unlikely). Defense-in-depth against a Merkle
	// collision that would mask a real fork.
	ForkKindSameSizeDifferentChainHead ForkKind = "same_size_different_chain_head"

	// ForkKindTimestampNonMonotonic — A.TreeSize < B.TreeSize AND
	// B.Timestamp is strictly before A.Timestamp. An honest log
	// MUST issue STHs with non-decreasing Timestamps as TreeSize
	// grows; the reverse indicates either a clock rollback or a
	// replay of an earlier private state.
	ForkKindTimestampNonMonotonic ForkKind = "timestamp_non_monotonic"

	// ForkKindInconsistentProof — A.TreeSize < B.TreeSize and a
	// ConsistencyProof between them fails to verify. The operator
	// signed STHs whose relationship cannot be bridged — either the
	// old tree was retroactively rewritten, or the two STHs belong
	// to different trees issued under one key (split-brain
	// operator).
	ForkKindInconsistentProof ForkKind = "inconsistent_proof"

	// ForkKindDifferentSigners — A.SigningKeyID != B.SigningKeyID.
	// This is NOT strictly a fork — different log operators can
	// legitimately sign different STHs — but it is reported because
	// code calling DetectFork on two STHs MUST have pre-determined
	// they come from the same operator; if not, the caller has a
	// bug. Surfaced here as a structural sanity signal, not an
	// Incident.
	ForkKindDifferentSigners ForkKind = "different_signers"
)

// IsIncident reports whether this fork kind is an actionable incident
// signal. ForkKindDifferentSigners is NOT an incident — it is a
// programmer error in the caller. All other kinds are.
func (k ForkKind) IsIncident() bool {
	switch k {
	case ForkKindSameSizeDifferentRoot,
		ForkKindSameSizeDifferentChainHead,
		ForkKindTimestampNonMonotonic,
		ForkKindInconsistentProof:
		return true
	}
	return false
}

// AsError renders a ForkEvidence as a classified error. Incident-class
// forks surface as CategoryIncident with CodeTamperSignal; the
// different-signers case surfaces as Structural (caller bug).
func (e *ForkEvidence) AsError() error {
	if e == nil {
		return nil
	}
	if e.Kind.IsIncident() {
		return shared_errors.Incident(
			shared_errors.CodeTamperSignal,
			"witness: fork detected ("+string(e.Kind)+"): "+e.Detail,
			nil,
		)
	}
	return shared_errors.Structural(
		shared_errors.CodeCrossFieldInconsistent,
		"witness: inconsistent signers ("+string(e.Kind)+"): "+e.Detail,
		nil,
	)
}

// DetectFork compares two STHs and returns ForkEvidence if they are
// mutually inconsistent — with an optional consistency proof bridging
// the pair when their sizes differ. Returns (nil, nil) when the pair
// is consistent.
//
// Ordering of arguments does NOT matter: the function normalizes so
// that the returned evidence's A has the smaller (or equal) TreeSize.
//
// Required invariant: a and b must carry the same SigningKeyID. If
// they do not, DetectFork returns a ForkKindDifferentSigners evidence
// (which surfaces as Structural, not Incident) so the caller can
// correct its book-keeping — two DIFFERENT operators are expected to
// have divergent STHs. The witness-log threat model says "honest
// append-only PER OPERATOR".
//
// When both sizes are equal, proof is ignored and MAY be nil.
// When sizes differ, proof is REQUIRED for the function to distinguish
// a legitimate append from a fork. If proof is nil and sizes differ,
// DetectFork returns ForkKindInconsistentProof — the caller could not
// produce a valid consistency proof, which itself is an Incident
// signal from an honest operator.
func DetectFork(a, b *SignedTreeHead, proof *ConsistencyProof) (*ForkEvidence, error) {
	if a == nil || b == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"witness: DetectFork: both STHs required",
			nil,
		)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	// Normalize: A is the smaller-or-equal size.
	x, y := a, b
	if x.TreeSize > y.TreeSize {
		x, y = y, x
	}

	// Signer check (not strictly a fork, but a caller-level sanity
	// gate). We run this BEFORE the equality checks because a caller
	// comparing STHs from two different operators will often see
	// "same size, different root" as their first symptom — which
	// would be mislabeled as an Incident without this gate.
	if !signerEqual(x.SigningKeyID, y.SigningKeyID) {
		return &ForkEvidence{
			A:      *x,
			B:      *y,
			Kind:   ForkKindDifferentSigners,
			Detail: "a.signing_key_id=" + x.SigningKeyID.String() + " b.signing_key_id=" + y.SigningKeyID.String(),
		}, nil
	}

	// Case 1: equal sizes.
	if x.TreeSize == y.TreeSize {
		if !bytes.Equal(x.TreeHash, y.TreeHash) {
			return &ForkEvidence{
				A:      *x,
				B:      *y,
				Kind:   ForkKindSameSizeDifferentRoot,
				Detail: "tree_size=" + formatUint(x.TreeSize),
			}, nil
		}
		if !bytes.Equal(x.TreeChainHead, y.TreeChainHead) {
			return &ForkEvidence{
				A:      *x,
				B:      *y,
				Kind:   ForkKindSameSizeDifferentChainHead,
				Detail: "tree_size=" + formatUint(x.TreeSize),
			}, nil
		}
		// Same size, same root, same chain head — consistent. (We do
		// NOT check Timestamp equality here; two valid STHs at the
		// same tree size MAY carry different Timestamps if the
		// operator re-published, and this is not a fork.)
		return nil, nil
	}

	// Case 2: differing sizes. Timestamp gate first — non-monotonic
	// is an Incident regardless of Merkle math.
	if y.Timestamp.Before(x.Timestamp) {
		return &ForkEvidence{
			A:      *x,
			B:      *y,
			Kind:   ForkKindTimestampNonMonotonic,
			Detail: "a.tree_size=" + formatUint(x.TreeSize) + " b.tree_size=" + formatUint(y.TreeSize),
		}, nil
	}

	// Consistency proof gate. Missing proof with differing sizes =
	// inconsistency (we cannot prove the pair is legitimate).
	if proof == nil {
		return &ForkEvidence{
			A:      *x,
			B:      *y,
			Kind:   ForkKindInconsistentProof,
			Detail: "consistency_proof missing",
		}, nil
	}
	if proof.OldSize != x.TreeSize || proof.NewSize != y.TreeSize {
		return &ForkEvidence{
			A:      *x,
			B:      *y,
			Kind:   ForkKindInconsistentProof,
			Detail: "consistency_proof sizes disagree with STHs",
		}, nil
	}
	if err := VerifyConsistency(x.TreeHash, y.TreeHash, proof); err != nil {
		return &ForkEvidence{
			A:      *x,
			B:      *y,
			Kind:   ForkKindInconsistentProof,
			Detail: "consistency proof failed: " + err.Error(),
		}, nil
	}
	// Consistency proof passed and timestamps are monotonic —
	// honest append.
	return nil, nil
}

// signerEqual is a tiny helper that centralizes the comparison —
// makes the DetectFork branching a little easier to read.
func signerEqual(a, b ids.KeyID) bool {
	return a.String() == b.String()
}

// formatUint is a dependency-free uint64→decimal formatter used only
// to build Detail strings. Avoids pulling strconv into this file for
// one call site — keeps the import list minimal.
func formatUint(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
