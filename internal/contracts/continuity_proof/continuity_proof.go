// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Schema versioning for the ContinuityProof wire format. All three
// constants advance together when the wire shape changes.
const (
	// SchemaVersionMin is the lowest format version this build accepts
	// on read.
	SchemaVersionMin uint16 = 1
	// SchemaVersionMax is the highest format version this build accepts
	// on read.
	SchemaVersionMax uint16 = 1
	// SchemaVersionCurrent is the version this build writes.
	SchemaVersionCurrent uint16 = 1
)

// ContinuityProof is the keystone bundle that binds an AGD's ancestry,
// behavioral scorecard, and transparency-log inclusion into one
// stateless-verifiable object.
//
// See doc.go for the doctrinal role and the Verify() order.
type ContinuityProof struct {
	// SchemaVersion gates the wire format. Readers MUST validate first.
	SchemaVersion uint16 `json:"schema_version"`

	// ProofID is an opaque stable handle assigned by the issuer. It is
	// NOT content-addressed — the bundle's bytes are already
	// self-authenticating via Signature. Required.
	ProofID ids.ContinuityProofID `json:"proof_id"`

	// Subject is the GenomeID this proof speaks for — the descendant
	// whose continuity is being attested. MUST equal
	// AncestorChain[0].GenomeID and WitnessReceipt.Entry.GenomeID and
	// ProbeScorecard.GenomeID.
	Subject ids.GenomeID `json:"subject"`

	// AncestorChain is the full, signed descent record, in pre-order
	// DFS from Subject toward roots. Index 0 is Subject's own AGD; at
	// least one element must be a generation-0 genesis (Generation=0
	// and Provenance.DerivedFrom empty). Every non-root AGD's
	// DerivedFrom parent MUST appear elsewhere in the chain — there
	// are no dangling parent references. Merge-parented DAGs are
	// expressed by listing a shared ancestor once; multiple children
	// cite it by GenomeID.
	AncestorChain []genome_descriptor.GenomeDescriptor `json:"ancestor_chain"`

	// ProbeScorecard is the signed scorecard binding the Subject's
	// current behavior to a specific probe battery. The scorecard's
	// BatteryMerkleRoot MUST match Subject's
	// BehavioralFingerprint.BatteryMerkleRoot and its MerkleRoot MUST
	// match Subject's BehavioralFingerprint.CanonicalScoresRoot.
	ProbeScorecard probe_battery.Scorecard `json:"probe_scorecard"`

	// WitnessReceipt is the RFC 6962 inclusion proof that binds the
	// three commitments (AttestationRoot, BatteryMerkleRoot,
	// ScorecardRoot) at a specific position of the witness operator's
	// log. The entry's GenomeID MUST equal Subject, its
	// BatteryMerkleRoot MUST equal ProbeScorecard.BatteryMerkleRoot,
	// and its ScorecardRoot MUST equal ProbeScorecard.MerkleRoot.
	WitnessReceipt witness.WitnessReceipt `json:"witness_receipt"`

	// IssuedAt is the wall-clock moment the issuer bound this bundle.
	// MUST NOT be earlier than WitnessReceipt.STH.Timestamp — an
	// issuer cannot predate a witness commitment it is citing.
	IssuedAt time.Time `json:"issued_at"`

	// SigningKeyID identifies the authority that signed this bundle.
	// Signatures use keys.PurposeSigningAuthority. The authority key
	// for this proof may differ from the keys that signed the inner
	// AGDs or scorecard — the proof's own signature binds the
	// ASSERTION "I, the issuing authority, vouch that this bundle is
	// internally consistent and that I stand behind its release."
	SigningKeyID ids.KeyID `json:"signing_key_id"`

	// Signature is the Ed25519 signature over CanonicalBytes (which
	// excludes Signature itself). Binds every field above.
	Signature []byte `json:"signature"`
}
