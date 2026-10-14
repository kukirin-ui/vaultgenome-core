// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/continuity_proof"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- ancestor chain linkage -----------------------------------------------

// A parent whose generation is not strictly below its child's is refused
// as an Incident (tamper signal). Every AGD here is well formed and passes
// its own Validate — generation>0 with a parent, generation 0 without —
// so only the chain-level gate can see the inverted edge.
func TestContinuityProof_Validate_AncestorChain_GenerationNotMonotonic(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	batteryRoot := f.Scorecard.BatteryMerkleRoot

	genesis := agdSkeleton("genesis-family", 0, batteryRoot, repeat(0xF2, crypto.HashSize))
	signAGD(t, f.Store, &genesis)

	elder := agdSkeleton("elder-family", 2, batteryRoot, repeat(0xF3, crypto.HashSize))
	elder.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: genesis.GenomeID, Method: genome_descriptor.DerivationDistill},
	}
	signAGD(t, f.Store, &elder)

	// Generation 1 citing a generation-2 parent: the edge runs backwards.
	child := agdSkeleton("continuity-llm", 1, batteryRoot, f.Scorecard.MerkleRoot)
	child.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: elder.GenomeID, Method: genome_descriptor.DerivationFineTune},
	}
	signAGD(t, f.Store, &child)

	p := buildProof(t, f)
	p.Subject = child.GenomeID
	p.AncestorChain = []genome_descriptor.GenomeDescriptor{child, elder, genesis}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeTamperSignal, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "generation monotonicity violated at "+child.GenomeID.String())
}

// A dangling parent reference deeper in the chain — on an ancestor's edge,
// not the Subject's own — is caught too, and the refusal names the index
// of the AGD that cites the absent parent.
func TestContinuityProof_Validate_AncestorChain_DanglingParentDeepInChain(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	batteryRoot := f.Scorecard.BatteryMerkleRoot

	// A real genesis that the chain fails to carry.
	absent := agdSkeleton("absent-family", 0, batteryRoot, repeat(0xF4, crypto.HashSize))
	signAGD(t, f.Store, &absent)

	middle := agdSkeleton("middle-family", 1, batteryRoot, repeat(0xF5, crypto.HashSize))
	middle.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: absent.GenomeID, Method: genome_descriptor.DerivationQuantize},
	}
	signAGD(t, f.Store, &middle)

	child := agdSkeleton("continuity-llm", 2, batteryRoot, f.Scorecard.MerkleRoot)
	child.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: middle.GenomeID, Method: genome_descriptor.DerivationFineTune},
	}
	signAGD(t, f.Store, &child)

	p := buildProof(t, f)
	p.Subject = child.GenomeID
	p.AncestorChain = []genome_descriptor.GenomeDescriptor{child, middle}
	err := p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "ancestor_chain[1] cites unknown parent "+absent.GenomeID.String())
}

// ---- cross-field bindings -------------------------------------------------

// A scorecard measured over different answers — well formed, correctly
// rooted, signed by the runner, naming the right genome and battery —
// still does not bind: its merkle_root is not the canonical_scores_root
// the Subject's AGD committed to.
func TestContinuityProof_Validate_ScorecardRootNotSubjectsCommitment(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	other := *f.Scorecard
	other.Entries = scoreEntriesFor(f.Battery)
	other.Entries[0].ResponseHash = repeat(0x5C, crypto.HashSize)
	root, err := other.DeriveMerkleRoot()
	require.NoError(t, err)
	other.MerkleRoot = root
	other.Signature = nil
	require.NoError(t, other.SignWith(f.Store))
	require.NoError(t, other.Validate())

	p := buildProof(t, f)
	p.ProbeScorecard = other
	err = p.Validate()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "probe_scorecard.merkle_root != subject.behavioral_fingerprint.canonical_scores_root")
}

// A receipt for a different commitment — a real entry of the same witness
// log, included under a signed tree head, naming the Subject — does not
// bind unless it commits to exactly the battery root and the scorecard
// root the scorecard carries.
func TestContinuityProof_Validate_WitnessEntryRootsNotScorecards(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	batteryRoot := f.Scorecard.BatteryMerkleRoot
	scoreRoot := f.Scorecard.MerkleRoot

	t.Run("battery_merkle_root", func(t *testing.T) {
		other := appendAndReceipt(t, f.Log, f.Subject.GenomeID,
			f.AttestationRoot, repeat(0xB7, crypto.HashSize), scoreRoot, f.STHTime)
		p := buildProof(t, f)
		p.WitnessReceipt = *other
		err := p.Validate()
		require.Error(t, err)
		require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
		require.ErrorContains(t, err, "witness_receipt.entry.battery_merkle_root != probe_scorecard.battery_merkle_root")
	})
	t.Run("scorecard_root", func(t *testing.T) {
		other := appendAndReceipt(t, f.Log, f.Subject.GenomeID,
			f.AttestationRoot, batteryRoot, repeat(0x5C, crypto.HashSize), f.STHTime)
		p := buildProof(t, f)
		p.WitnessReceipt = *other
		err := p.Validate()
		require.Error(t, err)
		require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
		require.ErrorContains(t, err, "witness_receipt.entry.scorecard_root != probe_scorecard.merkle_root")
	})
}

// ---- Verify: the inner signatures ------------------------------------------

// Verify re-checks the scorecard's runner signature after Validate has
// accepted the scorecard's shape and Merkle root: a scorecard whose
// signature does not verify is refused as Integrity.
func TestContinuityProof_Verify_ScorecardSignatureRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	p.ProbeScorecard.Signature = append([]byte(nil), p.ProbeScorecard.Signature...)
	p.ProbeScorecard.Signature[0] ^= 0x01
	require.NoError(t, p.Validate(), "the shape and Merkle gates do not see the signature")

	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
}

// Verify re-checks the witness operator's signature on the tree head after
// Validate has accepted the receipt's inclusion proof: a tree head whose
// signature does not verify is refused as Integrity.
func TestContinuityProof_Verify_WitnessSTHSignatureRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	p := buildProof(t, f)
	p.WitnessReceipt.STH.Signature = append([]byte(nil), p.WitnessReceipt.STH.Signature...)
	p.WitnessReceipt.STH.Signature[0] ^= 0x01
	require.NoError(t, p.Validate(), "the inclusion gate does not see the signature")

	err := p.Verify(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSignatureInvalid, shared_errors.CodeOf(err))
}

// ---- signer and resolver refusals -----------------------------------------

// SignWith asks the signer for p.SigningKeyID under PurposeSigningAuthority
// and passes its refusal through unchanged: a store without that key
// refuses as Authority, and the witness operator's key — held under
// PurposeSigningWitness — cannot sign a continuity proof (Integrity).
// Either way the bundle stays unsigned.
func TestContinuityProof_SignWith_SignerRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	p := buildProof(t, f)
	p.SigningKeyID = ids.KeyID("vault-auth-unknown")
	p.Signature = nil
	err := p.SignWith(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))
	require.Empty(t, p.Signature)

	p = buildProof(t, f)
	p.SigningKeyID = kidWitness
	p.Signature = nil
	err = p.SignWith(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Empty(t, p.Signature)
}

// VerifySignature on its own — the outer authority signature only —
// refuses a nil resolver and an unsigned bundle as Structural before any
// key is looked up, and passes the resolver's refusal through for a
// well-formed bundle: Authority when the resolver does not hold the kid,
// Integrity when it holds the kid under another purpose.
func TestContinuityProof_VerifySignature_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	p := buildProof(t, f)
	err := p.VerifySignature(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))

	p = buildProof(t, f)
	p.Signature = nil
	err = p.VerifySignature(f.Store)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))

	p = buildProof(t, f)
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	empty := keys.NewInMemoryStore(fc)
	err = p.VerifySignature(empty)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryAuthority, shared_errors.CategoryOf(err))

	witnessOnly := keys.NewInMemoryStore(fc)
	_, err = witnessOnly.GenerateSigning(kidAuthority, keys.PurposeSigningWitness)
	require.NoError(t, err)
	err = p.VerifySignature(witnessOnly)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	require.NoError(t, p.VerifySignature(f.Store))
}

// ---- wire-format gates -----------------------------------------------------

// The schema gate runs at decode time, not only in Validate: a bundle
// written by a build this one does not understand is refused before any
// embedded object is interpreted.
func TestContinuityProof_UnmarshalJSON_SchemaOutOfRange(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	raw, err := json.Marshal(buildProof(t, f))
	require.NoError(t, err)

	// The bundle's own schema_version is the first key; the embedded
	// objects carry their own, which this test leaves alone.
	current := []byte(`{"schema_version":` + strconv.Itoa(int(continuity_proof.SchemaVersionCurrent)) + `,`)
	require.True(t, bytes.HasPrefix(raw, current), "outer schema_version must be the first key")
	unsupported := []byte(`{"schema_version":` + strconv.Itoa(int(continuity_proof.SchemaVersionMax)+1) + `,`)
	tampered := append(append([]byte(nil), unsupported...), raw[len(current):]...)

	var decoded continuity_proof.ContinuityProof
	err = decoded.UnmarshalJSON(tampered)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
}
