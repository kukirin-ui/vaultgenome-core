// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/continuity_proof"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	witness_contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	witness_op "github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- key material ----------------------------------------------------------

// kidAuthority signs every AGD in the ancestry chain and the outer
// ContinuityProof itself. Mirrors the production topology where a
// single vault authority key stands behind all continuity claims.
const (
	kidAuthority = ids.KeyID("vault-auth-1")
	kidRunner    = ids.KeyID("probe-runner-1")
	kidWitness   = ids.KeyID("witness-op-1")
)

// newFixtureStore constructs an InMemoryStore seeded with the three
// signing keys needed to build a ContinuityProof end-to-end.
func newFixtureStore(t *testing.T) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC))
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kidAuthority, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = s.GenerateSigning(kidRunner, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = s.GenerateSigning(kidWitness, keys.PurposeSigningWitness)
	require.NoError(t, err)
	return s
}

// repeat returns a length-n slice where every byte equals b.
func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// ---- probe battery (unsigned, deferred sign until after roots known) ------

// buildUnsignedBattery returns a ProbeBattery with MerkleRoot derived
// but Signature empty. Callers sign it after they've captured the
// MerkleRoot for AGD citation.
func buildUnsignedBattery(t *testing.T) *probe_battery.ProbeBattery {
	t.Helper()
	probes := []probe_battery.Probe{
		{
			Kind:              probe_battery.ProbeKindIdentity,
			InputHash:         repeat(0x01, crypto.HashSize),
			ExpectedShapeHash: repeat(0xA1, crypto.HashSize),
			Label:             "identity-alpha",
		},
		{
			Kind:              probe_battery.ProbeKindIdentity,
			InputHash:         repeat(0x02, crypto.HashSize),
			ExpectedShapeHash: repeat(0xA2, crypto.HashSize),
			Label:             "identity-beta",
		},
		{
			Kind:              probe_battery.ProbeKindCapability,
			InputHash:         repeat(0x03, crypto.HashSize),
			ExpectedShapeHash: nil,
			Label:             "capability-gamma",
		},
	}
	for i := range probes {
		id, err := probes[i].DeriveID()
		require.NoError(t, err)
		probes[i].ID = id
	}
	b := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "continuity-test-v1",
		Probes:        probes,
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID:  kidRunner,
	}
	root, err := b.DeriveMerkleRoot()
	require.NoError(t, err)
	b.MerkleRoot = root
	return b
}

// scoreEntriesFor builds deterministic entries matching b's probes.
func scoreEntriesFor(b *probe_battery.ProbeBattery) []probe_battery.ScoreEntry {
	entries := make([]probe_battery.ScoreEntry, len(b.Probes))
	for i := range b.Probes {
		h := make([]byte, crypto.HashSize)
		copy(h, b.Probes[i].InputHash)
		h[0] ^= 0xFE
		entries[i] = probe_battery.ScoreEntry{
			ProbeID:      b.Probes[i].ID,
			ResponseHash: h,
		}
	}
	return entries
}

// deriveScorecardRoot returns the MerkleRoot a scorecard over these
// entries would produce. Callers use this to populate AGDs' scores
// roots BEFORE signing either scorecard or AGD.
func deriveScorecardRoot(t *testing.T, entries []probe_battery.ScoreEntry) []byte {
	t.Helper()
	tmp := &probe_battery.Scorecard{Entries: entries}
	root, err := tmp.DeriveMerkleRoot()
	require.NoError(t, err)
	return root
}

// ---- AGD construction ------------------------------------------------------

// agdSkeleton returns a partially-populated descriptor with behavioral
// fingerprint filled from the caller's batteryRoot/scoresRoot.
func agdSkeleton(family string, generation uint64, batteryRoot, scoresRoot []byte) genome_descriptor.GenomeDescriptor {
	issued := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)
	produced := time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC)
	return genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    family,
		Generation:    generation,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 7_000_000_000,
			PrecisionBits:  16,
			ConfigHash:     repeat(0xA1, crypto.HashSize),
		},
		ComponentTreeRoot: repeat(0xB0+byte(generation), crypto.HashSize),
		ComponentCount:    512,
		TotalBytes:        14_000_000_000,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity: "producer:alpha-lab",
			ProducedAt:       produced,
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-v3",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    append([]byte(nil), batteryRoot...),
			CanonicalScoresRoot:  append([]byte(nil), scoresRoot...),
			ProbeCount:           256,
			MinPassingScore:      0.85,
		},
		IssuedAt:     issued,
		SigningKeyID: kidAuthority,
	}
}

// signAGD runs the canonical producer sequence: Derive → Sign →
// Validate. Mutates g in place.
func signAGD(t *testing.T, store *keys.InMemoryStore, g *genome_descriptor.GenomeDescriptor) {
	t.Helper()
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	require.NoError(t, g.SignWith(store))
	require.NoError(t, g.Validate())
}

// ---- witness receipt -------------------------------------------------------

// appendAndReceipt builds a LogEntry binding {genomeID, attestation,
// batteryRoot, scorecardRoot}, appends it to the witness log, and
// returns the inclusion receipt the operator produces.
func appendAndReceipt(
	t *testing.T,
	log *witness_op.InMemoryLog,
	genomeID ids.GenomeID,
	attestationRoot, batteryRoot, scorecardRoot []byte,
	when time.Time,
) *witness_contract.WitnessReceipt {
	t.Helper()
	entry := witness_contract.LogEntry{
		SchemaVersion:     witness_contract.SchemaVersionCurrent,
		Timestamp:         when,
		GenomeID:          genomeID,
		AttestationRoot:   append([]byte(nil), attestationRoot...),
		BatteryMerkleRoot: append([]byte(nil), batteryRoot...),
		ScorecardRoot:     append([]byte(nil), scorecardRoot...),
	}
	committed, err := log.Append(entry)
	require.NoError(t, err)
	receipt, err := log.Receipt(committed.Index)
	require.NoError(t, err)
	return receipt
}

// ---- whole fixture ---------------------------------------------------------

// fixture bundles every object a valid ContinuityProof refers to.
// Tests clone-then-mutate one piece at a time to probe negative
// paths.
type fixture struct {
	Store           *keys.InMemoryStore
	Battery         *probe_battery.ProbeBattery
	Parent          genome_descriptor.GenomeDescriptor
	Subject         genome_descriptor.GenomeDescriptor
	Scorecard       *probe_battery.Scorecard
	Receipt         *witness_contract.WitnessReceipt
	Log             *witness_op.InMemoryLog
	STHTime         time.Time
	AttestationRoot []byte
}

// newFixture builds a complete, valid, end-to-end ContinuityProof
// fixture. Flow (non-circular):
//
//  1. Build battery, derive MerkleRoot. (Don't sign yet — but sign is
//     safe here; battery's canonical bytes don't depend on Subject.)
//  2. Build scorecard entries; derive scoreRoot. (Scorecard's
//     MerkleRoot depends only on entries — no AGD needed.)
//  3. Sign parent AGD citing {batteryRoot, parentScoresRoot}.
//  4. Sign child AGD citing {batteryRoot, scoreRoot}, DerivedFrom
//     parent. This gives us Subject.GenomeID.
//  5. Sign scorecard with GenomeID = Subject.GenomeID.
//  6. Sign battery.
//  7. Append witness entry binding {Subject, att, batteryRoot,
//     scoreRoot}; take receipt.
func newFixture(t *testing.T) fixture {
	t.Helper()
	store := newFixtureStore(t)

	battery := buildUnsignedBattery(t)
	batteryRoot := append([]byte(nil), battery.MerkleRoot...)

	entries := scoreEntriesFor(battery)
	scoreRoot := deriveScorecardRoot(t, entries)

	parentScoresRoot := repeat(0xF1, crypto.HashSize)
	parent := agdSkeleton("parent-family", 0, batteryRoot, parentScoresRoot)
	signAGD(t, store, &parent)

	subject := agdSkeleton("continuity-llm", 1, batteryRoot, scoreRoot)
	subject.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: parent.GenomeID, Method: genome_descriptor.DerivationFineTune},
	}
	signAGD(t, store, &subject)

	// Scorecard bound to the Subject.
	scorecard := &probe_battery.Scorecard{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          subject.GenomeID,
		BatteryName:       battery.Name,
		BatteryMerkleRoot: append([]byte(nil), batteryRoot...),
		Entries:           entries,
		MerkleRoot:        append([]byte(nil), scoreRoot...),
		MeasuredAt:        time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC),
		SigningKeyID:      kidRunner,
	}
	require.NoError(t, scorecard.SignWith(store))
	require.NoError(t, scorecard.Validate())

	// Battery sign (deferred so all AGDs have seen MerkleRoot first).
	require.NoError(t, battery.SignWith(store))
	require.NoError(t, battery.Validate())

	// Witness log + receipt.
	sthTime := time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)
	fc := shared_time.NewFakeClock(sthTime)
	log, err := witness_op.NewInMemoryLog(store, kidWitness, fc)
	require.NoError(t, err)

	attRoot := repeat(0xAA, crypto.HashSize)
	receipt := appendAndReceipt(t, log, subject.GenomeID,
		attRoot, batteryRoot, scoreRoot, sthTime)

	return fixture{
		Store:           store,
		Battery:         battery,
		Parent:          parent,
		Subject:         subject,
		Scorecard:       scorecard,
		Receipt:         receipt,
		Log:             log,
		STHTime:         sthTime,
		AttestationRoot: attRoot,
	}
}

// buildProof composes a valid, signed ContinuityProof from f. The
// returned proof is self-consistent: p.Verify(f.Store) succeeds.
func buildProof(t *testing.T, f fixture) *continuity_proof.ContinuityProof {
	t.Helper()
	p := &continuity_proof.ContinuityProof{
		SchemaVersion:  continuity_proof.SchemaVersionCurrent,
		ProofID:        ids.ContinuityProofID("proof-0001"),
		Subject:        f.Subject.GenomeID,
		AncestorChain:  []genome_descriptor.GenomeDescriptor{f.Subject, f.Parent},
		ProbeScorecard: *f.Scorecard,
		WitnessReceipt: *f.Receipt,
		IssuedAt:       f.STHTime.Add(time.Minute),
		SigningKeyID:   kidAuthority,
	}
	require.NoError(t, p.SignWith(f.Store))
	return p
}
