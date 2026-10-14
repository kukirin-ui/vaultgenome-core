// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
	witness_op "github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- key ids shared across tests ------------------------------------------

const (
	kidAuthority = ids.KeyID("vault-auth-1")
	kidRunner    = ids.KeyID("probe-runner-1")
	kidWitness   = ids.KeyID("witness-op-1")
)

// issuerEpoch is the canonical wall-clock moment tests use for all
// time-dependent fixtures. Tests that need the issuer clock to advance
// between operations derive offsets from this anchor.
var issuerEpoch = time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC)

// ---- key + agd + witness-log scaffolding ----------------------------------

// newKeystore returns an InMemoryStore seeded with the three signing
// keys every disclosure fixture uses.
func newKeystore(t *testing.T) *keys.InMemoryStore {
	t.Helper()
	fc := shared_time.NewFakeClock(issuerEpoch)
	s := keys.NewInMemoryStore(fc)
	_, err := s.GenerateSigning(kidAuthority, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = s.GenerateSigning(kidRunner, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = s.GenerateSigning(kidWitness, keys.PurposeSigningWitness)
	require.NoError(t, err)
	return s
}

// newAGDStore returns an empty AGD CAS backed by the given resolver.
func newAGDStore(t *testing.T, resolver keys.Resolver) *store.InMemoryStore {
	t.Helper()
	s, err := store.NewInMemoryStore(resolver)
	require.NoError(t, err)
	return s
}

// newWitnessLog constructs an InMemoryLog signing STHs under kidWitness
// and driven by a fake clock seeded to logEpoch. Shared with the issuer
// so STH.Timestamp aligns with IssuedAt in the common case.
func newWitnessLog(t *testing.T, signer keys.Signer, logEpoch time.Time) (*witness_op.InMemoryLog, shared_time.Clock) {
	t.Helper()
	fc := shared_time.NewFakeClock(logEpoch)
	l, err := witness_op.NewInMemoryLog(signer, kidWitness, fc)
	require.NoError(t, err)
	return l, fc
}

// repeat returns a length-n slice where every byte equals b.
func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// ---- probe battery + scorecard + attestation ------------------------------

// buildBattery returns a signed, validated ProbeBattery.
func buildBattery(t *testing.T, signer keys.Signer) *probe_battery.ProbeBattery {
	t.Helper()
	probes := []probe_battery.Probe{
		{
			Kind:              probe_battery.ProbeKindIdentity,
			InputHash:         repeat(0x01, crypto.HashSize),
			ExpectedShapeHash: repeat(0xA1, crypto.HashSize),
			Label:             "identity-alpha",
		},
		{
			Kind:              probe_battery.ProbeKindCapability,
			InputHash:         repeat(0x02, crypto.HashSize),
			ExpectedShapeHash: nil,
			Label:             "capability-beta",
		},
	}
	for i := range probes {
		id, err := probes[i].DeriveID()
		require.NoError(t, err)
		probes[i].ID = id
	}
	b := &probe_battery.ProbeBattery{
		SchemaVersion: probe_battery.SchemaVersionCurrent,
		Name:          "continuity-issuer-test-v1",
		Probes:        probes,
		Policy:        probe_battery.DefaultTolerancePolicy(),
		IssuedAt:      issuerEpoch.Add(-2 * time.Hour),
		SigningKeyID:  kidRunner,
	}
	root, err := b.DeriveMerkleRoot()
	require.NoError(t, err)
	b.MerkleRoot = root
	require.NoError(t, b.SignWith(signer))
	require.NoError(t, b.Validate())
	return b
}

// scoreEntriesFor builds deterministic score entries covering b's probes.
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

// deriveScoreRoot returns MerkleRoot over entries — useful before the
// subject AGD is signed (scorecard.MerkleRoot is entries-only).
func deriveScoreRoot(t *testing.T, entries []probe_battery.ScoreEntry) []byte {
	t.Helper()
	tmp := &probe_battery.Scorecard{Entries: entries}
	root, err := tmp.DeriveMerkleRoot()
	require.NoError(t, err)
	return root
}

// signedScorecard constructs a signed scorecard bound to subjectID,
// battery roots, and entries. Callers can then mutate a field and
// re-sign to exercise negative paths — the helper keeps the common
// happy-path construction terse.
func signedScorecard(
	t *testing.T,
	signer keys.Signer,
	subjectID ids.GenomeID,
	batteryName string,
	batteryRoot []byte,
	entries []probe_battery.ScoreEntry,
	measuredAt time.Time,
) *probe_battery.Scorecard {
	t.Helper()
	root, err := (&probe_battery.Scorecard{Entries: entries}).DeriveMerkleRoot()
	require.NoError(t, err)
	sc := &probe_battery.Scorecard{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          subjectID,
		BatteryName:       batteryName,
		BatteryMerkleRoot: append([]byte(nil), batteryRoot...),
		Entries:           append([]probe_battery.ScoreEntry(nil), entries...),
		MerkleRoot:        root,
		MeasuredAt:        measuredAt,
		SigningKeyID:      kidRunner,
	}
	require.NoError(t, sc.SignWith(signer))
	require.NoError(t, sc.Validate())
	return sc
}

// signedAttestation constructs a signed attestation that cross-binds
// scorecard + battery roots under the same subject.
func signedAttestation(
	t *testing.T,
	signer keys.Signer,
	subjectID ids.GenomeID,
	batteryName string,
	batteryRoot, scorecardRoot []byte,
	runStart, runEnd, issuedAt time.Time,
) *probe_battery.ProbeAttestation {
	t.Helper()
	a := &probe_battery.ProbeAttestation{
		SchemaVersion:     probe_battery.SchemaVersionCurrent,
		GenomeID:          subjectID,
		BatteryName:       batteryName,
		BatteryMerkleRoot: append([]byte(nil), batteryRoot...),
		ScorecardRoot:     append([]byte(nil), scorecardRoot...),
		RunnerIdentity:    "runner:alpha-test",
		TEEMeasurement:    repeat(0xC3, crypto.HashSize),
		RunStartedAt:      runStart,
		RunCompletedAt:    runEnd,
		IssuedAt:          issuedAt,
		SigningKeyID:      kidRunner,
	}
	require.NoError(t, a.SignWith(signer))
	require.NoError(t, a.Validate())
	return a
}

// ---- AGD construction ------------------------------------------------------

// agdSkeleton returns a partially-populated descriptor with behavioral
// fingerprint filled from the caller's battery/scores roots.
func agdSkeleton(family string, generation uint64, batteryRoot, scoresRoot []byte) genome_descriptor.GenomeDescriptor {
	issued := issuerEpoch.Add(-1 * time.Hour)
	produced := issuerEpoch.Add(-6 * time.Hour)
	// ComponentTreeRoot must differ per generation so derived GenomeIDs
	// diverge even when behavioral roots are shared.
	ctr := repeat(0xB0+byte(generation), crypto.HashSize)
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
		ComponentTreeRoot: ctr,
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

// signAGD runs Derive → Sign → Validate on g.
func signAGD(t *testing.T, signer keys.Signer, g *genome_descriptor.GenomeDescriptor) {
	t.Helper()
	id, err := g.DeriveID()
	require.NoError(t, err)
	g.GenomeID = id
	require.NoError(t, g.SignWith(signer))
	require.NoError(t, g.Validate())
}

// putAGD stores g in the CAS. Returns the stored GenomeID for terseness.
func putAGD(t *testing.T, s *store.InMemoryStore, g *genome_descriptor.GenomeDescriptor) ids.GenomeID {
	t.Helper()
	id, err := s.Put(g)
	require.NoError(t, err)
	return id
}

// ---- fixture bundling every object the issuer needs ----------------------

// fixture is a complete, valid end-to-end scaffold: three keys, a
// battery, a two-generation ancestry, the scorecard + attestation
// that would be fed into Issue, a populated AGD store, and a witness
// log driven by the same clock as the issuer. Tests clone-then-mutate
// one piece at a time to exercise negative paths.
type fixture struct {
	Keystore    *keys.InMemoryStore
	AGDStore    *store.InMemoryStore
	Log         *witness_op.InMemoryLog
	Clock       shared_time.Clock
	Battery     *probe_battery.ProbeBattery
	Parent      genome_descriptor.GenomeDescriptor
	Subject     genome_descriptor.GenomeDescriptor
	Scorecard   *probe_battery.Scorecard
	Attestation *probe_battery.ProbeAttestation
}

// newFixture builds a fresh fixture. Flow:
//
//  1. Create keystore + AGD store + shared-clock witness log.
//  2. Sign battery, derive scoreRoot from entries.
//  3. Sign parent AGD (genesis, generation 0).
//  4. Sign subject AGD (generation 1, DerivedFrom parent via fine-tune).
//  5. Put both AGDs in the store.
//  6. Sign scorecard bound to Subject.GenomeID + battery root + score root.
//  7. Sign attestation citing scorecard + battery roots.
func newFixture(t *testing.T) fixture {
	t.Helper()

	ks := newKeystore(t)
	agds := newAGDStore(t, ks)
	log, clk := newWitnessLog(t, ks, issuerEpoch)

	battery := buildBattery(t, ks)
	batteryRoot := append([]byte(nil), battery.MerkleRoot...)

	entries := scoreEntriesFor(battery)
	scoreRoot := deriveScoreRoot(t, entries)

	// Parent: genesis, different behavioral root so its derived ID
	// differs from subject's.
	parentScoreRoot := repeat(0xF1, crypto.HashSize)
	parent := agdSkeleton("parent-family", 0, batteryRoot, parentScoreRoot)
	signAGD(t, ks, &parent)

	subject := agdSkeleton("continuity-llm", 1, batteryRoot, scoreRoot)
	subject.Provenance.DerivedFrom = []genome_descriptor.GenomeDerivation{
		{ParentGenomeID: parent.GenomeID, Method: genome_descriptor.DerivationFineTune},
	}
	signAGD(t, ks, &subject)

	putAGD(t, agds, &parent)
	putAGD(t, agds, &subject)

	measuredAt := issuerEpoch.Add(-30 * time.Minute)
	scorecard := signedScorecard(t, ks, subject.GenomeID, battery.Name, batteryRoot, entries, measuredAt)

	attestation := signedAttestation(
		t, ks,
		subject.GenomeID, battery.Name, batteryRoot, scorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute),
		issuerEpoch.Add(-35*time.Minute),
		issuerEpoch.Add(-25*time.Minute),
	)

	return fixture{
		Keystore:    ks,
		AGDStore:    agds,
		Log:         log,
		Clock:       clk,
		Battery:     battery,
		Parent:      parent,
		Subject:     subject,
		Scorecard:   scorecard,
		Attestation: attestation,
	}
}
