// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/probe_battery"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// fixtures builds one signed battery, scorecard and attestation under two
// keys so each refusal test starts from a document that verifies.
type fixtures struct {
	store       *keys.InMemoryStore
	batKID      ids.KeyID
	runnerKID   ids.KeyID
	battery     *probe_battery.ProbeBattery
	scorecard   *probe_battery.Scorecard
	attestation *probe_battery.ProbeAttestation
}

func newFixtures(t *testing.T) fixtures {
	t.Helper()
	batKID := ids.KeyID("battery-signer")
	runnerKID := ids.KeyID("probe-runner-7")
	store := newAuthStore(t, batKID)
	_, err := store.GenerateSigning(runnerKID, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	b := newSignedBattery(t, store, batKID)
	s := newSignedScorecard(t, store, runnerKID, ids.GenomeID("gen:abc"), b, 0x00)
	a := newSignedAttestation(t, store, runnerKID, ids.GenomeID("gen:abc"), b, s)
	return fixtures{store: store, batKID: batKID, runnerKID: runnerKID, battery: b, scorecard: s, attestation: a}
}

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

func TestAttestation_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	rows := []struct {
		name string
		edit func(a *probe_battery.ProbeAttestation)
		code string
	}{
		{"schema below range", func(a *probe_battery.ProbeAttestation) { a.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"genome id missing", func(a *probe_battery.ProbeAttestation) { a.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"battery name missing", func(a *probe_battery.ProbeAttestation) { a.BatteryName = "" }, shared_errors.CodeRequiredFieldMissing},
		{"battery root short", func(a *probe_battery.ProbeAttestation) { a.BatteryMerkleRoot = a.BatteryMerkleRoot[:31] }, shared_errors.CodeFieldValueInvalid},
		{"scorecard root short", func(a *probe_battery.ProbeAttestation) { a.ScorecardRoot = nil }, shared_errors.CodeFieldValueInvalid},
		{"runner identity missing", func(a *probe_battery.ProbeAttestation) { a.RunnerIdentity = "" }, shared_errors.CodeRequiredFieldMissing},
		{"tee measurement of 33 bytes", func(a *probe_battery.ProbeAttestation) { a.TEEMeasurement = repeat(0x5A, 33) }, shared_errors.CodeFieldValueInvalid},
		{"run start missing", func(a *probe_battery.ProbeAttestation) { a.RunStartedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"run end missing", func(a *probe_battery.ProbeAttestation) { a.RunCompletedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"run ends before it starts", func(a *probe_battery.ProbeAttestation) { a.RunCompletedAt = a.RunStartedAt }, shared_errors.CodeCrossFieldInconsistent},
		{"issued at missing", func(a *probe_battery.ProbeAttestation) { a.IssuedAt = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"issued before the run ended", func(a *probe_battery.ProbeAttestation) { a.IssuedAt = a.RunCompletedAt.Add(-time.Second) }, shared_errors.CodeCrossFieldInconsistent},
		{"signing key missing", func(a *probe_battery.ProbeAttestation) { a.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(a *probe_battery.ProbeAttestation) { a.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			a := *f.attestation
			row.edit(&a)
			requireRefusal(t, a.Validate(), shared_errors.CategoryStructural, row.code)
			_, err := a.CanonicalBytes()
			require.Error(t, err, "canonical bytes of an invalid attestation")
			require.Error(t, a.VerifySignature(f.store), "verification of an invalid attestation")
		})
	}
	var nilAtt *probe_battery.ProbeAttestation
	requireRefusal(t, nilAtt.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, nilAtt.SignWith(f.store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	// Every TEE measurement width the doctrine admits is accepted.
	for _, n := range []int{32, 48, 64} {
		a := *f.attestation
		a.TEEMeasurement = repeat(0x5A, n)
		a.Signature = nil
		require.NoError(t, a.SignWith(f.store), "measurement of %d bytes", n)
		require.NoError(t, a.VerifySignature(f.store), "measurement of %d bytes", n)
	}
}

func TestAttestation_SignAndVerify_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)

	unsigned := *f.attestation
	unsigned.SigningKeyID = ""
	requireRefusal(t, unsigned.SignWith(f.store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	unknown := *f.attestation
	unknown.SigningKeyID = "nobody"
	require.Error(t, unknown.SignWith(f.store), "signing with a key the store does not hold")
	unknown.Signature = []byte{1}
	require.Error(t, unknown.VerifySignature(f.store), "resolving a key the store does not hold")

	requireRefusal(t, f.attestation.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
}

func TestAttestation_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	raw, err := json.Marshal(f.attestation)
	require.NoError(t, err)

	// json.Unmarshal refuses trailing bytes itself; the decoder's own check
	// is reached through the method.
	var trailing probe_battery.ProbeAttestation
	requireRefusal(t, trailing.UnmarshalJSON(append(append([]byte(nil), raw...), []byte(" {}")...)), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	var unknown probe_battery.ProbeAttestation
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":1,"extra":true}`), &unknown), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	var schema probe_battery.ProbeAttestation
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":99}`), &schema), shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported)
}

func TestScorecard_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	rows := []struct {
		name     string
		edit     func(s *probe_battery.Scorecard)
		category shared_errors.Category
		code     string
	}{
		{"schema below range", func(s *probe_battery.Scorecard) { s.SchemaVersion = 0 }, shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported},
		{"genome id missing", func(s *probe_battery.Scorecard) { s.GenomeID = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"battery name missing", func(s *probe_battery.Scorecard) { s.BatteryName = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"battery root short", func(s *probe_battery.Scorecard) { s.BatteryMerkleRoot = s.BatteryMerkleRoot[:1] }, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"no entries", func(s *probe_battery.Scorecard) { s.Entries = nil }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"merkle root short", func(s *probe_battery.Scorecard) { s.MerkleRoot = s.MerkleRoot[:31] }, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"measured at missing", func(s *probe_battery.Scorecard) { s.MeasuredAt = time.Time{} }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"signing key missing", func(s *probe_battery.Scorecard) { s.SigningKeyID = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(s *probe_battery.Scorecard) { s.Signature = nil }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"entry with a short response hash", func(s *probe_battery.Scorecard) {
			s.Entries = append([]probe_battery.ScoreEntry(nil), s.Entries...)
			s.Entries[0].ResponseHash = s.Entries[0].ResponseHash[:31]
		}, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"entry without a probe id", func(s *probe_battery.Scorecard) {
			s.Entries = append([]probe_battery.ScoreEntry(nil), s.Entries...)
			s.Entries[0].ProbeID = ""
		}, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"stored root disagrees with the entries", func(s *probe_battery.Scorecard) {
			s.MerkleRoot = append([]byte(nil), s.MerkleRoot...)
			s.MerkleRoot[0] ^= 0xFF
		}, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			s := *f.scorecard
			row.edit(&s)
			requireRefusal(t, s.Validate(), row.category, row.code)
			_, err := s.CanonicalBytes()
			require.Error(t, err)
			require.Error(t, s.VerifySignature(f.store))
		})
	}
	var nilCard *probe_battery.Scorecard
	requireRefusal(t, nilCard.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err := nilCard.DeriveMerkleRoot()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, nilCard.SignWith(f.store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err = (&probe_battery.Scorecard{}).DeriveMerkleRoot()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
}

func TestScorecard_SignAndVerify_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)

	noKey := *f.scorecard
	noKey.SigningKeyID = ""
	requireRefusal(t, noKey.SignWith(f.store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	noRoot := *f.scorecard
	noRoot.MerkleRoot = nil
	requireRefusal(t, noRoot.SignWith(f.store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	unknown := *f.scorecard
	unknown.SigningKeyID = "nobody"
	require.Error(t, unknown.SignWith(f.store))
	unknown.Signature = []byte{1}
	require.Error(t, unknown.VerifySignature(f.store))

	requireRefusal(t, f.scorecard.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
}

func TestScorecard_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	raw, err := json.Marshal(f.scorecard)
	require.NoError(t, err)
	var trailing probe_battery.Scorecard
	requireRefusal(t, trailing.UnmarshalJSON(append(append([]byte(nil), raw...), []byte(" 1")...)), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var unknown probe_battery.Scorecard
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":1,"extra":true}`), &unknown), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var schema probe_battery.Scorecard
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":0}`), &schema), shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported)
}

func TestBattery_Validate_RefusesEachDefect(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	rows := []struct {
		name     string
		edit     func(b *probe_battery.ProbeBattery)
		category shared_errors.Category
		code     string
	}{
		{"schema below range", func(b *probe_battery.ProbeBattery) { b.SchemaVersion = 0 }, shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported},
		{"name missing", func(b *probe_battery.ProbeBattery) { b.Name = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"merkle root short", func(b *probe_battery.ProbeBattery) { b.MerkleRoot = b.MerkleRoot[:31] }, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"no probes", func(b *probe_battery.ProbeBattery) { b.Probes = nil }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"probe without an id", func(b *probe_battery.ProbeBattery) {
			b.Probes = append([]probe_battery.Probe(nil), b.Probes...)
			b.Probes[0].ID = ""
		}, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"policy without entries", func(b *probe_battery.ProbeBattery) { b.Policy = probe_battery.TolerancePolicy{} }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"issued at missing", func(b *probe_battery.ProbeBattery) { b.IssuedAt = time.Time{} }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"signing key missing", func(b *probe_battery.ProbeBattery) { b.SigningKeyID = "" }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(b *probe_battery.ProbeBattery) { b.Signature = nil }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"the same probe twice", func(b *probe_battery.ProbeBattery) {
			b.Probes = append(append([]probe_battery.Probe(nil), b.Probes...), b.Probes[0])
		}, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent},
		{"stored root disagrees with the probes", func(b *probe_battery.ProbeBattery) {
			b.MerkleRoot = append([]byte(nil), b.MerkleRoot...)
			b.MerkleRoot[0] ^= 0xFF
		}, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			b := *f.battery
			row.edit(&b)
			requireRefusal(t, b.Validate(), row.category, row.code)
			_, err := b.CanonicalBytes()
			require.Error(t, err)
			require.Error(t, b.VerifySignature(f.store))
		})
	}
	var nilBattery *probe_battery.ProbeBattery
	requireRefusal(t, nilBattery.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err := nilBattery.DeriveMerkleRoot()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, nilBattery.SignWith(f.store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err = (&probe_battery.ProbeBattery{}).DeriveMerkleRoot()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
}

func TestBattery_SignAndVerify_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)

	unknown := *f.battery
	unknown.SigningKeyID = "nobody"
	require.Error(t, unknown.SignWith(f.store))
	unknown.Signature = []byte{1}
	require.Error(t, unknown.VerifySignature(f.store))

	requireRefusal(t, f.battery.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
}

func TestBattery_UnmarshalJSON_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	raw, err := json.Marshal(f.battery)
	require.NoError(t, err)
	var trailing probe_battery.ProbeBattery
	requireRefusal(t, trailing.UnmarshalJSON(append(append([]byte(nil), raw...), []byte(" null")...)), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var unknown probe_battery.ProbeBattery
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":1,"extra":true}`), &unknown), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var schema probe_battery.ProbeBattery
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":2}`), &schema), shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported)
}

func TestProbe_Validate_Refusals(t *testing.T) {
	t.Parallel()
	probes := buildProbes(t)

	noID := probes[0]
	noID.ID = ""
	requireRefusal(t, noID.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	swapped := probes[0]
	swapped.ID = probes[1].ID
	requireRefusal(t, swapped.Validate(), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	for _, kind := range []probe_battery.ProbeKind{probe_battery.ProbeKindIdentity, probe_battery.ProbeKindNegative} {
		bare := probe_battery.Probe{Kind: kind, InputHash: repeat(0x01, crypto.HashSize), Label: "bare"}
		_, err := bare.DeriveID()
		requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent)
	}
	odd := probe_battery.Probe{Kind: probe_battery.ProbeKindCapability, InputHash: repeat(0x01, crypto.HashSize), ExpectedShapeHash: repeat(0x02, 5)}
	_, err := odd.DeriveID()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
}

func TestTolerancePolicy_Validate_Refusals(t *testing.T) {
	t.Parallel()
	var nilPolicy *probe_battery.TolerancePolicy
	requireRefusal(t, nilPolicy.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, (&probe_battery.TolerancePolicy{}).Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	missing := probe_battery.DefaultTolerancePolicy()
	delete(missing.MaxCapabilityDrift, genome_descriptor.DerivationMerge)
	requireRefusal(t, missing.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	negative := probe_battery.DefaultTolerancePolicy()
	negative.MaxCapabilityDrift[genome_descriptor.DerivationDistill] = -0.01
	requireRefusal(t, negative.Validate(), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	generous := probe_battery.DefaultTolerancePolicy()
	generous.MaxCapabilityDrift[genome_descriptor.DerivationFineTune] = probe_battery.MaxDriftFineTune + 0.01
	requireRefusal(t, generous.Validate(), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	stranger := probe_battery.DefaultTolerancePolicy()
	stranger.MaxCapabilityDrift[genome_descriptor.DerivationMethod("teleport")] = 0
	requireRefusal(t, stranger.Validate(), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	_, err := probe_battery.MethodBudget(genome_descriptor.DerivationMethod("teleport"))
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
}

func TestCompare_Refusals(t *testing.T) {
	t.Parallel()
	f := newFixtures(t)
	b := f.battery
	parent := newSignedScorecard(t, f.store, f.runnerKID, "gen:parent", b, 0x00)
	child := newSignedScorecard(t, f.store, f.runnerKID, "gen:child", b, 0x00)
	method := genome_descriptor.DerivationFineTune

	_, err := probe_battery.Compare(nil, child, b, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err = probe_battery.Compare(parent, nil, b, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err = probe_battery.Compare(parent, child, nil, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	_, err = probe_battery.Compare(parent, child, b, method, probe_battery.TolerancePolicy{})
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	unknownMethod := genome_descriptor.DerivationMethod("teleport")
	lax := probe_battery.TolerancePolicy{MaxCapabilityDrift: map[genome_descriptor.DerivationMethod]float64{unknownMethod: 0.5}}
	_, err = probe_battery.Compare(parent, child, b, unknownMethod, lax)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	generous := probe_battery.DefaultTolerancePolicy()
	generous.MaxCapabilityDrift[method] = probe_battery.MaxDriftFineTune + 0.1
	_, err = probe_battery.Compare(parent, child, b, method, generous)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	elsewhere := *child
	elsewhere.BatteryMerkleRoot = child.BatteryMerkleRoot[:31]
	_, err = probe_battery.Compare(parent, &elsewhere, b, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryIntegrity, shared_errors.CodeCrossFieldInconsistent)

	otherBattery := *b
	otherBattery.MerkleRoot = repeat(0xEE, crypto.HashSize)
	_, err = probe_battery.Compare(parent, child, &otherBattery, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryIntegrity, shared_errors.CodeCrossFieldInconsistent)

	fewer := *parent
	fewer.Entries = parent.Entries[:len(parent.Entries)-1]
	_, err = probe_battery.Compare(&fewer, child, b, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent)
	_, err = probe_battery.Compare(parent, &fewer, b, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent)

	renamed := *child
	renamed.Entries = append([]probe_battery.ScoreEntry(nil), child.Entries...)
	renamed.Entries[0].ProbeID = probe_battery.ProbeID(probe_battery.ProbeIDPrefix + "ffff")
	_, err = probe_battery.Compare(parent, &renamed, b, method, b.Policy)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent)
}
