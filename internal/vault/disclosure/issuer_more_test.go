// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	witness_contract "github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
	witness_op "github.com/vault-genome/vaultgenome-core/internal/genome/witness"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// failingLog is a witness log that refuses at the step it is told to.
type failingLog struct {
	witness_op.Log
	appendErr  error
	receiptErr error
}

func (l *failingLog) Append(e witness_contract.LogEntry) (*witness_contract.LogEntry, error) {
	if l.appendErr != nil {
		return nil, l.appendErr
	}
	return l.Log.Append(e)
}

func (l *failingLog) Receipt(i uint64) (*witness_contract.WitnessReceipt, error) {
	if l.receiptErr != nil {
		return nil, l.receiptErr
	}
	return l.Log.Receipt(i)
}

// hidingStore is an AGD store that no longer holds one descriptor.
type hidingStore struct {
	store.Store
	hidden ids.GenomeID
}

func (s hidingStore) Get(id ids.GenomeID) (*genome_descriptor.GenomeDescriptor, error) {
	if id == s.hidden {
		return nil, shared_errors.Authority(shared_errors.CodeRequiredFieldMissing, "store: unknown genome "+id.String(), nil)
	}
	return s.Store.Get(id)
}

func (s hidingStore) Exists(id ids.GenomeID) bool { return id != s.hidden && s.Store.Exists(id) }

// refusingSigner signs nothing, the way a signing service that went away
// would.
type refusingSigner struct{}

func (refusingSigner) Sign(ids.KeyID, keys.Purpose, []byte) ([]byte, error) {
	return nil, shared_errors.Operational("signer_offline", "signer offline", nil)
}

// Inputs that do not validate on their own are refused before anything
// is committed to the witness log, with the contract's own code.
func TestIssuer_Issue_RefusesInputsThatDoNotValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*disclosure.IssueParams)
	}{
		{"scorecard schema unsupported", func(p *disclosure.IssueParams) { p.Scorecard.SchemaVersion = 0 }},
		{"attestation schema unsupported", func(p *disclosure.IssueParams) { p.Attestation.SchemaVersion = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			iss := newIssuer(t, f, disclosure.Options{})
			p := issueParamsFrom(f)
			tc.mutate(&p)
			proof, err := iss.Issue(p)
			require.Nil(t, proof)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
			require.Equal(t, shared_errors.CodeSchemaVersionUnsupported, shared_errors.CodeOf(err))
			require.Zero(t, f.Log.Size(), "nothing is witnessed for an input that does not validate")
		})
	}
}

// A scorecard whose scores root is not the one the subject's descriptor
// commits to is refused — even when it is signed, bound to the subject
// and cited by its attestation — and nothing is witnessed.
func TestIssuer_Issue_ScorecardScoresRootMismatchesSubjectAGD(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	entries := scoreEntriesFor(f.Battery)
	entries[0].ResponseHash[0] ^= 0x01
	batteryRoot := append([]byte(nil), f.Battery.MerkleRoot...)
	scorecard := signedScorecard(t, f.Keystore, f.Subject.GenomeID, f.Battery.Name, batteryRoot, entries, issuerEpoch.Add(-30*time.Minute))
	require.NotEqual(t, f.Subject.BehavioralFingerprint.CanonicalScoresRoot, scorecard.MerkleRoot)
	attestation := signedAttestation(t, f.Keystore, f.Subject.GenomeID, f.Battery.Name, batteryRoot, scorecard.MerkleRoot,
		issuerEpoch.Add(-45*time.Minute), issuerEpoch.Add(-35*time.Minute), issuerEpoch.Add(-25*time.Minute))

	iss := newIssuer(t, f, disclosure.Options{})
	proof, err := iss.Issue(disclosure.IssueParams{GenomeID: f.Subject.GenomeID, Scorecard: *scorecard, Attestation: *attestation})
	require.Nil(t, proof)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeCrossFieldInconsistent, shared_errors.CodeOf(err))
	require.ErrorContains(t, err, "canonical_scores_root")
	require.Zero(t, f.Log.Size())
}

// A subject whose ancestor the store no longer holds has no provable
// chain: the walk fails, the error names the missing genome, and nothing
// is witnessed.
func TestIssuer_Issue_AncestorMissingFromStore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss, err := disclosure.NewIssuer(f.Clock, f.Keystore, f.Keystore, kidAuthority,
		hidingStore{Store: f.AGDStore, hidden: f.Parent.GenomeID}, f.Log, disclosure.Options{})
	require.NoError(t, err)

	proof, err := iss.Issue(issueParamsFrom(f))
	require.Nil(t, proof)
	require.Error(t, err)
	require.ErrorContains(t, err, f.Parent.GenomeID.String())
	require.Zero(t, f.Log.Size(), "nothing is witnessed for a chain that cannot be walked")

	// With the parent back, the same inputs issue.
	iss = newIssuer(t, f, disclosure.Options{})
	proof, err = iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	require.Len(t, proof.AncestorChain, 2)
}

// The witness log is the step that commits: a refused append leaves
// nothing behind, while a receipt that cannot be produced leaves the
// committed entry in the log, as the append-only contract says.
func TestIssuer_Issue_WitnessLogFailures(t *testing.T) {
	t.Parallel()
	appendErr := errors.New("witness log append refused")
	receiptErr := errors.New("witness log receipt unavailable")
	cases := []struct {
		name    string
		log     func(witness_op.Log) *failingLog
		want    error
		entries uint64
	}{
		{"append refused", func(l witness_op.Log) *failingLog { return &failingLog{Log: l, appendErr: appendErr} }, appendErr, 0},
		{"receipt unavailable", func(l witness_op.Log) *failingLog { return &failingLog{Log: l, receiptErr: receiptErr} }, receiptErr, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			iss, err := disclosure.NewIssuer(f.Clock, f.Keystore, f.Keystore, kidAuthority, f.AGDStore, tc.log(f.Log), disclosure.Options{})
			require.NoError(t, err)
			proof, err := iss.Issue(issueParamsFrom(f))
			require.Nil(t, proof)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, tc.entries, f.Log.Size())
		})
	}
}

// A proof is never dated before the tree head it carries: when the
// witness log's clock runs ahead of the issuer's, the proof takes the
// head's time, and still validates.
func TestIssuer_Issue_IssuedAtNeverPredatesTheSTH(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ahead := issuerEpoch.Add(90 * time.Minute)
	log, _ := newWitnessLog(t, f.Keystore, ahead)
	iss, err := disclosure.NewIssuer(f.Clock, f.Keystore, f.Keystore, kidAuthority, f.AGDStore, log, disclosure.Options{})
	require.NoError(t, err)

	proof, err := iss.Issue(issueParamsFrom(f))
	require.NoError(t, err)
	require.Equal(t, ahead, proof.WitnessReceipt.STH.Timestamp)
	require.Equal(t, ahead, proof.IssuedAt, "the proof is dated by the later clock")
	require.NoError(t, proof.Validate())
	require.NoError(t, proof.VerifySignature(f.Keystore))

	// With the clocks aligned the proof carries the issuer's own time.
	aligned, err := newIssuer(t, f, disclosure.Options{}).Issue(issueParamsFrom(f))
	require.NoError(t, err)
	require.Equal(t, issuerEpoch, aligned.IssuedAt)
}

// A proof that cannot be signed is not issued; the witness entry it was
// to carry stays in the log, as the append-only contract says.
func TestIssuer_Issue_SigningFailureLeavesTheEntryCommitted(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	iss, err := disclosure.NewIssuer(f.Clock, refusingSigner{}, f.Keystore, kidAuthority, f.AGDStore, f.Log, disclosure.Options{})
	require.NoError(t, err)
	proof, err := iss.Issue(issueParamsFrom(f))
	require.Nil(t, proof)
	require.Equal(t, "signer_offline", shared_errors.CodeOf(err))
	require.Equal(t, uint64(1), f.Log.Size(), "the entry was committed before the signature was asked for")
}
