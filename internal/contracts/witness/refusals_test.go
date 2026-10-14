// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package witness_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/witness"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

func requireRefusal(t *testing.T, err error, category shared_errors.Category, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, category, shared_errors.CategoryOf(err), "category of %v", err)
	require.Equal(t, code, shared_errors.CodeOf(err), "code of %v", err)
}

func TestInclusionProof_Validate_Refusals(t *testing.T) {
	t.Parallel()
	var nilProof *witness.InclusionProof
	requireRefusal(t, nilProof.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	rows := map[string]struct {
		proof witness.InclusionProof
		code  string
	}{
		"empty tree":                 {witness.InclusionProof{TreeSize: 0}, shared_errors.CodeFieldValueInvalid},
		"leaf beyond the tree":       {witness.InclusionProof{LeafIndex: 2, TreeSize: 2, Path: [][]byte{zeros32()}}, shared_errors.CodeCrossFieldInconsistent},
		"path element of 31 bytes":   {witness.InclusionProof{LeafIndex: 0, TreeSize: 2, Path: [][]byte{repeat(1, 31)}}, shared_errors.CodeFieldValueInvalid},
		"singleton with a path":      {witness.InclusionProof{LeafIndex: 0, TreeSize: 1, Path: [][]byte{zeros32()}}, shared_errors.CodeCrossFieldInconsistent},
		"larger tree without a path": {witness.InclusionProof{LeafIndex: 0, TreeSize: 2}, shared_errors.CodeCrossFieldInconsistent},
	}
	for name, row := range rows {
		proof := row.proof
		requireRefusal(t, proof.Validate(), shared_errors.CategoryStructural, row.code)
		t.Log(name)
	}
}

func TestVerifyInclusion_Refusals(t *testing.T) {
	t.Parallel()
	chain := buildChain(t, 4)
	leaves := leafHashes(chain)
	root, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	path := buildInclusionPath(t, leaves, 0)
	good := &witness.InclusionProof{LeafIndex: 0, TreeSize: 4, Path: path}
	require.NoError(t, witness.VerifyInclusion(leaves[0], good, root))

	requireRefusal(t, witness.VerifyInclusion(leaves[0][:31], good, root), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, witness.VerifyInclusion(leaves[0], good, root[:31]), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, witness.VerifyInclusion(leaves[0], &witness.InclusionProof{TreeSize: 0}, root), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	single := &witness.InclusionProof{LeafIndex: 0, TreeSize: 1}
	require.NoError(t, witness.VerifyInclusion(leaves[0], single, leaves[0]))
	requireRefusal(t, witness.VerifyInclusion(leaves[0], single, leaves[1]), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	long := &witness.InclusionProof{LeafIndex: 0, TreeSize: 2, Path: [][]byte{leaves[1], leaves[2]}}
	requireRefusal(t, witness.VerifyInclusion(leaves[0], long, root), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	short := &witness.InclusionProof{LeafIndex: 0, TreeSize: 4, Path: path[:1]}
	requireRefusal(t, witness.VerifyInclusion(leaves[0], short, root), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	requireRefusal(t, witness.VerifyInclusion(leaves[0], good, repeat(0xEE, crypto.HashSize)), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
}

func TestConsistencyProof_Validate_Refusals(t *testing.T) {
	t.Parallel()
	var nilProof *witness.ConsistencyProof
	requireRefusal(t, nilProof.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	rows := map[string]struct {
		proof witness.ConsistencyProof
		code  string
	}{
		"shrinking tree":           {witness.ConsistencyProof{OldSize: 3, NewSize: 2}, shared_errors.CodeCrossFieldInconsistent},
		"path element of 31 bytes": {witness.ConsistencyProof{OldSize: 1, NewSize: 2, Path: [][]byte{repeat(1, 31)}}, shared_errors.CodeFieldValueInvalid},
		"from empty with a path":   {witness.ConsistencyProof{OldSize: 0, NewSize: 2, Path: [][]byte{zeros32()}}, shared_errors.CodeCrossFieldInconsistent},
		"same size with a path":    {witness.ConsistencyProof{OldSize: 2, NewSize: 2, Path: [][]byte{zeros32()}}, shared_errors.CodeCrossFieldInconsistent},
	}
	for name, row := range rows {
		proof := row.proof
		requireRefusal(t, proof.Validate(), shared_errors.CategoryStructural, row.code)
		t.Log(name)
	}
}

func TestVerifyConsistency_Refusals(t *testing.T) {
	t.Parallel()
	chain := buildChain(t, 4)
	leaves := leafHashes(chain)
	oldRoot, err := witness.ComputeMerkleRoot(leaves[:3])
	require.NoError(t, err)
	newRoot, err := witness.ComputeMerkleRoot(leaves)
	require.NoError(t, err)
	path := buildConsistencyPath(t, leaves, 3)
	good := &witness.ConsistencyProof{OldSize: 3, NewSize: 4, Path: path}
	require.NoError(t, witness.VerifyConsistency(oldRoot, newRoot, good))

	requireRefusal(t, witness.VerifyConsistency(oldRoot[:31], newRoot, good), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, witness.VerifyConsistency(oldRoot, newRoot[:31], good), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	requireRefusal(t, witness.VerifyConsistency(oldRoot, newRoot, &witness.ConsistencyProof{OldSize: 5, NewSize: 4}), shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent)

	require.NoError(t, witness.VerifyConsistency(oldRoot, newRoot, &witness.ConsistencyProof{OldSize: 0, NewSize: 4}))
	require.NoError(t, witness.VerifyConsistency(newRoot, newRoot, &witness.ConsistencyProof{OldSize: 4, NewSize: 4}))
	requireRefusal(t, witness.VerifyConsistency(oldRoot, newRoot, &witness.ConsistencyProof{OldSize: 4, NewSize: 4}), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	requireRefusal(t, witness.VerifyConsistency(oldRoot, newRoot, &witness.ConsistencyProof{OldSize: 3, NewSize: 4}), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	long := &witness.ConsistencyProof{OldSize: 3, NewSize: 4, Path: append(append([][]byte(nil), path...), leaves[0])}
	requireRefusal(t, witness.VerifyConsistency(oldRoot, newRoot, long), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	short := &witness.ConsistencyProof{OldSize: 3, NewSize: 4, Path: path[:len(path)-1]}
	requireRefusal(t, witness.VerifyConsistency(oldRoot, newRoot, short), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	requireRefusal(t, witness.VerifyConsistency(repeat(0xEE, crypto.HashSize), newRoot, good), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	requireRefusal(t, witness.VerifyConsistency(oldRoot, repeat(0xEE, crypto.HashSize), good), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
}

func TestSignedTreeHead_Validate_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-1")
	store := newWitnessStore(t, kid)
	chain := buildChain(t, 2)
	good := newSignedSTH(t, store, kid, chain, coverTime(chain))
	require.NoError(t, good.Validate())

	var nilSTH *witness.SignedTreeHead
	requireRefusal(t, nilSTH.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	requireRefusal(t, nilSTH.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name string
		edit func(s *witness.SignedTreeHead)
		code string
	}{
		{"schema below range", func(s *witness.SignedTreeHead) { s.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"tree hash short", func(s *witness.SignedTreeHead) { s.TreeHash = s.TreeHash[:31] }, shared_errors.CodeFieldValueInvalid},
		{"chain head short", func(s *witness.SignedTreeHead) { s.TreeChainHead = nil }, shared_errors.CodeFieldValueInvalid},
		{"empty tree with a hash", func(s *witness.SignedTreeHead) { s.TreeSize = 0 }, shared_errors.CodeCrossFieldInconsistent},
		{"empty tree with a chain head", func(s *witness.SignedTreeHead) { s.TreeSize = 0; s.TreeHash = zeros32() }, shared_errors.CodeCrossFieldInconsistent},
		{"tree without a hash", func(s *witness.SignedTreeHead) { s.TreeHash = zeros32() }, shared_errors.CodeCrossFieldInconsistent},
		{"tree without a chain head", func(s *witness.SignedTreeHead) { s.TreeChainHead = zeros32() }, shared_errors.CodeCrossFieldInconsistent},
		{"single leaf whose hash is not the head", func(s *witness.SignedTreeHead) { s.TreeSize = 1 }, shared_errors.CodeCrossFieldInconsistent},
		{"timestamp missing", func(s *witness.SignedTreeHead) { s.Timestamp = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"signing key missing", func(s *witness.SignedTreeHead) { s.SigningKeyID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"signature missing", func(s *witness.SignedTreeHead) { s.Signature = nil }, shared_errors.CodeRequiredFieldMissing},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			s := *good
			row.edit(&s)
			requireRefusal(t, s.Validate(), shared_errors.CategoryStructural, row.code)
			_, err := s.CanonicalBytes()
			require.Error(t, err)
			require.Error(t, s.VerifySignature(store))
		})
	}
}

func TestSignedTreeHead_SignAndVerify_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-1")
	store := newWitnessStore(t, kid)
	chain := buildChain(t, 2)
	good := newSignedSTH(t, store, kid, chain, coverTime(chain))

	noKey := *good
	noKey.SigningKeyID = ""
	requireRefusal(t, noKey.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	noHash := *good
	noHash.TreeHash = nil
	requireRefusal(t, noHash.SignWith(store), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	unknown := *good
	unknown.SigningKeyID = "nobody"
	require.Error(t, unknown.SignWith(store))
	unknown.Signature = []byte{1}
	require.Error(t, unknown.VerifySignature(store))
	requireRefusal(t, good.VerifySignature(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	raw, err := json.Marshal(good)
	require.NoError(t, err)
	var trailing witness.SignedTreeHead
	requireRefusal(t, trailing.UnmarshalJSON(append(append([]byte(nil), raw...), []byte(" {}")...)), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var unknownField witness.SignedTreeHead
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":1,"extra":true}`), &unknownField), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var schema witness.SignedTreeHead
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":7}`), &schema), shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported)
}

func newReceipt(t *testing.T, chain []witness.LogEntry, index int, sthTime time.Time) (witness.WitnessReceipt, *witness.SignedTreeHead) {
	t.Helper()
	kid := ids.KeyID("witness-1")
	store := newWitnessStore(t, kid)
	leaves := leafHashes(chain)
	sth := newSignedSTH(t, store, kid, chain, sthTime)
	r := witness.WitnessReceipt{
		SchemaVersion:  witness.SchemaVersionCurrent,
		Entry:          chain[index],
		InclusionProof: witness.InclusionProof{LeafIndex: uint64(index), TreeSize: uint64(len(chain)), Path: buildInclusionPath(t, leaves, index)},
		STH:            *sth,
	}
	require.NoError(t, r.Validate())
	return r, sth
}

func TestWitnessReceipt_Validate_Refusals(t *testing.T) {
	t.Parallel()
	chain := buildChain(t, 3)
	good, _ := newReceipt(t, chain, 1, coverTime(chain))
	tail, _ := newReceipt(t, chain, 2, coverTime(chain))

	var nilReceipt *witness.WitnessReceipt
	requireRefusal(t, nilReceipt.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	rows := []struct {
		name     string
		base     witness.WitnessReceipt
		edit     func(r *witness.WitnessReceipt)
		category shared_errors.Category
		code     string
	}{
		{"schema below range", good, func(r *witness.WitnessReceipt) { r.SchemaVersion = 0 }, shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported},
		{"entry without a leaf hash", good, func(r *witness.WitnessReceipt) { r.Entry.LeafHash = nil }, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"proof of an empty tree", good, func(r *witness.WitnessReceipt) { r.InclusionProof.TreeSize = 0 }, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid},
		{"tree head without a signature", good, func(r *witness.WitnessReceipt) { r.STH.Signature = nil }, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing},
		{"proof for another leaf", good, func(r *witness.WitnessReceipt) { r.InclusionProof.LeafIndex = 0 }, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent},
		{"proof for another tree size", good, func(r *witness.WitnessReceipt) { r.InclusionProof.TreeSize = 2 }, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent},
		{"tree head older than the entry", good, func(r *witness.WitnessReceipt) { r.STH.Timestamp = r.Entry.Timestamp.Add(-time.Second) }, shared_errors.CategoryStructural, shared_errors.CodeCrossFieldInconsistent},
		{"tail entry that is not the chain head", tail, func(r *witness.WitnessReceipt) { r.STH.TreeChainHead = repeat(0xEE, crypto.HashSize) }, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid},
		{"path that does not reach the root", good, func(r *witness.WitnessReceipt) {
			r.InclusionProof.Path = [][]byte{repeat(0xEE, crypto.HashSize), repeat(0xEF, crypto.HashSize)}
		}, shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			r := row.base
			row.edit(&r)
			requireRefusal(t, r.Validate(), row.category, row.code)
			require.Error(t, r.Verify(newWitnessStore(t, "witness-1")))
		})
	}
	requireRefusal(t, good.Verify(nil), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	raw, err := json.Marshal(good)
	require.NoError(t, err)
	var trailing witness.WitnessReceipt
	requireRefusal(t, trailing.UnmarshalJSON(append(append([]byte(nil), raw...), []byte(" 0")...)), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var unknownField witness.WitnessReceipt
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":1,"extra":true}`), &unknownField), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var schema witness.WitnessReceipt
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":0}`), &schema), shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported)
}

func TestLogEntry_Refusals(t *testing.T) {
	t.Parallel()
	require.Equal(t, "log:abc", witness.EntryID("log:abc").String())

	var nilEntry *witness.LogEntry
	_, _, err := nilEntry.DeriveLeafHashAndID()
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	chain := buildChain(t, 2)
	good := chain[1]
	require.NoError(t, good.Validate())

	structural := []struct {
		name string
		edit func(e *witness.LogEntry)
		code string
	}{
		{"schema below range", func(e *witness.LogEntry) { e.SchemaVersion = 0 }, shared_errors.CodeSchemaVersionUnsupported},
		{"previous hash short", func(e *witness.LogEntry) { e.PrevLeafHash = e.PrevLeafHash[:31] }, shared_errors.CodeFieldValueInvalid},
		{"genesis anchored to a hash", func(e *witness.LogEntry) { e.Index = 0 }, shared_errors.CodeCrossFieldInconsistent},
		{"later entry anchored to nothing", func(e *witness.LogEntry) { e.PrevLeafHash = zeros32() }, shared_errors.CodeCrossFieldInconsistent},
		{"timestamp missing", func(e *witness.LogEntry) { e.Timestamp = time.Time{} }, shared_errors.CodeRequiredFieldMissing},
		{"genome missing", func(e *witness.LogEntry) { e.GenomeID = "" }, shared_errors.CodeRequiredFieldMissing},
		{"attestation root short", func(e *witness.LogEntry) { e.AttestationRoot = nil }, shared_errors.CodeFieldValueInvalid},
		{"battery root short", func(e *witness.LogEntry) { e.BatteryMerkleRoot = e.BatteryMerkleRoot[:1] }, shared_errors.CodeFieldValueInvalid},
		{"scorecard root short", func(e *witness.LogEntry) { e.ScorecardRoot = e.ScorecardRoot[:1] }, shared_errors.CodeFieldValueInvalid},
		{"parent without a method", func(e *witness.LogEntry) { e.DerivationMethod = "" }, shared_errors.CodeCrossFieldInconsistent},
		{"method without a parent", func(e *witness.LogEntry) { e.ParentGenomeID = "" }, shared_errors.CodeCrossFieldInconsistent},
		{"unknown method", func(e *witness.LogEntry) { e.DerivationMethod = genome_descriptor.DerivationMethod("teleport") }, shared_errors.CodeFieldValueInvalid},
	}
	for _, row := range structural {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e := good
			row.edit(&e)
			_, _, err := e.DeriveLeafHashAndID()
			requireRefusal(t, err, shared_errors.CategoryStructural, row.code)
			requireRefusal(t, e.Validate(), shared_errors.CategoryStructural, row.code)
		})
	}

	noLeaf := good
	noLeaf.LeafHash = noLeaf.LeafHash[:31]
	requireRefusal(t, noLeaf.Validate(), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	noID := good
	noID.EntryID = ""
	requireRefusal(t, noID.Validate(), shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	otherLeaf := good
	otherLeaf.LeafHash = repeat(0xEE, crypto.HashSize)
	requireRefusal(t, otherLeaf.Validate(), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)
	otherID := good
	otherID.EntryID = "log:ffff"
	requireRefusal(t, otherID.Validate(), shared_errors.CategoryIntegrity, shared_errors.CodeSignatureInvalid)

	_, err = witness.ComputeMerkleRoot([][]byte{zeros32(), repeat(1, 31)})
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	_, err = witness.CombineNodes(zeros32(), nil)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)

	raw, err := json.Marshal(good)
	require.NoError(t, err)
	var trailing witness.LogEntry
	requireRefusal(t, trailing.UnmarshalJSON(append(append([]byte(nil), raw...), []byte(" []")...)), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var unknownField witness.LogEntry
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":1,"extra":true}`), &unknownField), shared_errors.CategoryStructural, shared_errors.CodeFieldValueInvalid)
	var schema witness.LogEntry
	requireRefusal(t, json.Unmarshal([]byte(`{"schema_version":0}`), &schema), shared_errors.CategoryStructural, shared_errors.CodeSchemaVersionUnsupported)
}

func TestDetectFork_Refusals(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("witness-1")
	store := newWitnessStore(t, kid)
	chain := buildChain(t, 1)
	empty := newSignedSTH(t, store, kid, nil, coverTime(chain).Add(10*time.Second))
	one := newSignedSTH(t, store, kid, chain, coverTime(chain))

	_, err := witness.DetectFork(nil, one, nil)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err = witness.DetectFork(one, nil, nil)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	broken := *one
	broken.Signature = nil
	_, err = witness.DetectFork(&broken, one, nil)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)
	_, err = witness.DetectFork(one, &broken, nil)
	requireRefusal(t, err, shared_errors.CategoryStructural, shared_errors.CodeRequiredFieldMissing)

	// The empty tree head was issued after the one-leaf head: time ran
	// backwards for the same signer, and the evidence names both sizes.
	ev, err := witness.DetectFork(one, empty, nil)
	require.NoError(t, err)
	require.NotNil(t, ev)
	require.Equal(t, witness.ForkKindTimestampNonMonotonic, ev.Kind)
	require.Equal(t, "a.tree_size=0 b.tree_size=1", ev.Detail)
	require.True(t, ev.Kind.IsIncident())
	require.Equal(t, shared_errors.CategoryIncident, shared_errors.CategoryOf(ev.AsError()))
	var none *witness.ForkEvidence
	require.NoError(t, none.AsError())
}
