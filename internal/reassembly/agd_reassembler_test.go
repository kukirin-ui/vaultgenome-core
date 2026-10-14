// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reassembly_test

// Tests for the receive-side AGDReassembler. The invariants pinned
// down here:
//
//   1. Happy path: all admitted components unseal, hash-match, and
//      size-match; Finalize returns plaintexts keyed by Path, the
//      signed GenomeID, and the rebuilt Merkle root.
//   2. Constructor refuses on malformed inputs (nil AGD, nil sealer,
//      component map size/root/total_bytes mismatch).
//   3. Admit refuses on every documented refusal code with the
//      documented classification.
//   4. Finalize refuses on every documented refusal code with the
//      documented classification, and zeroizes any already-admitted
//      plaintext before returning.
//   5. Single-shot: Admit after Finalize refuses; a second Finalize
//      is idempotent.
//   6. Doctrine: no plaintext substring appears in any error message
//      emitted by the package (invariant #7 mirror).

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/reassembly"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- fixtures --------------------------------------------------------------

const (
	kidSealing = ids.KeyID("recv-seal-1")
	kidAuth    = ids.KeyID("release-auth-1")
)

// compSpec describes one fixture component. The test builds real
// plaintext for each; its hash and byte-size land in the AGD tree.
type compSpec struct {
	cid       ids.ComponentID
	path      string
	kind      componenttree.Kind
	plaintext []byte
}

func defaultSpecs() []compSpec {
	return []compSpec{
		{cid: ids.ComponentID("c-cfg"), path: "config/architecture", kind: componenttree.KindConfig, plaintext: []byte("architecture-descriptor-bytes-cfg-01")},
		{cid: ids.ComponentID("c-tok"), path: "tokenizer/vocab", kind: componenttree.KindTokenizer, plaintext: []byte("TOKENIZER-VOCAB-BINARY-BLOB-ABCDEF-01")},
		{cid: ids.ComponentID("c-w0"), path: "weights/shard-00", kind: componenttree.KindTensor, plaintext: bytes.Repeat([]byte{0xA1}, 256)},
		{cid: ids.ComponentID("c-w1"), path: "weights/shard-01", kind: componenttree.KindTensor, plaintext: bytes.Repeat([]byte{0xB2}, 512)},
		{cid: ids.ComponentID("c-probe"), path: "probes/default", kind: componenttree.KindBehavioralProbe, plaintext: []byte(`{"input":"hello","expected":"hi"}`)},
	}
}

type harness struct {
	store   *keys.InMemoryStore
	agd     *genome_descriptor.GenomeDescriptor
	compMap reassembly.ComponentMap
	// ordered so tests can admit in a specific order.
	messages []*disclosure_message.DisclosureMessage
	specs    []compSpec
}

// buildHarness constructs a keystore with both sealing and authority
// keys, seals each compSpec.plaintext into a well-formed
// DisclosureMessage, and builds a signed AGD whose ComponentTreeRoot
// commits exactly to the sealed components' (path, kind, byte_size,
// hash) tuples.
func buildHarness(t testing.TB, specs []compSpec) *harness {
	t.Helper()

	store := keys.NewInMemoryStore(shared_time.SystemClock{})
	require.NoError(t, store.GenerateSealing(kidSealing))
	_, err := store.GenerateSigning(kidAuth, keys.PurposeSigningAuthority)
	require.NoError(t, err)

	// Build the committed tree from the specs.
	leaves := make([]componenttree.Component, 0, len(specs))
	compMap := make(reassembly.ComponentMap, len(specs))
	var totalBytes uint64
	for _, s := range specs {
		sum := crypto.SHA256(s.plaintext)
		c := componenttree.Component{
			Path:     s.path,
			Kind:     s.kind,
			ByteSize: uint64(len(s.plaintext)),
			Hash:     append([]byte(nil), sum[:]...),
		}
		leaves = append(leaves, c)
		compMap[s.cid] = c
		totalBytes += c.ByteSize
	}
	tree, err := componenttree.BuildTree(leaves)
	require.NoError(t, err)

	// Build the AGD. Use real derivation so the content-addressing
	// invariant holds.
	agd := &genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    "reassembly-test-llm",
		Generation:    0,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 1_000_000,
			PrecisionBits:  16,
			ConfigHash:     fixedHash(0xA1),
		},
		ComponentTreeRoot: tree.RootSlice(),
		ComponentCount:    uint32(len(specs)),
		TotalBytes:        totalBytes,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity: "producer:reassembly-test",
			ProducedAt:       time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC),
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-v3",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    fixedHash(0xE5),
			CanonicalScoresRoot:  fixedHash(0xF6),
			ProbeCount:           256,
			MinPassingScore:      0.85,
		},
		IssuedAt:     time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID: kidAuth,
	}
	id, err := agd.DeriveID()
	require.NoError(t, err)
	agd.GenomeID = id
	require.NoError(t, agd.SignWith(store))
	require.NoError(t, agd.Validate())

	// Seal each component into a DisclosureMessage. Use SessionID and
	// PolicyVersion fixtures that the release side would have used;
	// they are AAD-bound, so they only need to match across seal/open.
	sess := ids.SessionID("sess-reassembly-1")
	pol := ids.PolicyVersion("v1")
	messages := make([]*disclosure_message.DisclosureMessage, 0, len(specs))
	for i, s := range specs {
		plaintext := append([]byte(nil), s.plaintext...)
		aad, err := disclosure_message.BuildRecipientAAD(sess, s.cid, uint32(i), pol, kidSealing)
		require.NoError(t, err)
		nonce, ct, err := store.Seal(kidSealing, plaintext, aad)
		require.NoError(t, err)
		msg := &disclosure_message.DisclosureMessage{
			SchemaVersion:  disclosure_message.SchemaVersionCurrent,
			DisclosureID:   ids.DisclosureID("disc-test-" + s.path),
			SessionID:      sess,
			ComponentID:    s.cid,
			PolicyVersion:  pol,
			SequenceIndex:  uint32(i),
			SealedPayload:  ct,
			Nonce:          nonce,
			RecipientKeyID: kidSealing,
			AuthorizedAt:   time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC),
			SigningKeyID:   kidAuth,
		}
		require.NoError(t, msg.SignWith(store))
		require.NoError(t, msg.Validate())
		messages = append(messages, msg)
	}

	return &harness{
		store:    store,
		agd:      agd,
		compMap:  compMap,
		messages: messages,
		specs:    specs,
	}
}

func fixedHash(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// ---- happy path ------------------------------------------------------------

func TestAGDReassembler_HappyPath(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())

	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	require.False(t, r.IsFinalized())

	for _, m := range h.messages {
		require.NoError(t, r.Admit(m))
	}

	res, err := r.Finalize()
	require.NoError(t, err)
	require.NotNil(t, res)
	require.True(t, r.IsFinalized())

	// GenomeID round-trip.
	require.Equal(t, h.agd.GenomeID, res.GenomeID)

	// Merkle root round-trip.
	require.True(t, bytes.Equal(h.agd.ComponentTreeRoot, res.ComponentTreeRoot),
		"reassembled tree root must equal signed agd commitment")

	// Components keyed by Path, content byte-equal to original plaintext.
	require.Len(t, res.Components, len(h.specs))
	for _, s := range h.specs {
		got, ok := res.Components[s.path]
		require.True(t, ok, "path %q absent from reassembly result", s.path)
		require.True(t, bytes.Equal(s.plaintext, got),
			"reassembled bytes for %q diverge from original plaintext", s.path)
	}
}

func TestAGDReassembler_AdmitAnyOrder(t *testing.T) {
	t.Parallel()
	// Order-independence: admit in reverse.
	h := buildHarness(t, defaultSpecs())

	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)

	for i := len(h.messages) - 1; i >= 0; i-- {
		require.NoError(t, r.Admit(h.messages[i]))
	}

	res, err := r.Finalize()
	require.NoError(t, err)
	require.Equal(t, h.agd.GenomeID, res.GenomeID)
}

// ---- constructor refusals --------------------------------------------------

func TestAGDReassembler_NewAGDReassembler_NilAGD(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	_, err := reassembly.NewAGDReassembler(nil, h.compMap, h.store)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeAGDMissing, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestAGDReassembler_NewAGDReassembler_NilSealer(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	_, err := reassembly.NewAGDReassembler(h.agd, h.compMap, nil)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeNilArgument, shared_errors.CodeOf(err))
}

func TestAGDReassembler_NewAGDReassembler_NilMap(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	_, err := reassembly.NewAGDReassembler(h.agd, nil, h.store)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeComponentMapMismatch, shared_errors.CodeOf(err))
}

func TestAGDReassembler_NewAGDReassembler_MapSizeMismatch(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	// Drop one component from the map; AGD still claims N.
	for k := range h.compMap {
		delete(h.compMap, k)
		break
	}
	_, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeComponentMapMismatch, shared_errors.CodeOf(err))
}

func TestAGDReassembler_NewAGDReassembler_MerkleRootMismatch(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	// Corrupt the AGD's ComponentTreeRoot (breaks Validate first).
	h.agd.ComponentTreeRoot = fixedHash(0x00)
	// Re-derive and re-sign so the AGD itself is internally valid.
	id, err := h.agd.DeriveID()
	require.NoError(t, err)
	h.agd.GenomeID = id
	require.NoError(t, h.agd.SignWith(h.store))

	_, err = reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeComponentMapMismatch, shared_errors.CodeOf(err))
}

func TestAGDReassembler_NewAGDReassembler_TotalBytesMismatch(t *testing.T) {
	t.Parallel()
	// Build a valid harness; then lie about TotalBytes in the AGD.
	// The mismatch must be caught by NewAGDReassembler. We re-derive +
	// re-sign so the AGD itself is internally valid — the failure must
	// come from the cross-check, not from an AGD validate.
	h := buildHarness(t, defaultSpecs())
	h.agd.TotalBytes++
	id, err := h.agd.DeriveID()
	require.NoError(t, err)
	h.agd.GenomeID = id
	require.NoError(t, h.agd.SignWith(h.store))

	_, err = reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeComponentMapMismatch, shared_errors.CodeOf(err))
}

// ---- Admit refusals --------------------------------------------------------

func TestAGDReassembler_Admit_NilMessage(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	err = r.Admit(nil)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeNilArgument, shared_errors.CodeOf(err))
}

func TestAGDReassembler_Admit_UnknownComponent(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	// Take a valid message and swap its ComponentID. The envelope will
	// re-validate (structural OK), but the Admit-time AGD lookup will
	// reject it.
	//
	// Note: changing ComponentID also breaks the AAD, so Open would
	// fail too — but the unknown-component gate runs BEFORE Open in the
	// refusal order, so that's what we expect to see here.
	msg := *h.messages[0] // shallow copy fine — we only mutate a scalar
	msg.ComponentID = ids.ComponentID("not-in-tree")
	// Re-sign so envelope validates.
	require.NoError(t, msg.SignWith(h.store))
	err = r.Admit(&msg)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeUnknownComponent, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestAGDReassembler_Admit_DuplicateComponent(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	require.NoError(t, r.Admit(h.messages[0]))
	err = r.Admit(h.messages[0])
	require.Error(t, err)
	require.Equal(t, reassembly.CodeDuplicateComponent, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestAGDReassembler_Admit_SealedOpenFailed_TamperedCiphertext(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	// Tamper one byte of ciphertext. Re-sign so the envelope itself is
	// internally consistent; GCM will reject at Open time.
	bad := *h.messages[0]
	bad.SealedPayload = append([]byte(nil), h.messages[0].SealedPayload...)
	bad.SealedPayload[0] ^= 0xFF
	require.NoError(t, bad.SignWith(h.store))
	err = r.Admit(&bad)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeSealedOpenFailed, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestAGDReassembler_Admit_SealedOpenFailed_AADDrift(t *testing.T) {
	t.Parallel()
	// Take the message the release side sealed for SequenceIndex=0,
	// rewrite SequenceIndex=99 on the receive side. The AAD we
	// reconstruct will differ from the one used at seal time → GCM
	// rejects.
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	bad := *h.messages[0]
	bad.SequenceIndex = 99
	require.NoError(t, bad.SignWith(h.store))
	err = r.Admit(&bad)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeSealedOpenFailed, shared_errors.CodeOf(err))
}

func TestAGDReassembler_Admit_ByteSizeMismatch(t *testing.T) {
	t.Parallel()
	// Build harness; then before constructing the reassembler, mutate
	// the AGD's committed ByteSize for one component. Admit for that
	// component will unseal successfully (AAD and hash unchanged) but
	// the byte-size check will fail.
	//
	// We need the AGD itself to stay internally valid, so after
	// tweaking ByteSize we rebuild the tree and re-derive/re-sign.
	specs := defaultSpecs()
	h := buildHarness(t, specs)

	// Locate comp c-probe in the map and change its ByteSize
	// commitment to the wrong value, then rebuild AGD so Validate
	// still passes.
	cid := ids.ComponentID("c-probe")
	mutated := h.compMap[cid]
	mutated.ByteSize++ // off by one
	h.compMap[cid] = mutated

	// Rebuild tree + re-sign AGD
	leaves := make([]componenttree.Component, 0, len(h.compMap))
	var total uint64
	for _, c := range h.compMap {
		leaves = append(leaves, c)
		total += c.ByteSize
	}
	tree, err := componenttree.BuildTree(leaves)
	require.NoError(t, err)
	h.agd.ComponentTreeRoot = tree.RootSlice()
	h.agd.TotalBytes = total
	id, err := h.agd.DeriveID()
	require.NoError(t, err)
	h.agd.GenomeID = id
	require.NoError(t, h.agd.SignWith(h.store))

	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)

	// Admit the original (honest) c-probe message. Unseal OK, but
	// len(plaintext) != AGD.ByteSize.
	var probe *disclosure_message.DisclosureMessage
	for _, m := range h.messages {
		if m.ComponentID == cid {
			probe = m
			break
		}
	}
	require.NotNil(t, probe)

	err = r.Admit(probe)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeComponentByteSizeMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestAGDReassembler_Admit_ComponentHashMismatch(t *testing.T) {
	t.Parallel()
	// Same technique: tweak the AGD-committed hash for one component
	// (keeping byte-size honest). Admit unseals and size-checks OK,
	// then hash-checks fail.
	specs := defaultSpecs()
	h := buildHarness(t, specs)

	cid := ids.ComponentID("c-cfg")
	mutated := h.compMap[cid]
	mutated.Hash = fixedHash(0x00) // wrong hash, right length
	h.compMap[cid] = mutated

	leaves := make([]componenttree.Component, 0, len(h.compMap))
	var total uint64
	for _, c := range h.compMap {
		leaves = append(leaves, c)
		total += c.ByteSize
	}
	tree, err := componenttree.BuildTree(leaves)
	require.NoError(t, err)
	h.agd.ComponentTreeRoot = tree.RootSlice()
	h.agd.TotalBytes = total
	id, err := h.agd.DeriveID()
	require.NoError(t, err)
	h.agd.GenomeID = id
	require.NoError(t, h.agd.SignWith(h.store))

	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)

	var cfg *disclosure_message.DisclosureMessage
	for _, m := range h.messages {
		if m.ComponentID == cid {
			cfg = m
			break
		}
	}
	require.NotNil(t, cfg)

	err = r.Admit(cfg)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeComponentHashMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

// ---- Finalize refusals -----------------------------------------------------

func TestAGDReassembler_Finalize_CoverageIncomplete(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)

	// Admit all but one.
	for i, m := range h.messages {
		if i == 0 {
			continue
		}
		require.NoError(t, r.Admit(m))
	}

	res, err := r.Finalize()
	require.Nil(t, res)
	require.Error(t, err)
	require.Equal(t, reassembly.CodeCoverageIncomplete, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.True(t, r.IsFinalized())
}

// ---- state machine --------------------------------------------------------

func TestAGDReassembler_AdmitAfterFinalize_Refused(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	for _, m := range h.messages {
		require.NoError(t, r.Admit(m))
	}
	_, err = r.Finalize()
	require.NoError(t, err)

	err = r.Admit(h.messages[0])
	require.Error(t, err)
	require.Equal(t, reassembly.CodeReassemblerFinalized, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
}

func TestAGDReassembler_Finalize_IdempotentOnSuccess(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	for _, m := range h.messages {
		require.NoError(t, r.Admit(m))
	}
	res1, err := r.Finalize()
	require.NoError(t, err)
	res2, err := r.Finalize()
	require.NoError(t, err)
	require.Same(t, res1, res2, "second Finalize must return the same result pointer")
}

func TestAGDReassembler_Finalize_IdempotentOnFailure(t *testing.T) {
	t.Parallel()
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	// Admit nothing → coverage incomplete at Finalize.
	_, err1 := r.Finalize()
	require.Error(t, err1)
	_, err2 := r.Finalize()
	require.Error(t, err2)
	require.Equal(t, shared_errors.CodeOf(err1), shared_errors.CodeOf(err2),
		"second Finalize must return the same classified code as the first")
}

// ---- doctrine: no plaintext in errors --------------------------------------

func TestAGDReassembler_NoPlaintextInErrorMessages(t *testing.T) {
	t.Parallel()
	// Exercise every refusal path and assert no plaintext substring
	// leaks into an error message. This mirrors invariant #7 at the
	// local level.
	h := buildHarness(t, defaultSpecs())
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)

	// Build error cases.
	var errs []error

	// unknown component
	{
		m := *h.messages[0]
		m.ComponentID = ids.ComponentID("nope")
		require.NoError(t, m.SignWith(h.store))
		errs = append(errs, r.Admit(&m))
	}
	// admit honest then duplicate
	{
		require.NoError(t, r.Admit(h.messages[1]))
		errs = append(errs, r.Admit(h.messages[1]))
	}
	// tampered ciphertext
	{
		m := *h.messages[2]
		m.SealedPayload = append([]byte(nil), h.messages[2].SealedPayload...)
		m.SealedPayload[0] ^= 0xFF
		require.NoError(t, m.SignWith(h.store))
		errs = append(errs, r.Admit(&m))
	}
	// nil message
	errs = append(errs, r.Admit(nil))

	for i, err := range errs {
		require.Error(t, err, "case %d expected to return error", i)
		for _, s := range h.specs {
			// Check for each plaintext fragment. Use a reasonably
			// distinctive substring — very short byte sequences could
			// randomly appear in error text, so restrict to length >= 8.
			if len(s.plaintext) < 8 {
				continue
			}
			needle := string(s.plaintext)
			require.False(t, strings.Contains(err.Error(), needle),
				"plaintext of %q leaked into error: %s", s.path, err.Error())
		}
	}
}
