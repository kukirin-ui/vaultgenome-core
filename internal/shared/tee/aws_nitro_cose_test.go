// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// TestAWSNitroRootG1_Fingerprint holds the embedded root to the
// fingerprint AWS publishes in the attestation documentation.
func TestAWSNitroRootG1_Fingerprint(t *testing.T) {
	t.Parallel()
	roots := awsNitroPinnedRoots()
	require.Len(t, roots, 1)
	sum := sha256.Sum256(roots[0])
	require.Equal(t, "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b", hex.EncodeToString(sum[:]))
	cert, err := x509.ParseCertificate(roots[0])
	require.NoError(t, err)
	require.Equal(t, "aws.nitro-enclaves", cert.Subject.CommonName)
	require.True(t, cert.IsCA)
	require.Equal(t, 2049, cert.NotAfter.Year())
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P384(), pub.Curve)
}

// TestCBOR_DecodeSubset covers the items the decoder accepts and the
// shapes it refuses.
func TestCBOR_DecodeSubset(t *testing.T) {
	t.Parallel()
	mustDecode := func(hexIn string) *cborItem {
		t.Helper()
		b, err := hex.DecodeString(hexIn)
		require.NoError(t, err)
		it, err := cborDecode(b)
		require.NoError(t, err, hexIn)
		return it
	}
	mustFail := func(hexIn, why string) {
		t.Helper()
		b, err := hex.DecodeString(hexIn)
		require.NoError(t, err)
		_, err = cborDecode(b)
		require.Error(t, err, why)
	}

	require.Equal(t, cborItem{kind: cborUint, u: 10}, *mustDecode("0a"))
	require.Equal(t, cborItem{kind: cborUint, u: 1000000}, *mustDecode("1a000f4240"))
	require.Equal(t, cborItem{kind: cborUint, u: 18446744073709551615}, *mustDecode("1bffffffffffffffff"))
	require.Equal(t, cborItem{kind: cborNInt, u: 34}, *mustDecode("3822")) // -35, ES384
	require.Equal(t, cborItem{kind: cborBytes, b: []byte{1, 2, 3, 4}}, *mustDecode("4401020304"))
	require.Equal(t, cborItem{kind: cborText, b: []byte("IETF")}, *mustDecode("6449455446"))
	require.Equal(t, cborItem{kind: cborNull}, *mustDecode("f6"))

	arr := mustDecode("83010203")
	require.Equal(t, cborArray, arr.kind)
	require.Len(t, arr.items, 3)

	m := mustDecode("a201020304") // {1: 2, 3: 4}
	require.Equal(t, cborMap, m.kind)
	v, dup := m.mapLookupInt(3)
	require.False(t, dup)
	require.Equal(t, uint64(4), v.u)
	v, _ = m.mapLookupInt(5)
	require.Nil(t, v)

	tagged := mustDecode("d28101") // 18([1])
	require.Equal(t, cborTag, tagged.kind)
	require.Equal(t, uint64(18), tagged.u)
	require.Equal(t, cborArray, tagged.tagged.kind)

	text := mustDecode("a2616101616202") // {"a": 1, "b": 2}
	v, dup = text.mapLookup("b")
	require.False(t, dup)
	require.Equal(t, uint64(2), v.u)
	twice := mustDecode("a2616101616103") // {"a": 1, "a": 3}
	_, dup = twice.mapLookup("a")
	require.True(t, dup, "a repeated key is reported")

	// Indefinite lengths (RFC 8949 §3.2.2, §3.2.3): the hypervisor writes
	// the document's map this way.
	indefArr := mustDecode("9f018202039f0405ffff") // [_ 1, [2, 3], [_ 4, 5]]
	require.Len(t, indefArr.items, 3)
	require.Len(t, indefArr.items[2].items, 2)
	indefMap := mustDecode("bf616101616202ff") // {_ "a": 1, "b": 2}
	v, dup = indefMap.mapLookup("b")
	require.False(t, dup)
	require.Equal(t, uint64(2), v.u)
	require.Equal(t, cborItem{kind: cborBytes, b: []byte{1, 2, 3, 4, 5}}, *mustDecode("5f42010243030405ff"))
	require.Equal(t, cborItem{kind: cborText, b: []byte("streaming")}, *mustDecode("7f657374726561646d696e67ff"))
	require.Equal(t, cborItem{kind: cborBytes, b: nil}, *mustDecode("5fff"))
	require.Len(t, mustDecode("9fff").items, 0)

	mustFail("", "empty input")
	mustFail("18", "truncated one-byte argument")
	mustFail("4403", "truncated byte string")
	mustFail("5f", "indefinite-length byte string without its break")
	mustFail("9f01", "indefinite-length array without its break")
	mustFail("bf6161", "indefinite-length map cut inside a pair")
	require.Len(t, mustDecode("bf616101ff").items, 2, "one pair then the break")
	mustFail("bf6161ff", "indefinite-length map with a key and no value")
	mustFail("5f01ff", "indefinite-length byte string holding an integer chunk")
	mustFail("5f6161ff", "indefinite-length byte string holding a text chunk")
	mustFail("5f5f4101ffff", "indefinite-length chunk inside an indefinite-length string")
	mustFail("ff", "a stray break code")
	mustFail("8101ff", "a break code after a definite array")
	mustFail("1f", "indefinite integer")
	mustFail("df01", "indefinite tag")
	mustFail("1c", "reserved additional information 28")
	mustFail("f5", "boolean")
	mustFail("f97e00", "half-precision float")
	mustFail("fb3ff0000000000000", "double")
	mustFail("0a0b", "trailing bytes")
	mustFail("a1f601", "null map key")
	mustFail("a1810102", "array map key")
	mustFail("f81602", "null written in the two-byte form")
	mustFail("8a01", "array claims more elements than the input holds")
	mustFail("b901000102", "map claims more pairs than the input holds")
	nested := strings.Repeat("81", cborMaxDepth+2) + "01"
	mustFail(nested, "nesting beyond the limit")
	mustFail(hex.EncodeToString(make([]byte, cborMaxInput+1)), "input beyond the size limit")
}

// TestCBOR_EncoderRoundTrip holds the encoder to the decoder and to the
// preferred serialization.
func TestCBOR_EncoderRoundTrip(t *testing.T) {
	t.Parallel()
	var e cborEncoder
	e.array(6)
	e.uint(23)
	e.uint(24)
	e.uint(256)
	e.uint(65536)
	e.uint(1 << 32)
	e.nint(-35)
	require.Equal(t, "861718181901001a000100001b00000001000000003822", hex.EncodeToString(e.buf), "shortest heads")
	it, err := cborDecode(e.buf)
	require.NoError(t, err)
	require.Len(t, it.items, 6)
	require.Equal(t, uint64(23), it.items[0].u)
	require.Equal(t, uint64(1<<32), it.items[4].u)
	require.Equal(t, cborNInt, it.items[5].kind)
	require.Equal(t, uint64(34), it.items[5].u)

	var s cborEncoder
	s.mapping(1)
	s.text("k")
	s.bytes([]byte{9})
	require.Equal(t, "a1616b4109", hex.EncodeToString(s.buf))
}

// TestAWSNitro_SyntheticChain_Verifies is the positive case: a document
// signed by the synthetic chain verifies against the synthetic root, both
// tagged and untagged.
func TestAWSNitro_SyntheticChain_Verifies(t *testing.T) {
	t.Parallel()
	now := time.Now()
	chain := newNitroTestChain(t, now)
	nonce := bytes.Repeat([]byte{0x5A}, NonceMinBytes)
	pcr0 := nitroPCR("verifies", 0)
	for _, tagged := range []bool{false, true} {
		ev := chain.sign(t, nitroTestDoc{Timestamp: now, Nonce: nonce, UserData: []byte("session-7"), PCRs: map[int][]byte{0: pcr0, 1: nitroPCR("verifies", 1), 8: nitroPCR("verifies", 8)}, Tagged: tagged})
		v, err := NewAWSNitroVerifier(nil, pcr0, AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now }})
		require.NoError(t, err)
		got, err := v.Verify(ev, nonce)
		require.NoError(t, err, "tagged=%v", tagged)
		require.Equal(t, Measurement(pcr0), got)

		report, err := AuditAWSNitroDocument(ev, [][]byte{chain.rootDER}, now)
		require.NoError(t, err)
		require.Equal(t, "i-0e35190ae3157095d-enc019e0512a5715d4f", report.ModuleID)
		require.Equal(t, now.UnixMilli(), report.Timestamp.UnixMilli())
		require.Equal(t, nonce, report.Nonce)
		require.Equal(t, []byte("session-7"), report.UserData)
		require.Len(t, report.Chain, 5)
		require.Contains(t, report.Chain[0], "enc019e0512a5715d4f")
		require.Contains(t, report.Chain[4], "CN=aws.nitro-enclaves")
		require.False(t, report.Debug)
		require.Equal(t, pcr0, report.PCRs[0])
	}
}

// TestAWSNitro_Verifier_Refusals is every refusal the verifier makes on
// a document the synthetic chain signed, one knob at a time.
func TestAWSNitro_Verifier_Refusals(t *testing.T) {
	t.Parallel()
	now := time.Now()
	chain := newNitroTestChain(t, now)
	other := newNitroTestChain(t, now)
	nonce := bytes.Repeat([]byte{0x5A}, NonceMinBytes)
	pcr0 := nitroPCR("refusals", 0)
	base := nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: map[int][]byte{0: pcr0, 1: nitroPCR("refusals", 1)}}
	verifier := func(cfg AWSNitroVerifierConfig) *AWSNitroVerifier {
		if cfg.PinnedRoots == nil {
			cfg.PinnedRoots = [][]byte{chain.rootDER}
		}
		if cfg.Now == nil {
			cfg.Now = func() time.Time { return now }
		}
		v, err := NewAWSNitroVerifier(nil, pcr0, cfg)
		require.NoError(t, err)
		return v
	}
	strangerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name  string
		doc   func() nitroTestDoc
		cfg   AWSNitroVerifierConfig
		nonce []byte
		want  string
	}{
		{"nonce_absent", func() nitroTestDoc { d := base; d.Nonce = nil; return d }, AWSNitroVerifierConfig{}, nonce, "nonce"},
		{"nonce_other", func() nitroTestDoc { return base }, AWSNitroVerifierConfig{}, bytes.Repeat([]byte{0x5B}, NonceMinBytes), "nonce"},
		{"signature_flipped", func() nitroTestDoc { d := base; d.BadSignature = true; return d }, AWSNitroVerifierConfig{}, nonce, "COSE signature"},
		{"signed_by_stranger", func() nitroTestDoc { d := base; d.SignWith = strangerKey; return d }, AWSNitroVerifierConfig{}, nonce, "COSE signature"},
		{"other_chain_same_shape", func() nitroTestDoc {
			d := base
			d.Certificate = other.leafDER
			d.CABundle = other.bundle
			d.SignWith = other.leafKey
			return d
		}, AWSNitroVerifierConfig{}, nonce, "cabundle[0] is not a pinned root"},
		{"bundle_root_swapped", func() nitroTestDoc {
			d := base
			d.CABundle = append([][]byte{other.rootDER}, chain.bundle[1:]...)
			return d
		}, AWSNitroVerifierConfig{}, nonce, "cabundle[0] is not a pinned root"},
		{"bundle_missing_intermediate", func() nitroTestDoc {
			d := base
			d.CABundle = [][]byte{chain.bundle[0], chain.bundle[1], chain.bundle[3]}
			return d
		}, AWSNitroVerifierConfig{}, nonce, "certificate chain"},
		{"chain_expired_at_verification", func() nitroTestDoc { return base }, AWSNitroVerifierConfig{Now: func() time.Time { return now.Add(4 * time.Hour) }, MaxClockSkew: 5 * time.Hour}, nonce, "certificate chain"},
		{"alg_not_es384", func() nitroTestDoc { d := base; d.Alg = -7; return d }, AWSNitroVerifierConfig{}, nonce, "ES384"},
		{"alg_in_unprotected_header", func() nitroTestDoc { d := base; d.Unprotected = true; return d }, AWSNitroVerifierConfig{}, nonce, "ES384"},
		{"crit_header", func() nitroTestDoc { d := base; d.CritHeader = true; return d }, AWSNitroVerifierConfig{}, nonce, "critical"},
		{"detached_payload", func() nitroTestDoc { d := base; d.DetachPayload = true; return d }, AWSNitroVerifierConfig{}, nonce, "payload"},
		{"digest_not_sha384", func() nitroTestDoc { d := base; d.Digest = "SHA256"; return d }, AWSNitroVerifierConfig{}, nonce, "SHA384"},
		{"field_outside_specification", func() nitroTestDoc { d := base; d.ExtraField = true; return d }, AWSNitroVerifierConfig{}, nonce, "outside the specification"},
		{"cabundle_missing", func() nitroTestDoc { d := base; d.OmitCABundle = true; return d }, AWSNitroVerifierConfig{}, nonce, "cabundle"},
		{"stale_timestamp", func() nitroTestDoc { d := base; d.Timestamp = now.Add(-10 * time.Minute); return d }, AWSNitroVerifierConfig{}, nonce, "timestamp skew"},
		{"debug_mode_pcr0_zero", func() nitroTestDoc {
			d := base
			d.PCRs = map[int][]byte{0: make([]byte, 48), 1: nitroPCR("refusals", 1)}
			return d
		}, AWSNitroVerifierConfig{AcceptablePCRSet: []Measurement{make([]byte, 48)}}, nonce, "debug-mode"},
		{"pcr0_not_acceptable", func() nitroTestDoc { d := base; d.PCRs = map[int][]byte{0: nitroPCR("elsewhere", 0)}; return d }, AWSNitroVerifierConfig{}, nonce, "not in acceptable set"},
		{"selected_pcr_missing", func() nitroTestDoc { return base }, AWSNitroVerifierConfig{PCRIndex: 4}, nonce, "missing PCR4"},
		{"pcr_bad_length", func() nitroTestDoc { d := base; d.PCRs = map[int][]byte{0: pcr0[:20]}; return d }, AWSNitroVerifierConfig{}, nonce, "32, 48 or 64 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := chain.sign(t, tc.doc())
			_, err := verifier(tc.cfg).Verify(ev, tc.nonce)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err), "every refusal of evidence is an integrity error")
		})
	}
}

// TestAWSNitro_Verifier_AcceptableSetAndPCRIndex covers the rolling
// deployment set and the PCR selector.
func TestAWSNitro_Verifier_AcceptableSetAndPCRIndex(t *testing.T) {
	t.Parallel()
	now := time.Now()
	chain := newNitroTestChain(t, now)
	nonce := bytes.Repeat([]byte{0x11}, NonceMinBytes)
	current, canary := nitroPCR("current", 0), nitroPCR("canary", 0)
	pcr2 := nitroPCR("app", 2)
	ev := chain.sign(t, nitroTestDoc{Timestamp: now, Nonce: nonce, PCRs: map[int][]byte{0: canary, 2: pcr2}})

	v, err := NewAWSNitroVerifier(nil, current, AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now }, AcceptablePCRSet: []Measurement{current, canary}})
	require.NoError(t, err)
	got, err := v.Verify(ev, nonce)
	require.NoError(t, err)
	require.Equal(t, Measurement(canary), got)

	v2, err := NewAWSNitroVerifier(nil, pcr2, AWSNitroVerifierConfig{PinnedRoots: [][]byte{chain.rootDER}, Now: func() time.Time { return now }, PCRIndex: 2})
	require.NoError(t, err)
	got, err = v2.Verify(ev, nonce)
	require.NoError(t, err)
	require.Equal(t, Measurement(pcr2), got)
}

// TestAWSNitro_Verifier_ConstructorRefusals: bad configuration fails at
// construction, not at the first Verify.
func TestAWSNitro_Verifier_ConstructorRefusals(t *testing.T) {
	t.Parallel()
	_, err := NewAWSNitroVerifier(nil, Measurement{}, AWSNitroVerifierConfig{PinnedRoots: [][]byte{[]byte("not-der")}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a DER certificate")
	_, err = NewAWSNitroVerifier(nil, Measurement{}, AWSNitroVerifierConfig{PCRIndex: 32})
	require.Error(t, err)
	require.Contains(t, err.Error(), "outside 0..31")
	v, err := NewAWSNitroVerifier(nil, Measurement{}, AWSNitroVerifierConfig{})
	require.NoError(t, err, "the built-in root is the default")
	require.Len(t, v.pinnedRoots, 1)
}

// TestAWSNitro_Audit_TimeSemantics: a zero time audits at the document's
// timestamp; a later time finds the signing certificate expired.
func TestAWSNitro_Audit_TimeSemantics(t *testing.T) {
	t.Parallel()
	signedAt := time.Date(2026, 5, 8, 0, 52, 52, 755_000_000, time.UTC)
	chain := newNitroTestChain(t, signedAt)
	ev := chain.sign(t, nitroTestDoc{Timestamp: signedAt, UserData: bytes.Repeat([]byte{7}, 64)})

	report, err := AuditAWSNitroDocument(ev, [][]byte{chain.rootDER}, time.Time{})
	require.NoError(t, err)
	require.Nil(t, report.Nonce)
	require.True(t, report.Timestamp.Equal(signedAt))
	require.Equal(t, signedAt.Add(3*time.Hour).Unix(), report.SigningCertNotAfter.Unix())

	_, err = AuditAWSNitroDocument(ev, [][]byte{chain.rootDER}, signedAt.Add(24*time.Hour))
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate chain")

	_, err = AuditAWSNitroDocument(ev, nil, time.Time{})
	require.Error(t, err, "the synthetic chain does not reach AWS's root")
	require.Contains(t, err.Error(), "cabundle[0] is not a pinned root")

	_, err = AuditAWSNitroDocument(ev[:len(ev)-1], [][]byte{chain.rootDER}, time.Time{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse COSE_Sign1")
}

// TestAWSNitro_DecodeDocument_Shapes covers decoder refusals that the
// signer cannot produce through the knobs.
func TestAWSNitro_DecodeDocument_Shapes(t *testing.T) {
	t.Parallel()
	var e cborEncoder
	e.array(1)
	e.uint(1)
	_, err := decodeNitroAttestationDoc(e.buf)
	require.ErrorContains(t, err, "must be a map")

	var dup cborEncoder
	dup.mapping(2)
	dup.text("module_id")
	dup.text("a")
	dup.text("module_id")
	dup.text("b")
	_, err = decodeNitroAttestationDoc(dup.buf)
	require.ErrorContains(t, err, "more than once")

	var badTS cborEncoder
	badTS.mapping(2)
	badTS.text("module_id")
	badTS.text("m")
	badTS.text("digest")
	badTS.text("SHA384")
	_, err = decodeNitroAttestationDoc(badTS.buf)
	require.ErrorContains(t, err, "timestamp")

	_, err = parseCOSESign1([]byte{0xd3, 0x84, 0x40, 0xa0, 0x41, 0x01, 0x40}) // tag 19
	require.ErrorContains(t, err, "not COSE_Sign1")
	_, err = parseCOSESign1([]byte{0x83, 0x40, 0xa0, 0x40})
	require.ErrorContains(t, err, "four items")
}
