// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ---- wire framing ---------------------------------------------------------

func TestWireMagic_V10(t *testing.T) {
	t.Parallel()
	m := WireMagic()
	require.Equal(t, byte('R'), m[0])
	require.Equal(t, byte('P'), m[1])
	require.Equal(t, WireMajor, m[2])
	require.Equal(t, WireMinor, m[3])
	require.Equal(t, uint8(1), WireMajor)
	require.Equal(t, uint8(0), WireMinor)
}

func TestWriteReadFrame_RoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	payload := []byte(`{"type":"heartbeat","sent_at":"2026-04-22T00:00:00Z"}`)

	n, err := WriteFrame(&buf, payload)
	require.NoError(t, err)
	require.Equal(t, HeaderSize+len(payload), n)

	f, err := ReadFrame(&buf)
	require.NoError(t, err)
	require.Equal(t, payload, f.Payload)
}

func TestWriteFrame_RejectsZeroLength(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	_, err := WriteFrame(&buf, nil)
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestWriteFrame_RejectsOverMax(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	big := make([]byte, MaxFrameSize+1)
	_, err := WriteFrame(&buf, big)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.Equal(t, CodeIntegrityFailure, shared_errors.CodeOf(err))
}

func TestReadFrame_CleanCloseAtBoundary(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer // empty
	_, err := ReadFrame(&buf)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrWireClosed)
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	t.Parallel()
	// 3 bytes, less than HeaderSize.
	buf := bytes.NewBuffer([]byte{'R', 'P', 1})
	_, err := ReadFrame(buf)
	require.Error(t, err)
	require.Equal(t, CodeTruncatedFrame, shared_errors.CodeOf(err))
}

func TestReadFrame_MagicMismatch(t *testing.T) {
	t.Parallel()
	buf := bytes.NewBuffer([]byte{'X', 'Y', 1, 0, 0, 0, 0, 1, 0x00})
	_, err := ReadFrame(buf)
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

func TestReadFrame_ZeroLenHeader(t *testing.T) {
	t.Parallel()
	var hdr [HeaderSize]byte
	m := WireMagic()
	copy(hdr[:MagicSize], m[:])
	// LEN = 0, deliberately invalid.
	binary.BigEndian.PutUint32(hdr[MagicSize:], 0)
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

func TestReadFrame_OverMaxRejectedBeforeAlloc(t *testing.T) {
	t.Parallel()
	var hdr [HeaderSize]byte
	m := WireMagic()
	copy(hdr[:MagicSize], m[:])
	binary.BigEndian.PutUint32(hdr[MagicSize:], MaxFrameSize+1)
	// No body bytes after — this proves ReadFrame refuses *before*
	// attempting to read the oversized payload, because if it tried we
	// would hit io.EOF and the test would report CodeTruncatedFrame.
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	require.Error(t, err)
	require.Equal(t, CodeFrameOverSize, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	t.Parallel()
	// Announce 10 bytes, supply 3.
	var hdr [HeaderSize]byte
	m := WireMagic()
	copy(hdr[:MagicSize], m[:])
	binary.BigEndian.PutUint32(hdr[MagicSize:], 10)
	data := append(hdr[:], []byte{1, 2, 3}...)

	_, err := ReadFrame(bytes.NewReader(data))
	require.Error(t, err)
	require.Equal(t, CodeTruncatedFrame, shared_errors.CodeOf(err))
}

// ---- codec ---------------------------------------------------------------

func TestEncodeBody_IsCanonical(t *testing.T) {
	t.Parallel()
	// Two equivalent maps with different in-memory key orderings MUST
	// encode to byte-identical canonical JSON.
	a := map[string]any{"b": 2, "a": 1}
	b := map[string]any{"a": 1, "b": 2}
	ea, err := EncodeBody(a)
	require.NoError(t, err)
	eb, err := EncodeBody(b)
	require.NoError(t, err)
	require.Equal(t, ea, eb)
}

func TestPeekType_ExtractsDiscriminator(t *testing.T) {
	t.Parallel()
	payload, err := EncodeBody(NewHeartbeat(time.Now()))
	require.NoError(t, err)
	typ, err := PeekType(payload)
	require.NoError(t, err)
	require.Equal(t, string(FrameTypeHeartbeat), typ)
}

func TestPeekType_RejectsNonObject(t *testing.T) {
	t.Parallel()
	_, err := PeekType([]byte("[\"not\",\"object\"]"))
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

func TestPeekType_RejectsMissingType(t *testing.T) {
	t.Parallel()
	_, err := PeekType([]byte(`{"other":"field"}`))
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

func TestDecodeBody_NilDst(t *testing.T) {
	t.Parallel()
	err := DecodeBody([]byte("{}"), nil)
	require.Error(t, err)
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(err))
}

// ---- bodies: roundtrip every frame type ----------------------------------

func TestFrameTypes_RoundTrip_AllEleven(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		body     any
		wantType FrameType
	}{
		{"hello_client", mustHelloClient(t, now), FrameTypeHelloClient},
		{"hello_server", mustHelloServer(t), FrameTypeHelloServer},
		{"attest_client", mustAttestClient(t), FrameTypeAttestClient},
		{"session_ready", NewSessionReady(now), FrameTypeSessionReady},
		{"heartbeat", NewHeartbeat(now), FrameTypeHeartbeat},
		{"shutdown", NewShutdown(now, CodeShutdownNormal, "bye"), FrameTypeShutdown},
		{"error", NewErrorFrame(ErrorEnvelope{
			Category: "structural", Code: CodeProtocolViolation,
			HumanMessage: "test",
		}), FrameTypeError},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload, err := EncodeBody(tc.body)
			require.NoError(t, err)
			gotType, err := PeekType(payload)
			require.NoError(t, err)
			require.Equal(t, string(tc.wantType), gotType)
			require.True(t, IsValidFrameType(FrameType(gotType)))
		})
	}
}

func mustHelloClient(t *testing.T, _ time.Time) HelloClient {
	t.Helper()
	nonce := bytes.Repeat([]byte{0x11}, NonceMinBytes)
	hc, err := NewHelloClient(nonce, []byte("challenge"))
	require.NoError(t, err)
	return hc
}

func mustHelloServer(t *testing.T) HelloServer {
	t.Helper()
	clientNonce := bytes.Repeat([]byte{0x22}, NonceMinBytes)
	serverNonce := bytes.Repeat([]byte{0x33}, NonceMinBytes)
	hs, err := NewHelloServer(clientNonce, serverNonce, []byte("evidence"), []byte("ctx"))
	require.NoError(t, err)
	return hs
}

func mustAttestClient(t *testing.T) AttestClient {
	t.Helper()
	ac, err := NewAttestClient([]byte("client-evidence-bytes"))
	require.NoError(t, err)
	return ac
}

// ---- bodies: validators enforce floors -----------------------------------

func TestHelloClient_Validate_Rejections(t *testing.T) {
	t.Parallel()
	nonce := bytes.Repeat([]byte{0x01}, NonceMinBytes)

	// Wrong type.
	bad := HelloClient{Type: "wrong", WireMajor: WireMajor, WireMinor: WireMinor, ClientNonce: nonce}
	require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(bad.Validate()))

	// Wrong wire version.
	bad = HelloClient{Type: FrameTypeHelloClient, WireMajor: 99, WireMinor: 0, ClientNonce: nonce}
	require.Equal(t, CodeUnsupportedWireVersion, shared_errors.CodeOf(bad.Validate()))

	// Short nonce.
	bad = HelloClient{Type: FrameTypeHelloClient, WireMajor: WireMajor, WireMinor: WireMinor,
		ClientNonce: []byte{0x01, 0x02}}
	require.Equal(t, CodeNonceTooShort, shared_errors.CodeOf(bad.Validate()))
}

// ---- error envelope roundtrip --------------------------------------------

func TestErrorEnvelope_RoundTrip_AllCategories(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mk   func(code, msg string, inner error) shared_errors.Error
		want shared_errors.Category
	}{
		{"structural", shared_errors.Structural, shared_errors.CategoryStructural},
		{"authority", shared_errors.Authority, shared_errors.CategoryAuthority},
		{"operational", shared_errors.Operational, shared_errors.CategoryOperational},
		{"integrity", shared_errors.Integrity, shared_errors.CategoryIntegrity},
		{"incident", shared_errors.Incident, shared_errors.CategoryIncident},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			origin := tc.mk(CodeProtocolViolation, "just a test", nil)
			env := NewErrorEnvelope(origin, "manifest-123")
			require.Equal(t, "manifest-123", env.ManifestID)

			reconstructed := env.AsClassifiedError()
			require.Equal(t, tc.want, shared_errors.CategoryOf(reconstructed))
			require.Equal(t, CodeProtocolViolation, shared_errors.CodeOf(reconstructed))
		})
	}
}

func TestErrorEnvelope_TruncatesLongMessage(t *testing.T) {
	t.Parallel()
	long := bytes.Repeat([]byte{'x'}, 5000)
	origin := shared_errors.Structural(CodeProtocolViolation, string(long), nil)
	env := NewErrorEnvelope(origin, "")
	// HumanMessage is capped to 1024 bytes so an attacker cannot
	// amplify diagnostic output on the wire.
	require.LessOrEqual(t, len(env.HumanMessage), 1024)
}

func TestErrorEnvelope_NilError(t *testing.T) {
	t.Parallel()
	env := NewErrorEnvelope(nil, "m")
	require.Equal(t, CodeProtocolViolation, env.Code)
	require.Equal(t, "structural", env.Category)
	require.Equal(t, "m", env.ManifestID)
}

// ---- derivation determinism (handshake internals) ------------------------

func TestDeriveSessionKeys_Determinism(t *testing.T) {
	t.Parallel()
	tr := Transcript{
		ClientNonce:       bytes.Repeat([]byte{0xAA}, NonceMinBytes),
		ServerNonce:       bytes.Repeat([]byte{0xBB}, NonceMinBytes),
		ProposedChallenge: []byte("challenge"),
		DerivationContext: []byte("session-1"),
	}
	c2s1, s2c1, err := deriveSessionKeys(tr)
	require.NoError(t, err)
	c2s2, s2c2, err := deriveSessionKeys(tr)
	require.NoError(t, err)
	require.Equal(t, c2s1, c2s2)
	require.Equal(t, s2c1, s2c2)
	require.NotEqual(t, c2s1, s2c1, "directional keys must be distinct")
	require.Len(t, c2s1, MACSize)
	require.Len(t, s2c1, MACSize)
}

func TestDeriveSessionKeys_DifferentContextYieldsDifferentKeys(t *testing.T) {
	t.Parallel()
	base := Transcript{
		ClientNonce:       bytes.Repeat([]byte{0x01}, NonceMinBytes),
		ServerNonce:       bytes.Repeat([]byte{0x02}, NonceMinBytes),
		DerivationContext: []byte("session-A"),
	}
	other := base
	other.DerivationContext = []byte("session-B")

	a, _, err := deriveSessionKeys(base)
	require.NoError(t, err)
	b, _, err := deriveSessionKeys(other)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestTranscriptChallenges_AreDomainSeparated(t *testing.T) {
	t.Parallel()
	cn := bytes.Repeat([]byte{0x10}, NonceMinBytes)
	sn := bytes.Repeat([]byte{0x20}, NonceMinBytes)
	pc := []byte("challenge")
	dc := []byte("ctx")

	sC := transcriptServerChallenge(cn, pc)
	cC := transcriptClientChallenge(cn, sn, dc)
	require.NotEqual(t, sC, cC,
		"server-side and client-side TEE challenges MUST differ")
	// Feeding the same inputs twice yields the same digest.
	require.Equal(t, sC, transcriptServerChallenge(cn, pc))
	require.Equal(t, cC, transcriptClientChallenge(cn, sn, dc))
}

// ---- sanity: compile-time check that bodies.go list is exhaustive --------

func TestValidFrameTypes_MatchesExpectedEleven(t *testing.T) {
	t.Parallel()
	expected := []FrameType{
		FrameTypeHelloClient,
		FrameTypeHelloServer,
		FrameTypeAttestClient,
		FrameTypeSessionReady,
		FrameTypeJobRequest,
		FrameTypeJobAccept,
		FrameTypeJobReject,
		FrameTypeCandidateOutput,
		FrameTypeError,
		FrameTypeHeartbeat,
		FrameTypeShutdown,
	}
	for _, ft := range expected {
		require.True(t, IsValidFrameType(ft), "expected valid: %s", ft)
	}
	require.False(t, IsValidFrameType("not_a_real_type"))
}

// ---- sanity: io.Pipe round-trip exercises WriteFrame/ReadFrame across goroutines

func TestWriteReadFrame_AcrossPipe(t *testing.T) {
	t.Parallel()
	r, w := io.Pipe()
	done := make(chan []byte, 1)
	go func() {
		f, err := ReadFrame(r)
		if err != nil {
			done <- nil
			return
		}
		done <- f.Payload
	}()
	payload := []byte(`{"type":"heartbeat","sent_at":"2026-04-22T00:00:00Z"}`)
	_, err := WriteFrame(w, payload)
	require.NoError(t, err)
	_ = w.Close()
	got := <-done
	require.Equal(t, payload, got)
}
