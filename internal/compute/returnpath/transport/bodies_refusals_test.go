// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Every frame body refuses what the wire contract says it must refuse,
// with the code the contract names, and accepts a well-formed instance.
// One table per body; each row changes exactly one field of a valid
// value, so a passing row proves that field's check and nothing else.

func nonceOf(b byte) []byte { return bytes.Repeat([]byte{b}, NonceMinBytes) }

func requireStructural(t *testing.T, err error, code string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, code, shared_errors.CodeOf(err))
}

func TestHelloServer_Validate(t *testing.T) {
	t.Parallel()
	valid := mustHelloServer(t)
	require.NoError(t, valid.Validate())
	cases := []struct {
		name string
		mut  func(*HelloServer)
		code string
	}{
		{"type", func(h *HelloServer) { h.Type = FrameTypeHeartbeat }, CodeProtocolViolation},
		{"short echo", func(h *HelloServer) { h.ClientNonceEcho = h.ClientNonceEcho[:NonceMinBytes-1] }, CodeNonceTooShort},
		{"short server nonce", func(h *HelloServer) { h.ServerNonce = nil }, CodeNonceTooShort},
		{"no evidence", func(h *HelloServer) { h.ServerEvidence = nil }, CodeProtocolViolation},
		{"no derivation context", func(h *HelloServer) { h.DerivationContext = []byte{} }, CodeProtocolViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := valid
			tc.mut(&h)
			requireStructural(t, h.Validate(), tc.code)
		})
	}
}

func TestNewHelloServer_RefusesShortNonces(t *testing.T) {
	t.Parallel()
	_, err := NewHelloServer(nonceOf(1)[:3], nonceOf(2), []byte("ev"), []byte("ctx"))
	requireStructural(t, err, CodeNonceTooShort)
	_, err = NewHelloServer(nonceOf(1), nonceOf(2)[:3], []byte("ev"), []byte("ctx"))
	requireStructural(t, err, CodeNonceTooShort)
	hs, err := NewHelloServer(nonceOf(1), nonceOf(2), []byte("ev"), []byte("ctx"))
	require.NoError(t, err)
	require.Equal(t, FrameTypeHelloServer, hs.Type)
}

func TestAttestClient_Validate(t *testing.T) {
	t.Parallel()
	_, err := NewAttestClient(nil)
	requireStructural(t, err, CodeProtocolViolation)
	valid := mustAttestClient(t)
	require.NoError(t, valid.Validate())
	bad := valid
	bad.Type = FrameTypeHelloClient
	requireStructural(t, bad.Validate(), CodeProtocolViolation)
	bad = valid
	bad.ClientEvidence = nil
	requireStructural(t, bad.Validate(), CodeProtocolViolation)
}

func TestSessionReady_Validate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC)
	valid := NewSessionReady(now)
	require.NoError(t, valid.Validate())
	require.Equal(t, now, valid.ReadyAt)
	bad := valid
	bad.Type = FrameTypeShutdown
	requireStructural(t, bad.Validate(), CodeProtocolViolation)
	requireStructural(t, SessionReady{Type: FrameTypeSessionReady}.Validate(), CodeProtocolViolation)
}

func validJobRequest() JobRequest {
	issued := time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC)
	return JobRequest{
		Type:                   FrameTypeJobRequest,
		SchemaVersion:          1,
		ManifestID:             "manifest-1",
		SessionID:              "session-1",
		ExpectedOutputKind:     "weights",
		ExpectedOutputMaxBytes: 1 << 20,
		Deadline:               issued.Add(time.Hour),
		IssuedAt:               issued,
		SealedMaterial: []SealedMaterialRef{{
			RecipientKeyID: "worker-key-1",
			Nonce:          []byte{1, 2, 3},
			Ciphertext:     []byte{4, 5, 6},
		}},
	}
}

func TestJobRequest_Validate(t *testing.T) {
	t.Parallel()
	require.NoError(t, validJobRequest().Validate())
	cases := []struct {
		name string
		mut  func(*JobRequest)
	}{
		{"type", func(j *JobRequest) { j.Type = FrameTypeJobAccept }},
		{"schema version", func(j *JobRequest) { j.SchemaVersion = 2 }},
		{"manifest id", func(j *JobRequest) { j.ManifestID = "" }},
		{"session id", func(j *JobRequest) { j.SessionID = "" }},
		{"output kind", func(j *JobRequest) { j.ExpectedOutputKind = "" }},
		{"output max bytes", func(j *JobRequest) { j.ExpectedOutputMaxBytes = 0 }},
		{"deadline", func(j *JobRequest) { j.Deadline = time.Time{} }},
		{"issued at", func(j *JobRequest) { j.IssuedAt = time.Time{} }},
		{"deadline before issue", func(j *JobRequest) { j.Deadline = j.IssuedAt }},
		{"no material", func(j *JobRequest) { j.SealedMaterial = nil }},
		{"material without recipient", func(j *JobRequest) { j.SealedMaterial[0].RecipientKeyID = "" }},
		{"material without nonce", func(j *JobRequest) { j.SealedMaterial[0].Nonce = nil }},
		{"material without ciphertext", func(j *JobRequest) { j.SealedMaterial[0].Ciphertext = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := validJobRequest()
			j.SealedMaterial = append([]SealedMaterialRef(nil), j.SealedMaterial...)
			tc.mut(&j)
			requireStructural(t, j.Validate(), CodeProtocolViolation)
		})
	}
}

func TestJobRequest_NamesTheOffendingMaterialIndex(t *testing.T) {
	t.Parallel()
	j := validJobRequest()
	j.SealedMaterial = append(j.SealedMaterial, SealedMaterialRef{RecipientKeyID: "k", Nonce: []byte{1}})
	err := j.Validate()
	requireStructural(t, err, CodeProtocolViolation)
	require.Contains(t, err.Error(), "sealed_material[1]")
}

func TestJobAccept_Validate(t *testing.T) {
	t.Parallel()
	valid := JobAccept{Type: FrameTypeJobAccept, ManifestID: "m", AcceptedAt: time.Now().UTC(), EstimatedDuration: time.Second}
	require.NoError(t, valid.Validate())
	cases := []struct {
		name string
		mut  func(*JobAccept)
	}{
		{"type", func(j *JobAccept) { j.Type = FrameTypeJobReject }},
		{"manifest id", func(j *JobAccept) { j.ManifestID = "" }},
		{"accepted at", func(j *JobAccept) { j.AcceptedAt = time.Time{} }},
		{"zero duration", func(j *JobAccept) { j.EstimatedDuration = 0 }},
		{"negative duration", func(j *JobAccept) { j.EstimatedDuration = -time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := valid
			tc.mut(&j)
			requireStructural(t, j.Validate(), CodeProtocolViolation)
		})
	}
}

func TestJobReject_Validate(t *testing.T) {
	t.Parallel()
	valid := JobReject{Type: FrameTypeJobReject, ManifestID: "m", RejectedAt: time.Now().UTC(), Reason: "cannot_unseal"}
	require.NoError(t, valid.Validate())
	cases := []struct {
		name string
		mut  func(*JobReject)
	}{
		{"type", func(j *JobReject) { j.Type = FrameTypeJobAccept }},
		{"manifest id", func(j *JobReject) { j.ManifestID = "" }},
		{"rejected at", func(j *JobReject) { j.RejectedAt = time.Time{} }},
		{"reason", func(j *JobReject) { j.Reason = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := valid
			tc.mut(&j)
			requireStructural(t, j.Validate(), CodeProtocolViolation)
		})
	}
}

func validCandidateOutput() CandidateOutputFrame {
	return CandidateOutputFrame{
		Type: FrameTypeCandidateOutput, ManifestID: "m", SessionID: "s", OutputKind: "weights",
		Bytes: []byte{9, 9, 9}, ProducedAt: time.Now().UTC(), WorkerSigningKeyID: "worker-1", WorkerSignature: []byte{7},
	}
}

func TestCandidateOutputFrame_Validate(t *testing.T) {
	t.Parallel()
	require.NoError(t, validCandidateOutput().Validate())
	cases := []struct {
		name string
		mut  func(*CandidateOutputFrame)
	}{
		{"type", func(c *CandidateOutputFrame) { c.Type = FrameTypeJobRequest }},
		{"manifest id", func(c *CandidateOutputFrame) { c.ManifestID = "" }},
		{"session id", func(c *CandidateOutputFrame) { c.SessionID = "" }},
		{"output kind", func(c *CandidateOutputFrame) { c.OutputKind = "" }},
		{"empty bytes", func(c *CandidateOutputFrame) { c.Bytes = nil }},
		{"produced at", func(c *CandidateOutputFrame) { c.ProducedAt = time.Time{} }},
		{"signing key id", func(c *CandidateOutputFrame) { c.WorkerSigningKeyID = "" }},
		{"signature", func(c *CandidateOutputFrame) { c.WorkerSignature = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCandidateOutput()
			tc.mut(&c)
			requireStructural(t, c.Validate(), CodeProtocolViolation)
		})
	}
}

func TestCandidateOutputFrame_CoverBytesExcludesTheSignature(t *testing.T) {
	t.Parallel()
	c := validCandidateOutput()
	cover, err := c.CoverBytes()
	require.NoError(t, err)
	var back CandidateOutputFrame
	require.NoError(t, DecodeBody(cover, &back))
	require.Empty(t, back.WorkerSignature, "the covered bytes carry no signature")
	require.Equal(t, c.Bytes, back.Bytes)
	require.Equal(t, []byte{7}, c.WorkerSignature, "the frame itself is untouched")
	other := c
	other.WorkerSignature = []byte{8, 8}
	cover2, err := other.CoverBytes()
	require.NoError(t, err)
	require.Equal(t, cover, cover2, "the signature does not change what is signed")
}

func TestErrorFrame_Validate(t *testing.T) {
	t.Parallel()
	env := NewErrorEnvelope(shared_errors.Structural(CodeProtocolViolation, "x", nil), "manifest-1")
	valid := NewErrorFrame(env)
	require.NoError(t, valid.Validate())
	bad := valid
	bad.Type = FrameTypeHeartbeat
	requireStructural(t, bad.Validate(), CodeProtocolViolation)
	bad = valid
	bad.Envelope.Code = ""
	requireStructural(t, bad.Validate(), CodeProtocolViolation)
	bad = valid
	bad.Envelope.Category = ""
	requireStructural(t, bad.Validate(), CodeProtocolViolation)
}

func TestHeartbeatAndShutdown_Validate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC)
	hb := NewHeartbeat(now)
	require.NoError(t, hb.Validate())
	requireStructural(t, Heartbeat{Type: FrameTypeShutdown, SentAt: now}.Validate(), CodeProtocolViolation)
	requireStructural(t, Heartbeat{Type: FrameTypeHeartbeat}.Validate(), CodeProtocolViolation)

	sd := NewShutdown(now, "", "bye")
	require.Equal(t, CodeShutdownNormal, sd.Reason, "an empty reason is the normal close")
	require.NoError(t, sd.Validate())
	requireStructural(t, Shutdown{Type: FrameTypeHeartbeat, SentAt: now, Reason: "x"}.Validate(), CodeProtocolViolation)
	requireStructural(t, Shutdown{Type: FrameTypeShutdown, Reason: "x"}.Validate(), CodeProtocolViolation)
	requireStructural(t, Shutdown{Type: FrameTypeShutdown, SentAt: now}.Validate(), CodeProtocolViolation)
}

func TestItoa(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   int
		want string
	}{{0, "0"}, {7, "7"}, {10, "10"}, {4096, "4096"}, {-1, "-1"}, {-120, "-120"}} {
		require.Equal(t, tc.want, itoa(tc.in), "itoa(%d)", tc.in)
	}
}
