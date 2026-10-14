// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"time"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// FrameType is the on-wire `type` discriminator that every frame body
// carries as its first field. Stable strings — changing any of them is
// a wire-version break and requires a MAGIC bump per §3.2.
//
// The order of constants below mirrors the order frames appear on the
// wire during a normal session lifetime: handshake (four), then
// job-cycle (four), then either-direction utility frames (three).
type FrameType string

const (
	// --- handshake ---

	FrameTypeHelloClient  FrameType = "HELLO_CLIENT"
	FrameTypeHelloServer  FrameType = "HELLO_SERVER"
	FrameTypeAttestClient FrameType = "ATTEST_CLIENT"
	FrameTypeSessionReady FrameType = "SESSION_READY"

	// --- job cycle ---

	FrameTypeJobRequest      FrameType = "JOB_REQUEST"
	FrameTypeJobAccept       FrameType = "JOB_ACCEPT"
	FrameTypeJobReject       FrameType = "JOB_REJECT"
	FrameTypeCandidateOutput FrameType = "CANDIDATE_OUTPUT"

	// --- utility / shared ---

	FrameTypeError     FrameType = "ERROR"
	FrameTypeHeartbeat FrameType = "HEARTBEAT"
	FrameTypeShutdown  FrameType = "SHUTDOWN"
)

// validFrameTypes enumerates every legal wire-format discriminator.
// An unknown `type` on a decoded frame is a Structural /
// CodeProtocolViolation per §3.5.
var validFrameTypes = map[FrameType]struct{}{
	FrameTypeHelloClient:     {},
	FrameTypeHelloServer:     {},
	FrameTypeAttestClient:    {},
	FrameTypeSessionReady:    {},
	FrameTypeJobRequest:      {},
	FrameTypeJobAccept:       {},
	FrameTypeJobReject:       {},
	FrameTypeCandidateOutput: {},
	FrameTypeError:           {},
	FrameTypeHeartbeat:       {},
	FrameTypeShutdown:        {},
}

// IsValidFrameType reports whether t is one of the eleven frozen
// wire-format frame-type discriminators.
func IsValidFrameType(t FrameType) bool {
	_, ok := validFrameTypes[t]
	return ok
}

// ----------------------------------------------------------------------------
// Handshake bodies
// ----------------------------------------------------------------------------

// HelloClient is the first frame on every connection: the client
// asserts what wire version it wants to speak, offers a fresh nonce,
// and supplies the challenge bytes the server must cover in its
// subsequent TEE evidence.
//
// ProposedChallenge is opaque to transport — the client chose it, the
// server's TEE evidence must demonstrate it (i.e. the server-side
// attestation must bind ProposedChallenge into its quote_data). The
// server does NOT interpret ProposedChallenge as a structured value;
// the client may embed whatever context its attestation policy wants.
type HelloClient struct {
	Type              FrameType `json:"type"`
	WireMajor         uint8     `json:"wire_major"`
	WireMinor         uint8     `json:"wire_minor"`
	ClientNonce       []byte    `json:"client_nonce"`
	ProposedChallenge []byte    `json:"proposed_challenge,omitempty"`
}

// NewHelloClient constructs a HelloClient with the current Type tag and
// the negotiated wire version. Returns Structural / CodeNonceTooShort
// if nonce is shorter than NonceMinBytes.
func NewHelloClient(nonce, challenge []byte) (HelloClient, error) {
	if len(nonce) < NonceMinBytes {
		return HelloClient{}, shared_errors.Structural(
			CodeNonceTooShort,
			"returnpath/transport: HelloClient.ClientNonce below NonceMinBytes",
			nil,
		)
	}
	return HelloClient{
		Type:              FrameTypeHelloClient,
		WireMajor:         WireMajor,
		WireMinor:         WireMinor,
		ClientNonce:       append([]byte(nil), nonce...),
		ProposedChallenge: append([]byte(nil), challenge...),
	}, nil
}

// Validate runs structural checks on a decoded HelloClient:
// Type discriminator is correct, wire-version is exactly v1.0, nonce
// meets NonceMinBytes.
func (h HelloClient) Validate() error {
	if h.Type != FrameTypeHelloClient {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HelloClient.type mismatch",
			nil,
		)
	}
	if h.WireMajor != WireMajor || h.WireMinor != WireMinor {
		return shared_errors.Structural(
			CodeUnsupportedWireVersion,
			"returnpath/transport: HelloClient declares unsupported wire version",
			nil,
		)
	}
	if len(h.ClientNonce) < NonceMinBytes {
		return shared_errors.Structural(
			CodeNonceTooShort,
			"returnpath/transport: HelloClient.ClientNonce below NonceMinBytes",
			nil,
		)
	}
	return nil
}

// HelloServer is the server's handshake-phase response: it echoes the
// client's nonce (so the client can prove freshness), adds its own
// nonce, presents its TEE evidence, and publishes the session-key
// derivation context both sides will feed into HKDF.
//
// ServerEvidence is opaque to transport — the client's attestation
// verifier (provided by the caller of Dial/Handshake) is responsible
// for interpreting it. The transport layer only ensures the frame is
// well-formed and relays ServerEvidence upward.
type HelloServer struct {
	Type            FrameType `json:"type"`
	ClientNonceEcho []byte    `json:"client_nonce_echo"`
	ServerNonce     []byte    `json:"server_nonce"`
	ServerEvidence  []byte    `json:"server_evidence"`

	// DerivationContext is the HKDF info-string both sides feed into
	// the session-key derivation (see session.go). It is public on the
	// wire; its role is to domain-separate this session's MAC key from
	// any other session's.
	DerivationContext []byte `json:"derivation_context"`
}

// NewHelloServer constructs a HelloServer. Returns Structural /
// CodeNonceTooShort when either nonce fails the minimum-length check;
// clientNonceEcho must match the HelloClient.ClientNonce this server
// just received.
func NewHelloServer(clientNonceEcho, serverNonce, serverEvidence, derivationContext []byte) (HelloServer, error) {
	if len(clientNonceEcho) < NonceMinBytes {
		return HelloServer{}, shared_errors.Structural(
			CodeNonceTooShort,
			"returnpath/transport: HelloServer.ClientNonceEcho below NonceMinBytes",
			nil,
		)
	}
	if len(serverNonce) < NonceMinBytes {
		return HelloServer{}, shared_errors.Structural(
			CodeNonceTooShort,
			"returnpath/transport: HelloServer.ServerNonce below NonceMinBytes",
			nil,
		)
	}
	return HelloServer{
		Type:              FrameTypeHelloServer,
		ClientNonceEcho:   append([]byte(nil), clientNonceEcho...),
		ServerNonce:       append([]byte(nil), serverNonce...),
		ServerEvidence:    append([]byte(nil), serverEvidence...),
		DerivationContext: append([]byte(nil), derivationContext...),
	}, nil
}

// Validate runs structural checks on a decoded HelloServer.
func (h HelloServer) Validate() error {
	if h.Type != FrameTypeHelloServer {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HelloServer.type mismatch",
			nil,
		)
	}
	if len(h.ClientNonceEcho) < NonceMinBytes {
		return shared_errors.Structural(
			CodeNonceTooShort,
			"returnpath/transport: HelloServer.ClientNonceEcho below NonceMinBytes",
			nil,
		)
	}
	if len(h.ServerNonce) < NonceMinBytes {
		return shared_errors.Structural(
			CodeNonceTooShort,
			"returnpath/transport: HelloServer.ServerNonce below NonceMinBytes",
			nil,
		)
	}
	if len(h.ServerEvidence) == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HelloServer.ServerEvidence required",
			nil,
		)
	}
	if len(h.DerivationContext) == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: HelloServer.DerivationContext required",
			nil,
		)
	}
	return nil
}

// AttestClient is the third handshake frame: the client supplies its
// own TEE evidence, binding the server's challenge (the ProposedChallenge
// the client itself sent — the server committed to cover it in its
// evidence, and the client now has to prove it holds a TEE that can
// produce evidence against that same challenge on its side).
//
// Conceptually: HelloClient.ProposedChallenge travels outbound;
// HelloServer.ServerEvidence covers it on the server side;
// AttestClient.ClientEvidence covers the SAME challenge on the
// client side. The symmetry is deliberate — both peers prove to each
// other that they are TEE-bound before any sealed material moves.
type AttestClient struct {
	Type           FrameType `json:"type"`
	ClientEvidence []byte    `json:"client_evidence"`
}

// NewAttestClient constructs an AttestClient. Evidence must be
// non-empty.
func NewAttestClient(evidence []byte) (AttestClient, error) {
	if len(evidence) == 0 {
		return AttestClient{}, shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: AttestClient.ClientEvidence required",
			nil,
		)
	}
	return AttestClient{
		Type:           FrameTypeAttestClient,
		ClientEvidence: append([]byte(nil), evidence...),
	}, nil
}

// Validate runs structural checks on a decoded AttestClient.
func (a AttestClient) Validate() error {
	if a.Type != FrameTypeAttestClient {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: AttestClient.type mismatch",
			nil,
		)
	}
	if len(a.ClientEvidence) == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: AttestClient.ClientEvidence required",
			nil,
		)
	}
	return nil
}

// SessionReady is the fourth and final handshake frame: the server
// confirms that both TEE evidences verified and subsequent frames
// will be MAC-authenticated.
//
// ReadyAt lets the client log precisely when the session entered the
// authenticated regime — useful during live demos and indispensable
// when correlating transport-level timing with audit-chain
// timestamps.
type SessionReady struct {
	Type    FrameType `json:"type"`
	ReadyAt time.Time `json:"ready_at"`
}

// NewSessionReady constructs a SessionReady frame.
func NewSessionReady(now time.Time) SessionReady {
	return SessionReady{
		Type:    FrameTypeSessionReady,
		ReadyAt: now.UTC(),
	}
}

// Validate runs structural checks on a decoded SessionReady.
func (s SessionReady) Validate() error {
	if s.Type != FrameTypeSessionReady {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: SessionReady.type mismatch",
			nil,
		)
	}
	if s.ReadyAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: SessionReady.ReadyAt required",
			nil,
		)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Job-cycle bodies
// ----------------------------------------------------------------------------

// SealedMaterialRef is the pointer + unsealing context that a
// JobRequest hands to the worker. It mirrors the on-the-wire
// representation of a sealed disclosure: AES-256-GCM Nonce +
// Ciphertext + AAD, plus the RecipientKeyID the worker's keystore
// uses to Open() the plaintext.
//
// StoreKey is an opaque string — the vault side may also keep the
// sealed bytes in a content-addressed store and emit a pointer here
// instead of inlining Ciphertext; Phase 1 uses the inline shape
// because the demo fits comfortably in a 16 MiB frame. If a future
// phase needs out-of-band fetch, StoreKey becomes mandatory and the
// Ciphertext/Nonce fields become optional — that is a compatibility-
// preserving addition (new nullable fields, same wire version).
type SealedMaterialRef struct {
	StoreKey       string `json:"store_key,omitempty"`
	RecipientKeyID string `json:"recipient_key_id"`
	Nonce          []byte `json:"nonce"`
	Ciphertext     []byte `json:"ciphertext"`
	AAD            []byte `json:"aad,omitempty"`
}

// JobRequest is the server-to-client frame that carries one
// reconstruction assignment. Every field mirrors exactly one field of
// the authority-side ReconstructionJobManifest plus the sealed
// material the worker is being asked to operate on.
//
// The wire `JobRequest.SchemaVersion` is 1 and is frozen for
// wire-version v1.0 — bumping the manifest-side schema version is
// allowed as long as the wire schema version here stays 1 and the
// new manifest fields are optional.
type JobRequest struct {
	Type                   FrameType           `json:"type"`
	SchemaVersion          uint16              `json:"schema_version"`
	ManifestID             string              `json:"manifest_id"`
	SessionID              string              `json:"session_id"`
	ExpectedOutputKind     string              `json:"expected_output_kind"`
	ExpectedOutputMaxBytes uint64              `json:"expected_output_max_bytes"`
	Deadline               time.Time           `json:"deadline"`
	IssuedAt               time.Time           `json:"issued_at"`
	SealedMaterial         []SealedMaterialRef `json:"sealed_material"`
}

// Validate checks JobRequest structurally. Does NOT re-check the
// manifest signature — that is the server-side's responsibility
// (sagvd signs the manifest before sending; worker receives it signed
// inside `SealedMaterial[].AAD` at Phase 3+, inline trusted at Phase 1
// because the connection is already authenticated end-to-end by the
// handshake).
func (j JobRequest) Validate() error {
	if j.Type != FrameTypeJobRequest {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.type mismatch",
			nil,
		)
	}
	if j.SchemaVersion != 1 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.schema_version must be 1 on wire v1.0",
			nil,
		)
	}
	if j.ManifestID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.manifest_id required",
			nil,
		)
	}
	if j.SessionID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.session_id required",
			nil,
		)
	}
	if j.ExpectedOutputKind == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.expected_output_kind required",
			nil,
		)
	}
	if j.ExpectedOutputMaxBytes == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.expected_output_max_bytes must be > 0",
			nil,
		)
	}
	if j.Deadline.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.deadline required",
			nil,
		)
	}
	if j.IssuedAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.issued_at required",
			nil,
		)
	}
	if !j.Deadline.After(j.IssuedAt) {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.deadline must be after issued_at",
			nil,
		)
	}
	if len(j.SealedMaterial) == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobRequest.sealed_material required",
			nil,
		)
	}
	for i, m := range j.SealedMaterial {
		if m.RecipientKeyID == "" || len(m.Nonce) == 0 || len(m.Ciphertext) == 0 {
			return shared_errors.Structural(
				CodeProtocolViolation,
				"returnpath/transport: JobRequest.sealed_material["+itoa(i)+"] missing mandatory fields",
				nil,
			)
		}
	}
	return nil
}

// JobAccept is the worker's positive acknowledgement: "I have the
// manifest, I can unseal the material, I will reconstruct by
// EstimatedFinish." Declining is done via JobReject (never by silent
// drop) so the server can invalidate the session if the worker ghosts
// after a timeout.
type JobAccept struct {
	Type              FrameType     `json:"type"`
	ManifestID        string        `json:"manifest_id"`
	AcceptedAt        time.Time     `json:"accepted_at"`
	EstimatedDuration time.Duration `json:"estimated_duration_ns"`
}

// Validate structural-checks a JobAccept.
func (j JobAccept) Validate() error {
	if j.Type != FrameTypeJobAccept {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobAccept.type mismatch",
			nil,
		)
	}
	if j.ManifestID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobAccept.manifest_id required",
			nil,
		)
	}
	if j.AcceptedAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobAccept.accepted_at required",
			nil,
		)
	}
	if j.EstimatedDuration <= 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobAccept.estimated_duration_ns must be > 0",
			nil,
		)
	}
	return nil
}

// JobReject is the worker's negative acknowledgement. The Reason
// field MUST be a stable canonical code (either one of shared/errors
// Code* or a transport-local Code*) so the server can classify the
// rejection without parsing HumanMessage.
type JobReject struct {
	Type         FrameType `json:"type"`
	ManifestID   string    `json:"manifest_id"`
	RejectedAt   time.Time `json:"rejected_at"`
	Reason       string    `json:"reason"`
	HumanMessage string    `json:"human_message,omitempty"`
}

// Validate structural-checks a JobReject.
func (j JobReject) Validate() error {
	if j.Type != FrameTypeJobReject {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobReject.type mismatch",
			nil,
		)
	}
	if j.ManifestID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobReject.manifest_id required",
			nil,
		)
	}
	if j.RejectedAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobReject.rejected_at required",
			nil,
		)
	}
	if j.Reason == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: JobReject.reason required",
			nil,
		)
	}
	return nil
}

// CandidateOutputFrame is the worker-to-server frame carrying the
// proposed reconstruction. It mirrors the in-process
// returnpath.CandidateOutput shape (ManifestID, SessionID, OutputKind,
// Bytes, ProducedAt) and adds a WorkerSignature over the canonical
// encoding of the rest of the body for non-repudiable audit.
//
// The struct is named CandidateOutputFrame (not CandidateOutput) to
// avoid a collision with the existing
// /core/internal/compute/returnpath.CandidateOutput type which the
// server side translates this frame into. Callers should use the
// ToCandidateOutput / FromCandidateOutput helpers in server/client
// packages (task #73 follow-up) to convert between the two.
type CandidateOutputFrame struct {
	Type               FrameType `json:"type"`
	ManifestID         string    `json:"manifest_id"`
	SessionID          string    `json:"session_id"`
	OutputKind         string    `json:"output_kind"`
	Bytes              []byte    `json:"bytes"`
	ProducedAt         time.Time `json:"produced_at"`
	WorkerSigningKeyID string    `json:"worker_signing_key_id"`
	WorkerSignature    []byte    `json:"worker_signature"`
}

// Validate structural-checks a CandidateOutputFrame. Does NOT verify
// WorkerSignature — that is the caller's responsibility (the caller
// has the Resolver for worker keys; transport does not).
func (c CandidateOutputFrame) Validate() error {
	if c.Type != FrameTypeCandidateOutput {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.type mismatch",
			nil,
		)
	}
	if c.ManifestID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.manifest_id required",
			nil,
		)
	}
	if c.SessionID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.session_id required",
			nil,
		)
	}
	if c.OutputKind == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.output_kind required",
			nil,
		)
	}
	if len(c.Bytes) == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.bytes required (empty success is a protocol violation per /internal/compute/returnpath/candidate_output.go)",
			nil,
		)
	}
	if c.ProducedAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.produced_at required",
			nil,
		)
	}
	if c.WorkerSigningKeyID == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.worker_signing_key_id required",
			nil,
		)
	}
	if len(c.WorkerSignature) == 0 {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: CandidateOutputFrame.worker_signature required",
			nil,
		)
	}
	return nil
}

// CoverBytes returns the canonical-JSON bytes the worker must sign.
// This is the body with WorkerSignature zeroed out. The server
// re-encodes the received frame the same way and verifies the
// signature against CoverBytes.
func (c CandidateOutputFrame) CoverBytes() ([]byte, error) {
	cp := c
	cp.WorkerSignature = nil
	return EncodeBody(cp)
}

// ----------------------------------------------------------------------------
// Utility bodies
// ----------------------------------------------------------------------------

// ErrorFrame wraps ErrorEnvelope in a frame-typed shell. ErrorEnvelope
// itself is defined in errors.go (where the classified-error mapping
// lives); the frame wrapper adds the `type` discriminator.
type ErrorFrame struct {
	Type     FrameType     `json:"type"`
	Envelope ErrorEnvelope `json:"envelope"`
}

// NewErrorFrame wraps an ErrorEnvelope for the wire.
func NewErrorFrame(env ErrorEnvelope) ErrorFrame {
	return ErrorFrame{
		Type:     FrameTypeError,
		Envelope: env,
	}
}

// Validate structural-checks an ErrorFrame.
func (e ErrorFrame) Validate() error {
	if e.Type != FrameTypeError {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: ErrorFrame.type mismatch",
			nil,
		)
	}
	if e.Envelope.Category == "" || e.Envelope.Code == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: ErrorFrame.envelope missing category or code",
			nil,
		)
	}
	return nil
}

// Heartbeat is an empty-bodied liveness probe. Either side may send
// it on an otherwise-idle connection; the receiver is expected to
// either respond with another Heartbeat or proceed with any queued
// application frame.
//
// Heartbeat carries a ticks field purely so the decoder has a
// non-trivial body to parse (canonical JSON cannot represent an
// "empty" object in the strict sense — "{}" is valid but we prefer
// to explicitly tie every frame to a timestamp).
type Heartbeat struct {
	Type   FrameType `json:"type"`
	SentAt time.Time `json:"sent_at"`
}

// NewHeartbeat constructs a Heartbeat.
func NewHeartbeat(now time.Time) Heartbeat {
	return Heartbeat{
		Type:   FrameTypeHeartbeat,
		SentAt: now.UTC(),
	}
}

// Validate structural-checks a Heartbeat.
func (h Heartbeat) Validate() error {
	if h.Type != FrameTypeHeartbeat {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: Heartbeat.type mismatch",
			nil,
		)
	}
	if h.SentAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: Heartbeat.sent_at required",
			nil,
		)
	}
	return nil
}

// Shutdown is a graceful-close announcement. After sending a Shutdown
// frame the sender SHOULD NOT send any further frames except a final
// ErrorFrame if something goes wrong during close; the receiver
// SHOULD finish any in-flight job (CandidateOutput or JobReject) and
// then close its own half of the connection.
//
// Reason is a stable canonical code (typically "normal_close" for
// clean shutdowns, or a shared/errors Code* value when closing due to
// a detected condition).
type Shutdown struct {
	Type         FrameType `json:"type"`
	SentAt       time.Time `json:"sent_at"`
	Reason       string    `json:"reason"`
	HumanMessage string    `json:"human_message,omitempty"`
}

// CodeShutdownNormal is the canonical reason code for a graceful
// close that was not triggered by an error.
const CodeShutdownNormal = "normal_close"

// NewShutdown constructs a Shutdown frame.
func NewShutdown(now time.Time, reason, msg string) Shutdown {
	if reason == "" {
		reason = CodeShutdownNormal
	}
	return Shutdown{
		Type:         FrameTypeShutdown,
		SentAt:       now.UTC(),
		Reason:       reason,
		HumanMessage: msg,
	}
}

// Validate structural-checks a Shutdown frame.
func (s Shutdown) Validate() error {
	if s.Type != FrameTypeShutdown {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: Shutdown.type mismatch",
			nil,
		)
	}
	if s.SentAt.IsZero() {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: Shutdown.sent_at required",
			nil,
		)
	}
	if s.Reason == "" {
		return shared_errors.Structural(
			CodeProtocolViolation,
			"returnpath/transport: Shutdown.reason required",
			nil,
		)
	}
	return nil
}

// itoa is a minimal unsigned-int formatter. We avoid strconv.Itoa
// inside hot error-message paths so the transport package stays free
// of fmt/strconv imports beyond what is strictly necessary. It is
// only used in JobRequest.Validate for index-in-slice diagnostics.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
