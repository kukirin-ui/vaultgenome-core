// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_test

// Stage F.4 — End-to-end orchestrator + reassembler driver test.
//
// Phase 2 shipped the receive-side wire-integrity state machine
// (bootstrap.Orchestrator). Phase 3 shipped the receive-side
// plaintext-integrity engine (reassembly.AGDReassembler). Neither
// imports the other. Phase 4 wires them together and exercises the
// full composition against genuinely signed and AES-256-GCM-sealed
// artifacts — which is how the receive side actually operates in
// production.
//
// The integration demonstrates the two-tier integrity split pinned
// down in docs/doctrine/bootstrap-contracts.md §8.4:
//
//     ┌──────────────┐            ┌────────────────┐
//     │ Orchestrator │            │  Reassembler   │
//     │              │            │                │
//     │ Accept(msg)  │            │ Admit(msg)     │
//     │   ↓          │            │   ↓            │
//     │ wire-hash    │  == tier 1 │ Sealer.Open    │
//     │   vs         │            │ + plaintext    │  == tier 2
//     │ manifest     │            │ hash/bytesize  │
//     └──────────────┘            └────────────────┘
//         (CATCHES transit tamper)  (CATCHES release-side fraud)
//
// Tier 1 alone is insufficient: a release-side adversary who replaces
// a plaintext and re-seals/re-signs/re-pins it into the manifest
// defeats the wire-hash check but cannot forge the AGD's committed
// Merkle root without also breaking Ed25519. Tier 2 alone is
// insufficient: an in-flight tamperer would be caught only AFTER the
// audit-bound ReceivedDisclosure has been emitted, which muddies the
// evidence trail. Both tiers are required; this file pins that down
// with live cryptography.
//
// Stage G update: StateValidate → StateReady is now driven by a real
// recvvalidator.ValidationService — no stub VRID. The service appends
// RECV_VALIDATION_STARTED + RECV_VALIDATION_COMPLETED into the same
// receive-side audit chain the orchestrator writes DISCLOSURE_RECEIVED
// and RECONSTITUTION_DECIDED into. The happy path below now asserts
// the audit event count against this extended choreography.
//
// What these tests are NOT:
//   - They do NOT exercise a real TEE boundary or network transport;
//     the "release side" and "receive side" share one in-memory
//     keystore that registers the release-side signing key under the
//     same KeyID the receive side resolves. This is precisely the
//     same fixture shape as /vault/disclosure/integration_test.go.
//   - They do NOT exercise a semantic/behavioural receive-side
//     dimension — Stage G is operational-only by doctrine, see
//     /internal/recvvalidator/doc.go.

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/bootstrap"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/bootstrap_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstitution_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/reassembly"
	"github.com/vault-genome/vaultgenome-core/internal/recvvalidator"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- fixture IDs ----------------------------------------------------------

const (
	driverSessionID   = ids.SessionID("sess-f4-driver-1")
	driverManifestID  = ids.ManifestID("mani-f4-driver-1")
	driverBootstrapID = ids.BootstrapManifestID("boot-f4-driver-1")
	driverPolicy      = ids.PolicyVersion("policy-f4")
	driverFamily      = "continuity-llm"

	kidRelease   = ids.KeyID("release-auth-f4")
	kidRecv      = ids.KeyID("recv-auth-f4")
	kidAudit     = ids.KeyID("recv-audit-f4")
	kidRecipient = ids.KeyID("recipient-seal-f4")
	// Stage G: the receive-side trust authority signs the attestation.
	// In production this is distinct from the receive-side authority
	// signing the BootstrapManifest / session; in-test they share a
	// store but use different KeyIDs so a signature mixup would
	// surface.
	kidRecvTrust = ids.KeyID("recv-trust-f4")

	driverRequestID     = ids.RequestID("req-f4-driver-1")
	driverAttestationID = ids.AttestationID("att-f4-driver-1")
)

func driverClock() shared_time.Clock {
	return shared_time.NewFakeClock(time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC))
}

// driverCompSpec mirrors the Phase 3 compSpec shape but lives in an
// external test package. Kept intentionally parallel so that any future
// refactor of the Phase 3 harness can be picked up here with minimal
// churn.
type driverCompSpec struct {
	cid       ids.ComponentID
	path      string
	kind      componenttree.Kind
	plaintext []byte
}

func driverDefaultSpecs() []driverCompSpec {
	return []driverCompSpec{
		{cid: ids.ComponentID("c-cfg"), path: "config/architecture", kind: componenttree.KindConfig, plaintext: []byte("architecture-config-driver-01")},
		{cid: ids.ComponentID("c-tok"), path: "tokenizer/vocab", kind: componenttree.KindTokenizer, plaintext: []byte("TOKENIZER-VOCAB-DRIVER-ABCDEF-01")},
		{cid: ids.ComponentID("c-w0"), path: "weights/shard-00", kind: componenttree.KindTensor, plaintext: bytes.Repeat([]byte{0xA1}, 256)},
		{cid: ids.ComponentID("c-w1"), path: "weights/shard-01", kind: componenttree.KindTensor, plaintext: bytes.Repeat([]byte{0xB2}, 512)},
		{cid: ids.ComponentID("c-probe"), path: "probes/default", kind: componenttree.KindBehavioralProbe, plaintext: []byte(`{"input":"hello","expected":"hi"}`)},
	}
}

// driverHarness is the composite release+receive fixture. One store
// holds every key (release signing, receive signing, audit signing,
// recipient sealing); in production these would be in different
// physical stores, but the driver test's job is to exercise the
// composition topology, not the key-custody topology.
type driverHarness struct {
	store *keys.InMemoryStore

	// Release-side artifacts.
	agd      *genome_descriptor.GenomeDescriptor
	rjm      *reconstruction_job_manifest.ReconstructionJobManifest
	messages []*disclosure_message.DisclosureMessage
	wireH    [][]byte

	// Receive-side artifacts.
	bm    *bootstrap_manifest.BootstrapManifest
	chain chain.Chain

	// Stage G: receive-side trust-admission artifact and trusted
	// session. Both are signed by the test store under kidRecvTrust
	// and kidRecv respectively. Carried on the harness so tests can
	// mutate them (e.g. deny the attestation) to drive validator
	// refusals.
	attestation attestation_result.AttestationResult
	session     session_object.SessionObject

	// Bridge (ComponentID → Component) — both sides agree on this
	// mapping through the wire envelope's ComponentID and the AGD's
	// Path-sorted leaves.
	compMap reassembly.ComponentMap

	// Per-spec plaintexts — kept around so tests can assert that the
	// reassembled plaintexts are byte-exact.
	specs []driverCompSpec
}

func fixed32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// buildDriverHarness produces a complete, signed release-side bundle
// + a matched receive-side BootstrapManifest + the live
// AES-256-GCM-sealed DisclosureMessages.
//
// The optional mutate hook runs AFTER the release-side DisclosureMessage
// has been signed but BEFORE the wire-hash is computed. Use it to
// simulate in-flight tamper (the wire-hash will still match the
// mutated bytes, so the orchestrator won't notice) or release-side
// fraud (same caveat; the scenario is that the RELEASE side is
// lying to the AGD, not that the wire is being edited). For a genuine
// "wire tamper" scenario the mutate hook should run AFTER the
// wire-hash is computed — the test drives that directly rather than
// through this helper.
//
// By default no mutation is applied.
func buildDriverHarness(t *testing.T, specs []driverCompSpec) *driverHarness {
	t.Helper()

	store := keys.NewInMemoryStore(driverClock())

	// Register all four keys. In production the release-side and
	// receive-side stores would be disjoint; in this test both sides
	// share one store but the Purpose bindings prevent any
	// cross-purpose misuse.
	_, err := store.GenerateSigning(kidRelease, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(kidRecv, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(kidRecvTrust, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(kidAudit, keys.PurposeSigningAudit)
	require.NoError(t, err)
	require.NoError(t, store.GenerateSealing(kidRecipient))

	// ---- Release side: build the committed tree + signed AGD. -------------
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

	agd := &genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    driverFamily,
		Generation:    0,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 1_000_000,
			PrecisionBits:  16,
			ConfigHash:     fixed32(0xA1),
		},
		ComponentTreeRoot: tree.RootSlice(),
		ComponentCount:    uint32(len(specs)),
		TotalBytes:        totalBytes,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity: "producer:driver-f4",
			ProducedAt:       time.Date(2026, 4, 19, 9, 0, 0, 0, time.UTC),
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-v3",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    fixed32(0xE5),
			CanonicalScoresRoot:  fixed32(0xF6),
			ProbeCount:           256,
			MinPassingScore:      0.85,
		},
		IssuedAt:     time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC),
		SigningKeyID: kidRelease,
	}
	gid, err := agd.DeriveID()
	require.NoError(t, err)
	agd.GenomeID = gid
	require.NoError(t, agd.SignWith(store))
	require.NoError(t, agd.Validate())

	// ---- Release side: seal each component into a DisclosureMessage. ------
	issued := time.Date(2026, 4, 20, 11, 0, 0, 0, time.UTC)
	messages := make([]*disclosure_message.DisclosureMessage, 0, len(specs))
	wireH := make([][]byte, 0, len(specs))
	disclosureIDs := make([]ids.DisclosureID, 0, len(specs))
	componentIDs := make([]ids.ComponentID, 0, len(specs))
	for i, s := range specs {
		aad, err := disclosure_message.BuildRecipientAAD(
			driverSessionID, s.cid, uint32(i), driverPolicy, kidRecipient,
		)
		require.NoError(t, err)
		nonce, ct, err := store.Seal(kidRecipient, append([]byte(nil), s.plaintext...), aad)
		require.NoError(t, err)

		msg := &disclosure_message.DisclosureMessage{
			SchemaVersion:  disclosure_message.SchemaVersionCurrent,
			DisclosureID:   ids.DisclosureID("disc-f4-" + strconv.Itoa(i)),
			SessionID:      driverSessionID,
			ComponentID:    s.cid,
			PolicyVersion:  driverPolicy,
			SequenceIndex:  uint32(i),
			SealedPayload:  ct,
			Nonce:          nonce,
			RecipientKeyID: kidRecipient,
			AuthorizedAt:   issued.Add(time.Duration(i) * time.Second),
			SigningKeyID:   kidRelease,
		}
		require.NoError(t, msg.SignWith(store))
		require.NoError(t, msg.Validate())

		cb, err := msg.CanonicalBytes()
		require.NoError(t, err)
		h := crypto.SHA256Slice(cb)

		messages = append(messages, msg)
		wireH = append(wireH, h)
		disclosureIDs = append(disclosureIDs, msg.DisclosureID)
		componentIDs = append(componentIDs, msg.ComponentID)
	}

	// ---- Release side: ReconstructionJobManifest. ------------------------
	deadline := issued.Add(2 * time.Hour)
	rjm := &reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             driverManifestID,
		SessionID:              driverSessionID,
		GenomeID:               agd.GenomeID,
		PolicyVersion:          driverPolicy,
		DisclosureIDs:          append([]ids.DisclosureID(nil), disclosureIDs...),
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 1 << 24,
		RecipientKeyID:         kidRecipient,
		Deadline:               deadline,
		IssuedAt:               issued,
		SigningKeyID:           kidRelease,
		Signature:              []byte{0x01}, // signed on release side; not verified in this driver
	}

	// ---- Receive side: BootstrapManifest. --------------------------------
	bm := &bootstrap_manifest.BootstrapManifest{
		SchemaVersion:         bootstrap_manifest.SchemaVersionCurrent,
		BootstrapID:           driverBootstrapID,
		SessionID:             driverSessionID,
		ManifestID:            driverManifestID,
		GenomeID:              agd.GenomeID,
		PolicyVersion:         driverPolicy,
		ExpectedDisclosureIDs: append([]ids.DisclosureID(nil), disclosureIDs...),
		ExpectedComponentIDs:  append([]ids.ComponentID(nil), componentIDs...),
		Deadline:              deadline,
		IssuedAt:              issued,
		SigningKeyID:          kidRecv,
	}
	require.NoError(t, bm.SignWith(store))

	// ---- Receive side: Stage G pre-flight trust + session artifacts. -----
	// The validator's Now is pinned to the fake clock's 12:00:00 UTC
	// instant. Attestation issued at 11:58:00 UTC (DefaultTTL = 5 min,
	// so expires at 12:03:00 UTC — 3 min of headroom past validator
	// time). Session issued at the same instant with a generous 30-min
	// window, so it is safely active at validator time.
	attIssued := time.Date(2026, 4, 20, 11, 58, 0, 0, time.UTC)
	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: driverAttestationID,
		RequestID:     driverRequestID,
		Outcome:       attestation_result.OutcomeAllow,
		IssuedAt:      attIssued,
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  kidRecvTrust,
	}
	require.NoError(t, att.SignWith(store))

	sessIssued := attIssued
	sess := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     driverSessionID,
		RequestID:     driverRequestID,
		GenomeID:      agd.GenomeID,
		PolicyVersion: driverPolicy,
		IssuedAt:      sessIssued,
		ExpiresAt:     sessIssued.Add(30 * time.Minute),
		State:         session_object.StateActive,
		SigningKeyID:  kidRecv,
	}
	require.NoError(t, sess.SignWith(store))

	return &driverHarness{
		store:       store,
		agd:         agd,
		rjm:         rjm,
		messages:    messages,
		wireH:       wireH,
		bm:          bm,
		chain:       chain.NewInMemoryChain(),
		compMap:     compMap,
		specs:       specs,
		attestation: att,
		session:     sess,
	}
}

// newDriverValidationService builds a receive-side validator bound to
// the harness's shared audit chain (so STARTED/COMPLETED events land
// in the same ledger as DISCLOSURE_RECEIVED and RECONSTITUTION_DECIDED
// — the receive side is one audit tape).
func newDriverValidationService(t *testing.T, h *driverHarness) *recvvalidator.ValidationService {
	t.Helper()
	svc, err := recvvalidator.NewValidationService(recvvalidator.ServiceOptions{
		AuditChain:  h.chain,
		AuditSigner: h.store,
		AuditKeyID:  kidAudit,
		Clock:       driverClock(),
	})
	require.NoError(t, err)
	return svc
}

// driveValidation runs the full Stage G validator sequence using the
// harness's pre-built attestation + session. count is the number of
// disclosures the reassembler admitted (admitted=expected on the
// happy path). Returns the ValidationResult so the caller can decide
// whether to MarkValidated or MarkValidationFailed.
func driveValidation(t *testing.T, h *driverHarness, svc *recvvalidator.ValidationService, admitted int) *validation_result.ValidationResult {
	t.Helper()
	in := recvvalidator.ValidateInputs{
		OperationalInputs: recvvalidator.OperationalInputs{
			BootstrapManifest: h.bm,
			Attestation:       h.attestation,
			Session:           h.session,
			ActivePolicy:      driverPolicy,
			Coverage: recvvalidator.ReassemblyCoverage{
				Expected: len(h.bm.ExpectedDisclosureIDs),
				Admitted: admitted,
			},
			// Now is pulled from the service's clock via the
			// service's Validate() fallback; left zero here so that
			// the clock-fallback path is exercised end-to-end.
			Resolver: h.store,
		},
	}
	result, err := svc.Validate(in)
	require.NoError(t, err, "validator refusal at the service level would be a Stage G regression")
	require.NotNil(t, result)
	return result
}

// newDriverOrchestrator spins up a fully wired receive-side
// Orchestrator against h's fixtures. Separated from the harness so
// tests can mutate h's fields (e.g. corrupt a wire-hash) between
// harness build and orchestrator construction.
func newDriverOrchestrator(t *testing.T, h *driverHarness) *bootstrap.Orchestrator {
	t.Helper()
	o, err := bootstrap.NewOrchestrator(bootstrap.OrchestratorOptions{
		Manifest:            h.bm,
		JobManifest:         h.rjm,
		ExpectedWireHashes:  h.wireH,
		AuditChain:          h.chain,
		AuditSigner:         h.store,
		AuditKeyID:          kidAudit,
		RecvAuthoritySigner: h.store,
		RecvAuthorityKeyID:  kidRecv,
		Clock:               driverClock(),
	})
	require.NoError(t, err)
	return o
}

// newDriverReassembler builds the receive-side reassembler against
// h's AGD, component map, and sealer. The sealer is the same
// InMemoryStore; the recipient key is in it because the "receive
// side" has already completed the key-agreement handshake (see
// /vault/disclosure/ for the release-side seal step).
func newDriverReassembler(t *testing.T, h *driverHarness) *reassembly.AGDReassembler {
	t.Helper()
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	return r
}

// ---- happy path ----------------------------------------------------------

// TestDriver_HappyPath runs the complete end-to-end flow with real
// AES-256-GCM sealing and real Ed25519 signing:
//
//	Start → Accept×N (orchestrator wire-hash) →
//	Admit×N (reassembler payload check) →
//	Finalize (Merkle root + GenomeID round-trip) →
//	MarkReassembled → MarkValidated → Decide(Accepted=true).
//
// Asserts: every plaintext is byte-recovered, Reassembler's GenomeID
// equals AGD.GenomeID equals the ReconstitutionDecision's GenomeID,
// the audit chain verifies, and the final state is Reconstituted.
func TestDriver_HappyPath(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := newDriverOrchestrator(t, h)

	require.NoError(t, o.Start())
	require.Equal(t, bootstrap.StateIngress, o.State())

	// Tier 1: orchestrator wire-hash acceptance.
	for i, msg := range h.messages {
		rd, err := o.Accept(msg)
		require.NoErrorf(t, err, "Accept #%d", i)
		require.NotNil(t, rd)
		require.Equal(t, msg.DisclosureID, rd.DisclosureID)
		require.Equal(t, msg.ComponentID, rd.ComponentID)
		require.NotEmpty(t, rd.AuditEventID,
			"audit-event-before-record-surface: every ReceivedDisclosure must carry AuditEventID")
		require.NotEmpty(t, rd.Signature)
	}
	require.Equal(t, bootstrap.StateReassemble, o.State())

	// Tier 2: reassembler payload acceptance.
	r := newDriverReassembler(t, h)
	for i, msg := range h.messages {
		require.NoErrorf(t, r.Admit(msg), "Admit #%d", i)
	}

	result, err := r.Finalize()
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, r.IsFinalized())

	// Identity promise: the reassembled result's GenomeID equals the
	// AGD's signed GenomeID. This is what the two-tier split exists to
	// guarantee — "the bytes I just recovered hash up to the same
	// genome the release side committed to."
	require.Equal(t, h.agd.GenomeID, result.GenomeID)
	require.Equal(t, h.agd.ComponentTreeRoot, result.ComponentTreeRoot)
	require.Len(t, result.Components, len(h.specs))
	for _, s := range h.specs {
		got, ok := result.Components[s.path]
		require.Truef(t, ok, "missing recovered path %q", s.path)
		require.Equalf(t, s.plaintext, got,
			"recovered plaintext for %q diverges from committed plaintext", s.path)
	}

	// Stage G: run the receive-side validator. Six op.recv.* sub-checks,
	// all binary, all of which must pass on a clean happy path.
	require.NoError(t, o.MarkReassembled())
	require.Equal(t, bootstrap.StateValidate, o.State())

	svc := newDriverValidationService(t, h)
	vr := driveValidation(t, h, svc, len(h.messages))
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict,
		"operational-only dimension must pass on a clean reassembly")
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionOperational].Score)

	require.NoError(t, o.MarkValidated(vr.ValidationResultID))
	require.Equal(t, bootstrap.StateReady, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.True(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, dec.Reason)
	require.Equal(t, h.agd.GenomeID, dec.GenomeID,
		"ReconstitutionDecision.GenomeID must match AGD.GenomeID end-to-end")
	require.Equal(t, vr.ValidationResultID, dec.ValidationResultID,
		"decision must cite the ValidationResultID Stage G minted")
	require.Equal(t, bootstrap.StateReconstituted, o.State())

	// Audit chain consistency: N DISCLOSURE_RECEIVED + RECV_VALIDATION_STARTED +
	// RECV_VALIDATION_COMPLETED + 1 RECONSTITUTION_DECIDED.
	require.Equal(t, len(h.messages)+3, h.chain.Len(),
		"chain must carry envelope events, validator STARTED/COMPLETED, and the terminal decision")
	require.NoError(t, h.chain.Verify(h.store))

	// Stage G kinds appear in-order between the last DISCLOSURE_RECEIVED
	// and the terminal RECONSTITUTION_DECIDED.
	started, ok := h.chain.EventAt(len(h.messages))
	require.True(t, ok)
	completed, ok := h.chain.EventAt(len(h.messages) + 1)
	require.True(t, ok)
	decided, ok := h.chain.EventAt(len(h.messages) + 2)
	require.True(t, ok)
	require.Equal(t, audit_event.KindRecvValidationStarted, started.Kind)
	require.Equal(t, audit_event.KindRecvValidationCompleted, completed.Kind)
	require.Equal(t, audit_event.KindReconstitutionDecided, decided.Kind)
}

// ---- tier 1: wire tamper caught by orchestrator --------------------------

// TestDriver_WireTamper_CaughtByOrchestrator mutates the sealed
// ciphertext AFTER the release-side signature is computed AND the
// wire-hash is committed. The orchestrator's SHA-256 of the
// arriving canonical bytes no longer matches its committed expected
// hash — refusal fires BEFORE the reassembler is even touched.
//
// This is the "in-flight MITM" scenario: any byte flip on the wire
// is caught by tier 1. The reassembler's plaintext check never runs.
func TestDriver_WireTamper_CaughtByOrchestrator(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := newDriverOrchestrator(t, h)
	require.NoError(t, o.Start())

	// Accept the first message cleanly so we are genuinely
	// mid-stream when the tamper is introduced — this ensures the
	// orchestrator's slot-tracking and audit-chain state are
	// fully live when refusal fires.
	rd, err := o.Accept(h.messages[0])
	require.NoError(t, err)
	require.NotNil(t, rd)

	// Flip one byte in msg[1]'s sealed payload after signing. The
	// canonical-cover hash now diverges from what the manifest
	// committed.
	tampered := *h.messages[1] // shallow copy; SealedPayload is reassigned
	tampered.SealedPayload = append([]byte(nil), h.messages[1].SealedPayload...)
	tampered.SealedPayload[0] ^= 0xFF

	r := newDriverReassembler(t, h)
	// Record the reassembler's state before feeding anything to it.
	require.False(t, r.IsFinalized())

	_, err = o.Accept(&tampered)
	require.Error(t, err, "wire-tamper must be caught at tier 1")
	require.Equal(t, bootstrap.CodeAcceptWireHashMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"wire-hash mismatch is an Integrity signal per doctrine §8.4")
	require.Equal(t, bootstrap.StateRejected, o.State())

	// Tier 2 was never reached: if we had fed the tampered message to
	// the reassembler it would have failed on AAD/GCM integrity, but
	// the orchestrator stopped it sooner. Prove the reassembler was
	// untouched:
	require.False(t, r.IsFinalized())

	// The orchestrator can still emit a signed rejection decision.
	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
	require.NotEmpty(t, dec.AuditEventID)
}

// ---- tier 2: release-side plaintext fraud caught by reassembler ----------

// TestDriver_PayloadFraud_CaughtByReassembler is the doctrine §8.4
// "key" test: the release-side adversary swaps one component's
// plaintext BUT keeps the AGD unchanged. Because they control the
// release side's signer and manifest, they re-seal the fraudulent
// plaintext under the same AAD, re-sign the DisclosureMessage, and
// re-pin the new wire-hash into both manifests. The orchestrator's
// tier-1 check passes — from its vantage point every envelope is
// authentic, in-order, and the committed expected wire-hash matches
// the arriving canonical bytes exactly.
//
// But the AGD's Merkle root commits to the ORIGINAL plaintext's hash.
// The reassembler opens the sealed envelope, computes the plaintext's
// SHA-256, compares to the AGD's committed leaf hash, and refuses
// with CodeComponentHashMismatch (Integrity). That refusal is the
// doctrinal reason the reassembler exists: tier 1 alone does not
// bind the wire to the genome; only the AGD does.
func TestDriver_PayloadFraud_CaughtByReassembler(t *testing.T) {
	t.Parallel()
	// Build the harness in the usual way — AGD commits to the
	// ORIGINAL plaintexts.
	h := buildDriverHarness(t, driverDefaultSpecs())

	// Pick target slot (index 2, a weight-shard). Produce a fraudulent
	// plaintext of the SAME byte-length so the ByteSize commitment in
	// the AGD still matches; only the hash will disagree. (If we
	// changed the length too, the reassembler's byte-size check would
	// fire first — same classification, less informative.)
	target := 2
	fraudulentPlaintext := bytes.Repeat([]byte{0x5A}, int(h.compMap[h.specs[target].cid].ByteSize))
	require.NotEqual(t, h.specs[target].plaintext, fraudulentPlaintext,
		"sanity: fraudulent plaintext must actually differ")

	// Re-seal the fraudulent plaintext under the SAME AAD the release
	// side would have used (same SessionID, ComponentID, SequenceIndex,
	// PolicyVersion, RecipientKeyID) — this is the adversary operating
	// INSIDE the release side's signing scope.
	aad, err := disclosure_message.BuildRecipientAAD(
		driverSessionID,
		h.specs[target].cid,
		uint32(target),
		driverPolicy,
		kidRecipient,
	)
	require.NoError(t, err)
	nonce, ct, err := h.store.Seal(kidRecipient, fraudulentPlaintext, aad)
	require.NoError(t, err)

	fraudMsg := &disclosure_message.DisclosureMessage{
		SchemaVersion:  disclosure_message.SchemaVersionCurrent,
		DisclosureID:   h.messages[target].DisclosureID,
		SessionID:      driverSessionID,
		ComponentID:    h.specs[target].cid,
		PolicyVersion:  driverPolicy,
		SequenceIndex:  uint32(target),
		SealedPayload:  ct,
		Nonce:          nonce,
		RecipientKeyID: kidRecipient,
		AuthorizedAt:   h.messages[target].AuthorizedAt,
		SigningKeyID:   kidRelease,
	}
	require.NoError(t, fraudMsg.SignWith(h.store))
	require.NoError(t, fraudMsg.Validate())

	// Release-side adversary updates BOTH manifests' committed wire
	// data to match the fraudulent envelope. This is the doctrinal
	// assumption: the adversary has release-side signing authority for
	// the manifest wire metadata but CANNOT forge the AGD's Merkle
	// root (see §8.4: Ed25519 on the AGD is what closes the loop).
	h.messages[target] = fraudMsg
	cb, err := fraudMsg.CanonicalBytes()
	require.NoError(t, err)
	h.wireH[target] = crypto.SHA256Slice(cb)

	o := newDriverOrchestrator(t, h)
	r := newDriverReassembler(t, h)
	require.NoError(t, o.Start())

	// Tier 1 passes end-to-end — tier 1 has no way to know the
	// plaintext is fraudulent.
	for i, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoErrorf(t, err, "Accept #%d must pass — tier 1 sees no tamper", i)
	}
	require.Equal(t, bootstrap.StateReassemble, o.State(),
		"all wire-hashes matched; orchestrator advanced to reassemble")

	// Tier 2: the reassembler admits all OTHER messages, then refuses
	// the fraudulent slot with CodeComponentHashMismatch. Classification
	// is Integrity: the bytes we just unsealed are authentic as an
	// envelope but do not belong to this AGD's committed genome.
	for i, msg := range h.messages {
		err := r.Admit(msg)
		if i == target {
			require.Errorf(t, err, "Admit #%d must catch the fraud", i)
			require.Equal(t, reassembly.CodeComponentHashMismatch, shared_errors.CodeOf(err))
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
				"plaintext-hash mismatch is an Integrity signal")
			break
		}
		require.NoErrorf(t, err, "Admit #%d must pass (not the fraud slot)", i)
	}

	// Finalize would fail anyway on coverage, but the driver's
	// composition is: on any reassembly failure (Admit or Finalize),
	// call MarkReassemblyFailed and Decide to emit the signed
	// rejection artifact. That's the doctrinal exit for tier-2
	// refusals.
	require.NoError(t, o.MarkReassemblyFailed())
	require.Equal(t, bootstrap.StateRejected, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted,
		"tier-2 refusal produces a signed Accepted=false ReconstitutionDecision")
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
	require.NotEmpty(t, dec.AuditEventID)
}

// ---- reassembler coverage failure drives orchestrator rejection ----------

// TestDriver_CoverageIncomplete_DrivesRejection simulates the
// scenario where the orchestrator reports all wire-hashes healthy
// (tier 1 clean) but the receive-side driver, for whatever reason —
// a silent drop, a local policy refusal — only feeds a subset of the
// accepted envelopes to the reassembler. Finalize refuses with
// CodeCoverageIncomplete; the driver translates that into
// MarkReassemblyFailed → signed rejection.
//
// This exercises the fact that tier-1 acceptance is necessary but
// NOT sufficient: the driver is ultimately responsible for ensuring
// tier-2 is run over the same set of envelopes tier 1 accepted.
func TestDriver_CoverageIncomplete_DrivesRejection(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := newDriverOrchestrator(t, h)
	r := newDriverReassembler(t, h)

	require.NoError(t, o.Start())
	for _, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoError(t, err)
	}
	require.Equal(t, bootstrap.StateReassemble, o.State())

	// Admit only the first two — simulate dropped local messages.
	for i := 0; i < 2; i++ {
		require.NoError(t, r.Admit(h.messages[i]))
	}

	_, err := r.Finalize()
	require.Error(t, err)
	require.Equal(t, reassembly.CodeCoverageIncomplete, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err),
		"coverage incomplete is Structural — we never even looked at the missing bytes")

	// Translate tier-2 refusal into the orchestrator's rejection path.
	require.NoError(t, o.MarkReassemblyFailed())
	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
}

// ---- composition idempotence after terminal decision ---------------------

// TestDriver_TerminalIdempotence asserts that once the orchestrator
// has emitted its signed ReconstitutionDecision, every subsequent
// action from either side is refused cleanly:
//
//  1. Orchestrator.Decide → CodeAlreadyDecided
//  2. Orchestrator.Accept → CodeAcceptWrongState (terminal is not Ingress)
//  3. Reassembler.Admit   → CodeReassemblerFinalized
//  4. Reassembler.Finalize → returns the SAME result verbatim
//
// This is the composite single-shot discipline: neither engine can
// be driven past its terminal by either side poking it again.
func TestDriver_TerminalIdempotence(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := newDriverOrchestrator(t, h)
	r := newDriverReassembler(t, h)

	require.NoError(t, o.Start())
	for _, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoError(t, err)
		require.NoError(t, r.Admit(msg))
	}
	firstResult, err := r.Finalize()
	require.NoError(t, err)
	require.NotNil(t, firstResult)

	require.NoError(t, o.MarkReassembled())
	svc := newDriverValidationService(t, h)
	vr := driveValidation(t, h, svc, len(h.messages))
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict)
	require.NoError(t, o.MarkValidated(vr.ValidationResultID))
	firstDec, err := o.Decide()
	require.NoError(t, err)
	require.True(t, firstDec.Accepted)

	// (1) Orchestrator.Decide refuses.
	_, err = o.Decide()
	require.Error(t, err)
	require.Equal(t, bootstrap.CodeAlreadyDecided, shared_errors.CodeOf(err))

	// (2) Orchestrator.Accept refuses from any terminal state.
	_, err = o.Accept(h.messages[0])
	require.Error(t, err)
	require.Equal(t, bootstrap.CodeAcceptWrongState, shared_errors.CodeOf(err))

	// (3) Reassembler.Admit refuses.
	err = r.Admit(h.messages[0])
	require.Error(t, err)
	require.Equal(t, reassembly.CodeReassemblerFinalized, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))

	// (4) Reassembler.Finalize returns the SAME pointer (idempotent).
	secondResult, err := r.Finalize()
	require.NoError(t, err)
	require.Same(t, firstResult, secondResult,
		"second Finalize must return the same pointer — no re-derivation, no replay")
}

// ---- identity binding cross-check ----------------------------------------

// TestDriver_IdentityBindsEndToEnd asserts the doctrinal identity
// promise: across the signed release-side AGD, the accepted
// receive-side ReceivedDisclosures, the reassembled result, and the
// terminal ReconstitutionDecision, the GenomeID is a single
// immutable value. If ANY of these four surfaces drifted, the
// receive side would have accepted a genome whose identity is
// ambiguous — which is exactly the scenario invariant #1 + R-14 +
// §8.4 exist to prevent.
func TestDriver_IdentityBindsEndToEnd(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := newDriverOrchestrator(t, h)
	r := newDriverReassembler(t, h)

	// Pre-condition: the AGD's GenomeID must equal the derivation of
	// its own canonical bytes. This is the R-14 content-address rule
	// and is already verified by agd.Validate(); we re-run it here so
	// the identity chain is inspectable from the test.
	derived, err := h.agd.DeriveID()
	require.NoError(t, err)
	require.Equal(t, h.agd.GenomeID, derived,
		"R-14: GenomeID is content-addressed to the AGD's own bytes")

	// Manifest-level identity (both manifests carry GenomeID).
	require.Equal(t, h.agd.GenomeID, h.bm.GenomeID)
	require.Equal(t, h.agd.GenomeID, h.rjm.GenomeID)

	// Drive the pipeline.
	require.NoError(t, o.Start())
	for _, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoError(t, err)
		require.NoError(t, r.Admit(msg))
	}

	res, err := r.Finalize()
	require.NoError(t, err)
	require.Equal(t, h.agd.GenomeID, res.GenomeID,
		"reassembled result must name the same genome")

	require.NoError(t, o.MarkReassembled())
	svc := newDriverValidationService(t, h)
	vr := driveValidation(t, h, svc, len(h.messages))
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict,
		"a clean receive-side run must not trip any op.recv.* sub-check")
	require.NoError(t, o.MarkValidated(vr.ValidationResultID))
	dec, err := o.Decide()
	require.NoError(t, err)
	require.Equal(t, h.agd.GenomeID, dec.GenomeID,
		"ReconstitutionDecision.GenomeID is the fourth and terminal binding")

	// Every signed ReceivedDisclosure was emitted against the same
	// BootstrapManifest; each carries BootstrapID (not GenomeID) to
	// anchor it to the receive-side flow. We cross-check that
	// anchoring here to close the transitive binding:
	//   BootstrapID → BootstrapManifest.GenomeID → AGD.GenomeID.
	for _, rd := range o.Received() {
		require.Equal(t, h.bm.BootstrapID, rd.BootstrapID)
	}
}

// ---- Stage G: receive-side validator end-to-end ---------------------------

// TestDriver_ReceiveValidation_OperationalVeto is the doctrinal
// counterpart of the release-side TestInvariant_06: any failing
// op.recv.* sub-check MUST force OverallVerdict=fail and drive the
// orchestrator through MarkValidationFailed → StateRejected →
// signed rejection decision.
//
// Scenario: the reassembly succeeds end-to-end (tier 1 + tier 2
// clean), but the Orchestrator's receive-side trust-admission
// artifact turns out to be a DENY when the validator inspects it.
// Under doctrine, a deny MUST veto the decision even though the
// bytes have been fully recovered. The signed rejection carries
// Reason=validation_failed and cites the ValidationResultID Stage G
// minted, so an auditor can trace the verdict back to its audit
// anchors.
func TestDriver_ReceiveValidation_OperationalVeto(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())

	// Mutate the harness's attestation: DENY instead of ALLOW, and
	// re-sign so the signature still verifies — the validator's
	// CheckRecvAttestationValid MUST still refuse on outcome alone.
	h.attestation.Outcome = attestation_result.OutcomeDeny
	h.attestation.Reason = "recv.trust_denied"
	require.NoError(t, h.attestation.SignWith(h.store))

	o := newDriverOrchestrator(t, h)
	r := newDriverReassembler(t, h)

	require.NoError(t, o.Start())
	for _, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoError(t, err)
		require.NoError(t, r.Admit(msg))
	}
	_, err := r.Finalize()
	require.NoError(t, err,
		"reassembly should succeed — the tamper is at the trust-admission layer, not the bytes")
	require.NoError(t, o.MarkReassembled())

	// Run Stage G. Verdict must be Fail.
	svc := newDriverValidationService(t, h)
	vr := driveValidation(t, h, svc, len(h.messages))
	require.Equal(t, validation_result.VerdictFail, vr.OverallVerdict,
		"deny attestation MUST force OverallVerdict=fail per Stage G doctrine")
	opDim := vr.Dimensions[validation_result.DimensionOperational]
	require.Equal(t, validation_result.VerdictFail, opDim.Verdict)
	codes := map[string]bool{}
	for _, f := range opDim.Details {
		codes[f.Code] = true
	}
	require.True(t, codes[recvvalidator.CodeRecvAttestationValid],
		"the failing sub-check code must be surfaced to auditors")

	// Drive the orchestrator's rejection path.
	require.NoError(t, o.MarkValidationFailed(vr.ValidationResultID))
	require.Equal(t, bootstrap.StateRejected, o.State())

	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonValidationFailed, dec.Reason)
	require.Equal(t, vr.ValidationResultID, dec.ValidationResultID,
		"the signed rejection must cite the Stage G ValidationResultID")
	require.NotEmpty(t, dec.AuditEventID)

	// Audit chain: N DISCLOSURE_RECEIVED + STARTED + COMPLETED +
	// RECONSTITUTION_DECIDED. Even the refusal path produces the full
	// Stage G audit pair so auditors see precisely WHY the verdict
	// was fail.
	require.Equal(t, len(h.messages)+3, h.chain.Len())
	require.NoError(t, h.chain.Verify(h.store))
}

// TestDriver_ReceiveValidation_MirrorAggregation asserts that the
// receive-side aggregation rule mirrors the release-side §5 rule
// FOR the operational dimension:
//
//   - operational=Fail always overrides Pass on any other dimension.
//   - operational=Pass + no other dimensions yields Pass (Stage G today).
//
// The future two-dimension / three-dimension receive-side expansion
// will slot new dimensions in beside operational without changing
// the orchestrator driver — this test encodes that contract.
func TestDriver_ReceiveValidation_MirrorAggregation(t *testing.T) {
	t.Parallel()
	h := buildDriverHarness(t, driverDefaultSpecs())
	o := newDriverOrchestrator(t, h)
	r := newDriverReassembler(t, h)

	require.NoError(t, o.Start())
	for _, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoError(t, err)
		require.NoError(t, r.Admit(msg))
	}
	_, err := r.Finalize()
	require.NoError(t, err)
	require.NoError(t, o.MarkReassembled())

	svc := newDriverValidationService(t, h)
	vr := driveValidation(t, h, svc, len(h.messages))

	// Pass path — single operational dimension, Pass.
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict)
	require.Contains(t, vr.Dimensions, validation_result.DimensionOperational)
	require.Equal(t, validation_result.VerdictPass,
		vr.Dimensions[validation_result.DimensionOperational].Verdict)
	require.Equal(t, 1.0,
		vr.Dimensions[validation_result.DimensionOperational].Score)
	require.Empty(t, vr.Dimensions[validation_result.DimensionOperational].Details)

	// Cross-check the service's aggregation against the package's
	// pure Aggregate function: they MUST agree on every input. This
	// is the receive-side mirror of the release-side
	// referenceAggregate invariant pinned in doctrine/invariants_test.go.
	want := recvvalidator.Aggregate(vr.Dimensions)
	require.Equal(t, want, vr.OverallVerdict,
		"ValidationResult.OverallVerdict must equal recvvalidator.Aggregate(dims)")

	// Drive through to a signed acceptance.
	require.NoError(t, o.MarkValidated(vr.ValidationResultID))
	dec, err := o.Decide()
	require.NoError(t, err)
	require.True(t, dec.Accepted)
	require.Equal(t, vr.ValidationResultID, dec.ValidationResultID)
}
