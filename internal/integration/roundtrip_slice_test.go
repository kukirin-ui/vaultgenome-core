// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

// Stage F.5 — Round-trip integration slice.
//
// The package-local vertical_slice_test.go already exercises the
// release-side nine-stage flow (Intake → … → ReleaseDecision). This
// file is its receive-side counterpart: it drives the full bootstrap
// composition end-to-end under real cryptography and narrates every
// boundary via t.Logf, so `go test -v ./internal/integration/...`
// emits a readable demo trace.
//
// Topology:
//
//	┌─────────────────┐     DisclosureMessage stream     ┌──────────────────┐
//	│  Release side   │ ───────────────────────────────→ │  Receive side    │
//	│  StagedIssuer   │ + signed BootstrapManifest       │  Orchestrator    │
//	│  + signed AGD   │                                  │  + AGDReassembler│
//	└─────────────────┘                                  └──────────────────┘
//	         │                                                   │
//	         │ tier 1 wire-hash commitment                       │ tier 2 plaintext
//	         └───────── canonical envelope hash ─────────────────┤ hash + byte-size
//	                                                             │ + Merkle root
//	                                                             │ + GenomeID round-trip
//	                                                             ▼
//	                                              signed ReconstitutionDecision
//
// Three tests, in demo-relevant order:
//
//  1. TestRoundtripSlice_HappyPath — narrated full round trip,
//     six receive-side stages (including Stage G, the receive-side
//     validator), audit chain cross-verified on both ends.
//     This is what `make demo` tells the operator's eyes.
//
//  2. TestRoundtripSlice_Tier1_WireTamper — demonstrates that a single
//     byte flipped on the wire (post-signature) is caught at tier 1 by
//     the Orchestrator's wire-hash check before the Reassembler is
//     even touched.
//
//  3. TestRoundtripSlice_Tier2_PayloadFraud — demonstrates the
//     doctrine §8.4 acid test: a release-side adversary who forges
//     same-byte-length plaintext, re-seals it under the correct AAD,
//     re-signs the envelope, AND re-pins the wire-hash defeats tier 1
//     but is caught at tier 2 by the Reassembler's plaintext-hash
//     check against the AGD's signed Merkle leaf. Tier 2 is what
//     binds the wire to the genome.
//
// Stage G update: the happy-path narration now runs a real
// recvvalidator.ValidationService between MarkReassembled and
// MarkValidated, so the narration trace surfaces the receive-side
// validator's STARTED/COMPLETED audit events inline with the rest of
// the receive-side ledger. No stub VRIDs.
//
// The deeper adversarial surface area (terminal idempotence, coverage
// incomplete, identity binding across five observation points, Stage G
// operational veto) lives in /internal/bootstrap/driver_integration_test.go.
// This file carries only the scenarios whose story is told in the
// narrated demo.

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
	rtSessionID   = ids.SessionID("sess-f5-roundtrip-1")
	rtManifestID  = ids.ManifestID("mani-f5-roundtrip-1")
	rtBootstrapID = ids.BootstrapManifestID("boot-f5-roundtrip-1")
	rtPolicy      = ids.PolicyVersion("policy-f5")
	rtFamily      = "continuity-llm"

	rtKIDRelease   = ids.KeyID("release-auth-f5")
	rtKIDRecv      = ids.KeyID("recv-auth-f5")
	rtKIDAudit     = ids.KeyID("recv-audit-f5")
	rtKIDRecipient = ids.KeyID("recipient-seal-f5")
	// Stage G — receive-side trust authority. Distinct from rtKIDRecv
	// so that a signature mix-up between the trust (attestation) and
	// authority (BootstrapManifest/session) signers would surface as
	// a validator refusal rather than silently verifying.
	rtKIDRecvTrust = ids.KeyID("recv-trust-f5")

	rtRequestID     = ids.RequestID("req-f5-roundtrip-1")
	rtAttestationID = ids.AttestationID("att-f5-roundtrip-1")
)

func rtClock() shared_time.Clock {
	return shared_time.NewFakeClock(time.Date(2026, 4, 21, 9, 0, 0, 0, time.UTC))
}

// rtCompSpec is a plaintext component awaiting commitment into the AGD.
type rtCompSpec struct {
	cid       ids.ComponentID
	path      string
	kind      componenttree.Kind
	plaintext []byte
}

// rtDefaultSpecs — five components that together form a plausible
// "minimum viable transformer genome": one config blob, one tokenizer,
// two weight shards, one behavioral probe. Small enough to fit on the
// console; structurally identical to a real AGD.
func rtDefaultSpecs() []rtCompSpec {
	return []rtCompSpec{
		{cid: ids.ComponentID("c-cfg"), path: "config/architecture", kind: componenttree.KindConfig, plaintext: []byte("architecture-config-rt-01")},
		{cid: ids.ComponentID("c-tok"), path: "tokenizer/vocab", kind: componenttree.KindTokenizer, plaintext: []byte("TOKENIZER-VOCAB-RT-ABCDEF-01")},
		{cid: ids.ComponentID("c-w0"), path: "weights/shard-00", kind: componenttree.KindTensor, plaintext: bytes.Repeat([]byte{0xC3}, 256)},
		{cid: ids.ComponentID("c-w1"), path: "weights/shard-01", kind: componenttree.KindTensor, plaintext: bytes.Repeat([]byte{0xD4}, 512)},
		{cid: ids.ComponentID("c-probe"), path: "probes/default", kind: componenttree.KindBehavioralProbe, plaintext: []byte(`{"input":"hello","expected":"hi"}`)},
	}
}

// rtHarness holds every signed/sealed artifact produced by the release
// side plus the receive-side wiring (manifest + audit chain +
// component map).
type rtHarness struct {
	store *keys.InMemoryStore

	// Release side.
	agd      *genome_descriptor.GenomeDescriptor
	rjm      *reconstruction_job_manifest.ReconstructionJobManifest
	messages []*disclosure_message.DisclosureMessage
	wireH    [][]byte

	// Receive side.
	bm    *bootstrap_manifest.BootstrapManifest
	chain chain.Chain

	// Stage G — receive-side trust-admission artifact + trusted session.
	// Both are signed inside buildRoundtripHarness under rtKIDRecvTrust
	// and rtKIDRecv respectively, using timestamps consistent with the
	// rtClock's 2026-04-21 09:00:00 UTC fake instant.
	attestation attestation_result.AttestationResult
	session     session_object.SessionObject

	compMap reassembly.ComponentMap
	specs   []rtCompSpec
}

func rtFixed32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// buildRoundtripHarness produces the full release-side bundle and a
// matched receive-side BootstrapManifest. Real Ed25519 signing on the
// AGD, every DisclosureMessage envelope, and the BootstrapManifest;
// real AES-256-GCM sealing with the shared 5-field AAD. No placeholders
// except the ReconstructionJobManifest's signature (release-side only;
// not verified on the receive side beyond its own validator contract).
func buildRoundtripHarness(t *testing.T, specs []rtCompSpec) *rtHarness {
	t.Helper()

	store := keys.NewInMemoryStore(rtClock())

	_, err := store.GenerateSigning(rtKIDRelease, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(rtKIDRecv, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(rtKIDRecvTrust, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(rtKIDAudit, keys.PurposeSigningAudit)
	require.NoError(t, err)
	require.NoError(t, store.GenerateSealing(rtKIDRecipient))

	// Committed tree + signed AGD.
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
		FamilyName:    rtFamily,
		Generation:    0,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-decoder",
			ParameterCount: 1_000_000,
			PrecisionBits:  16,
			ConfigHash:     rtFixed32(0xA2),
		},
		ComponentTreeRoot: tree.RootSlice(),
		ComponentCount:    uint32(len(specs)),
		TotalBytes:        totalBytes,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity: "producer:roundtrip-f5",
			ProducedAt:       time.Date(2026, 4, 20, 9, 0, 0, 0, time.UTC),
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-v3",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    rtFixed32(0xE6),
			CanonicalScoresRoot:  rtFixed32(0xF7),
			ProbeCount:           256,
			MinPassingScore:      0.85,
		},
		IssuedAt:     time.Date(2026, 4, 21, 8, 0, 0, 0, time.UTC),
		SigningKeyID: rtKIDRelease,
	}
	gid, err := agd.DeriveID()
	require.NoError(t, err)
	agd.GenomeID = gid
	require.NoError(t, agd.SignWith(store))
	require.NoError(t, agd.Validate())

	// Seal each plaintext into a DisclosureMessage.
	issued := time.Date(2026, 4, 21, 8, 30, 0, 0, time.UTC)
	messages := make([]*disclosure_message.DisclosureMessage, 0, len(specs))
	wireH := make([][]byte, 0, len(specs))
	disclosureIDs := make([]ids.DisclosureID, 0, len(specs))
	componentIDs := make([]ids.ComponentID, 0, len(specs))
	for i, s := range specs {
		aad, err := disclosure_message.BuildRecipientAAD(
			rtSessionID, s.cid, uint32(i), rtPolicy, rtKIDRecipient,
		)
		require.NoError(t, err)
		nonce, ct, err := store.Seal(rtKIDRecipient, append([]byte(nil), s.plaintext...), aad)
		require.NoError(t, err)

		msg := &disclosure_message.DisclosureMessage{
			SchemaVersion:  disclosure_message.SchemaVersionCurrent,
			DisclosureID:   ids.DisclosureID("disc-f5-" + strconv.Itoa(i)),
			SessionID:      rtSessionID,
			ComponentID:    s.cid,
			PolicyVersion:  rtPolicy,
			SequenceIndex:  uint32(i),
			SealedPayload:  ct,
			Nonce:          nonce,
			RecipientKeyID: rtKIDRecipient,
			AuthorizedAt:   issued.Add(time.Duration(i) * time.Second),
			SigningKeyID:   rtKIDRelease,
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

	deadline := issued.Add(2 * time.Hour)
	rjm := &reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             rtManifestID,
		SessionID:              rtSessionID,
		GenomeID:               agd.GenomeID,
		PolicyVersion:          rtPolicy,
		DisclosureIDs:          append([]ids.DisclosureID(nil), disclosureIDs...),
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: 1 << 24,
		RecipientKeyID:         rtKIDRecipient,
		Deadline:               deadline,
		IssuedAt:               issued,
		SigningKeyID:           rtKIDRelease,
		Signature:              []byte{0x01},
	}

	bm := &bootstrap_manifest.BootstrapManifest{
		SchemaVersion:         bootstrap_manifest.SchemaVersionCurrent,
		BootstrapID:           rtBootstrapID,
		SessionID:             rtSessionID,
		ManifestID:            rtManifestID,
		GenomeID:              agd.GenomeID,
		PolicyVersion:         rtPolicy,
		ExpectedDisclosureIDs: append([]ids.DisclosureID(nil), disclosureIDs...),
		ExpectedComponentIDs:  append([]ids.ComponentID(nil), componentIDs...),
		Deadline:              deadline,
		IssuedAt:              issued,
		SigningKeyID:          rtKIDRecv,
	}
	require.NoError(t, bm.SignWith(store))

	// ---- Receive side: Stage G pre-flight trust + session artifacts. -----
	// rtClock is pinned to 2026-04-21 09:00:00 UTC. Attestation issued at
	// 08:58:00 UTC with DefaultTTL (5 min) so it remains within-TTL at
	// validator time with ~3 min of headroom. Session issued the same
	// instant with a 30-minute window so it is safely active.
	attIssued := time.Date(2026, 4, 21, 8, 58, 0, 0, time.UTC)
	att := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: rtAttestationID,
		RequestID:     rtRequestID,
		Outcome:       attestation_result.OutcomeAllow,
		IssuedAt:      attIssued,
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  rtKIDRecvTrust,
	}
	require.NoError(t, att.SignWith(store))

	sess := session_object.SessionObject{
		SchemaVersion: session_object.SchemaVersionCurrent,
		SessionID:     rtSessionID,
		RequestID:     rtRequestID,
		GenomeID:      agd.GenomeID,
		PolicyVersion: rtPolicy,
		IssuedAt:      attIssued,
		ExpiresAt:     attIssued.Add(30 * time.Minute),
		State:         session_object.StateActive,
		SigningKeyID:  rtKIDRecv,
	}
	require.NoError(t, sess.SignWith(store))

	return &rtHarness{
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

func rtNewOrchestrator(t *testing.T, h *rtHarness) *bootstrap.Orchestrator {
	t.Helper()
	o, err := bootstrap.NewOrchestrator(bootstrap.OrchestratorOptions{
		Manifest:            h.bm,
		JobManifest:         h.rjm,
		ExpectedWireHashes:  h.wireH,
		AuditChain:          h.chain,
		AuditSigner:         h.store,
		AuditKeyID:          rtKIDAudit,
		RecvAuthoritySigner: h.store,
		RecvAuthorityKeyID:  rtKIDRecv,
		Clock:               rtClock(),
	})
	require.NoError(t, err)
	return o
}

func rtNewReassembler(t *testing.T, h *rtHarness) *reassembly.AGDReassembler {
	t.Helper()
	r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
	require.NoError(t, err)
	return r
}

// rtNewValidationService builds a receive-side Stage G validator that
// writes its STARTED/COMPLETED audit events into the SAME audit chain
// the orchestrator writes DISCLOSURE_RECEIVED and
// RECONSTITUTION_DECIDED into — one receive-side ledger, per doctrine.
func rtNewValidationService(t *testing.T, h *rtHarness) *recvvalidator.ValidationService {
	t.Helper()
	svc, err := recvvalidator.NewValidationService(recvvalidator.ServiceOptions{
		AuditChain:  h.chain,
		AuditSigner: h.store,
		AuditKeyID:  rtKIDAudit,
		Clock:       rtClock(),
	})
	require.NoError(t, err)
	return svc
}

// rtDriveValidation runs the six op.recv.* sub-checks over the
// harness's attestation + session + bootstrap manifest. admitted is
// the count of envelopes the reassembler accepted (= len(h.messages)
// on the happy path). Leaves OperationalInputs.Now zero so the
// service's Clock.Now() fallback is the one observed by all sub-checks.
func rtDriveValidation(t *testing.T, h *rtHarness, svc *recvvalidator.ValidationService, admitted int) *validation_result.ValidationResult {
	t.Helper()
	in := recvvalidator.ValidateInputs{
		OperationalInputs: recvvalidator.OperationalInputs{
			BootstrapManifest: h.bm,
			Attestation:       h.attestation,
			Session:           h.session,
			ActivePolicy:      rtPolicy,
			Coverage: recvvalidator.ReassemblyCoverage{
				Expected: len(h.bm.ExpectedDisclosureIDs),
				Admitted: admitted,
			},
			Resolver: h.store,
		},
	}
	vr, err := svc.Validate(in)
	require.NoError(t, err, "Stage G service-level refusal would be a regression")
	require.NotNil(t, vr)
	return vr
}

// ---- narration ----------------------------------------------------------

// narrate prints a numbered stage marker. Output is deliberately plain
// ASCII so the demo script's colorizer can wrap it without collision.
func narrate(t *testing.T, stage, line string) {
	t.Helper()
	t.Logf("  [%s] %s", stage, line)
}

// ---- act II stage 1/6: happy-path round trip ------------------------------

// TestRoundtripSlice_HappyPath is the canonical narrated round trip.
// Under `go test -v` the t.Logf calls print one line per receive-side
// stage, producing a readable trace that mirrors the demo script's
// narration exactly.
//
// Seven receive-side stages:
//
//	R.1    BootstrapManifest + AGD signed on release side.
//	R.2    Receive-side Orchestrator.Start (pre-flight agreement + signatures).
//	R.3    Accept loop — tier-1 wire-hash commitment per envelope.
//	R.4    Reassembler.Admit loop — AES-256-GCM open + tier-2 plaintext checks.
//	R.5    Reassembler.Finalize — RFC 6962 Merkle + GenomeID round-trip.
//	R.5.5  Stage G — receive-side validator (six op.recv.* sub-checks,
//	       STARTED + COMPLETED audit events before MarkValidated).
//	R.6    Orchestrator.Decide — signed ReconstitutionDecision.
func TestRoundtripSlice_HappyPath(t *testing.T) {
	t.Parallel()
	narrate(t, "R.0", "Building the release-side bundle: signed AGD, sealed disclosures, matched manifests.")
	h := buildRoundtripHarness(t, rtDefaultSpecs())
	narrate(t, "R.0", "  AGD GenomeID:         "+string(h.agd.GenomeID))
	narrate(t, "R.0", "  BootstrapManifest ID: "+string(h.bm.BootstrapID))
	narrate(t, "R.0", "  Disclosures sealed:   "+strconv.Itoa(len(h.messages)))

	narrate(t, "R.1", "Instantiating the receive-side Orchestrator against the signed BootstrapManifest.")
	o := rtNewOrchestrator(t, h)

	narrate(t, "R.2", "Orchestrator.Start — verifying AGD signature, BootstrapManifest signature, cross-manifest agreement.")
	require.NoError(t, o.Start())
	require.Equal(t, bootstrap.StateIngress, o.State())
	narrate(t, "R.2", "  Start complete; state = "+string(o.State())+"; awaiting DisclosureMessage arrivals.")

	narrate(t, "R.3", "Accept loop — tier 1 wire-hash check per envelope, audit-event-before-record-surface per Accept.")
	for i, msg := range h.messages {
		rd, err := o.Accept(msg)
		require.NoErrorf(t, err, "Accept #%d", i)
		require.NotEmpty(t, rd.AuditEventID,
			"invariant #8 mirror: every ReceivedDisclosure must carry an AuditEventID")
		require.Equal(t, h.bm.BootstrapID, rd.BootstrapID)
		narrate(t, "R.3", "  Accept #"+strconv.Itoa(i)+" ok — DisclosureID="+string(rd.DisclosureID)+"  AuditEventID="+string(rd.AuditEventID))
	}
	require.Equal(t, bootstrap.StateReassemble, o.State())
	narrate(t, "R.3", "  All envelopes accepted; state = "+string(o.State())+"; tier 1 complete.")

	narrate(t, "R.4", "Reassembler.Admit loop — AES-256-GCM open under the committed AAD, tier-2 plaintext hash + byte-size.")
	r := rtNewReassembler(t, h)
	for i, msg := range h.messages {
		require.NoErrorf(t, r.Admit(msg), "Admit #%d", i)
		narrate(t, "R.4", "  Admit #"+strconv.Itoa(i)+" ok — plaintext hash matches the AGD's committed leaf for "+h.specs[i].path)
	}

	narrate(t, "R.5", "Reassembler.Finalize — rebuilding the RFC 6962 Merkle tree and asserting GenomeID round-trip.")
	res, err := r.Finalize()
	require.NoError(t, err)
	require.True(t, r.IsFinalized())
	require.Equal(t, h.agd.GenomeID, res.GenomeID,
		"Reassembler.GenomeID must equal AGD.GenomeID — the R-14 content-addressing invariant closes on the receive side")
	require.Equal(t, h.agd.ComponentTreeRoot, res.ComponentTreeRoot)
	for _, s := range h.specs {
		got, ok := res.Components[s.path]
		require.Truef(t, ok, "missing recovered path %q", s.path)
		require.Equalf(t, s.plaintext, got, "recovered plaintext for %q diverges from committed plaintext", s.path)
	}
	narrate(t, "R.5", "  Finalize ok — genome reassembled byte-exact; Merkle root and GenomeID both equal to AGD.")

	// Drive the state machine through to Stage G.
	require.NoError(t, o.MarkReassembled())
	require.Equal(t, bootstrap.StateValidate, o.State())

	narrate(t, "R.5.5", "Stage G — receive-side validator runs six op.recv.* sub-checks before MarkValidated.")
	svc := rtNewValidationService(t, h)
	vr := rtDriveValidation(t, h, svc, len(h.messages))
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict,
		"clean receive-side run must pass the operational dimension")
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionOperational].Score)
	narrate(t, "R.5.5", "  Verdict = "+string(vr.OverallVerdict)+"; ValidationResultID = "+string(vr.ValidationResultID)+".")
	narrate(t, "R.5.5", "  Audit events appended (STARTED + COMPLETED) against the same receive-side chain.")

	require.NoError(t, o.MarkValidated(vr.ValidationResultID))
	require.Equal(t, bootstrap.StateReady, o.State())

	narrate(t, "R.6", "Orchestrator.Decide — signing the terminal ReconstitutionDecision under the receive-side authority key.")
	dec, err := o.Decide()
	require.NoError(t, err)
	require.True(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReconstructedOK, dec.Reason)
	require.Equal(t, h.agd.GenomeID, dec.GenomeID)
	require.Equal(t, vr.ValidationResultID, dec.ValidationResultID,
		"terminal decision must cite the ValidationResultID Stage G minted")
	require.Equal(t, bootstrap.StateReconstituted, o.State())
	narrate(t, "R.6", "  Decide ok — ReconstitutionDecision signed; state = "+string(o.State())+"; reason = "+string(dec.Reason)+".")

	// Audit cross-verification: N DISCLOSURE_RECEIVED + STARTED + COMPLETED +
	// 1 RECONSTITUTION_DECIDED — the receive side is one audit tape.
	require.Equal(t, len(h.messages)+3, h.chain.Len())
	require.NoError(t, h.chain.Verify(h.store))
	narrate(t, "R.6", "  Audit chain length = "+strconv.Itoa(h.chain.Len())+" (N envelope + STARTED + COMPLETED + decided); chain.Verify(resolver) passes.")

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
	narrate(t, "R.6", "Round trip complete. GenomeID preserved end-to-end; Stage G anchors sit between envelope tail and terminal decision.")
}

// ---- act II stage 2/6: tier-1 refusal surfaces wire tamper ----------------

// TestRoundtripSlice_Tier1_WireTamper narrates a single-byte wire tamper
// and shows that the Orchestrator's wire-hash commitment catches it
// before any content-level machinery runs.
func TestRoundtripSlice_Tier1_WireTamper(t *testing.T) {
	t.Parallel()
	narrate(t, "T1.0", "Demonstrating tier-1 integrity: one byte flipped on the wire, post-signature.")
	h := buildRoundtripHarness(t, rtDefaultSpecs())
	o := rtNewOrchestrator(t, h)
	r := rtNewReassembler(t, h)
	require.NoError(t, o.Start())

	narrate(t, "T1.1", "Accepting the first envelope cleanly — we want the orchestrator genuinely mid-stream when the tamper lands.")
	_, err := o.Accept(h.messages[0])
	require.NoError(t, err)

	narrate(t, "T1.2", "Flipping one byte in envelope #1's sealed ciphertext. This alters the canonical bytes; the committed wire-hash no longer matches.")
	tampered := *h.messages[1]
	tampered.SealedPayload = append([]byte(nil), h.messages[1].SealedPayload...)
	tampered.SealedPayload[0] ^= 0xFF

	narrate(t, "T1.3", "Handing the tampered envelope to Orchestrator.Accept — expecting an Integrity-classified refusal at tier 1.")
	_, err = o.Accept(&tampered)
	require.Error(t, err)
	require.Equal(t, bootstrap.CodeAcceptWireHashMismatch, shared_errors.CodeOf(err))
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
		"wire-hash mismatch is an Integrity signal per doctrine §8.4")
	require.Equal(t, bootstrap.StateRejected, o.State())
	narrate(t, "T1.3", "  Refusal code = "+string(shared_errors.CodeOf(err))+"; category = Integrity; state = "+string(o.State())+".")

	narrate(t, "T1.4", "Proving the Reassembler was never touched: tier 2 did not run.")
	require.False(t, r.IsFinalized())

	narrate(t, "T1.5", "Emitting the signed rejection ReconstitutionDecision — receive side still closes cleanly.")
	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
	require.NotEmpty(t, dec.AuditEventID)
	narrate(t, "T1.5", "  Tier 1 stopped the tamper before any content was admitted. Audit event signed.")
}

// ---- act II stage 3/6: tier-2 refusal surfaces release-side fraud ---------

// TestRoundtripSlice_Tier2_PayloadFraud is the doctrine §8.4 acid test
// rendered as narration. A release-side adversary who holds the
// envelope-signing key forges same-byte-length plaintext, re-seals it
// under the correct AAD, re-signs the envelope, AND re-pins the wire-
// hash into the receive-side's expected-wire-hash list. Tier 1 has
// nothing to complain about. Tier 2 — the Reassembler — opens the
// fraudulent ciphertext and compares the plaintext's SHA-256 to the
// AGD's committed leaf hash. That is the comparison the adversary
// cannot forge without also forging the AGD's Ed25519 signature.
func TestRoundtripSlice_Tier2_PayloadFraud(t *testing.T) {
	t.Parallel()
	narrate(t, "T2.0", "Demonstrating tier-2 integrity: release-side forges same-byte-length plaintext with every wire-level signature re-minted.")
	h := buildRoundtripHarness(t, rtDefaultSpecs())

	target := 2 // one of the two weight shards
	fraudulentPlaintext := bytes.Repeat([]byte{0x5A}, int(h.compMap[h.specs[target].cid].ByteSize))
	require.NotEqual(t, h.specs[target].plaintext, fraudulentPlaintext)

	narrate(t, "T2.1", "Re-sealing the forged plaintext under the SAME 5-field AAD the release side would have built.")
	aad, err := disclosure_message.BuildRecipientAAD(
		rtSessionID, h.specs[target].cid, uint32(target), rtPolicy, rtKIDRecipient,
	)
	require.NoError(t, err)
	nonce, ct, err := h.store.Seal(rtKIDRecipient, fraudulentPlaintext, aad)
	require.NoError(t, err)

	fraudMsg := &disclosure_message.DisclosureMessage{
		SchemaVersion:  disclosure_message.SchemaVersionCurrent,
		DisclosureID:   h.messages[target].DisclosureID,
		SessionID:      rtSessionID,
		ComponentID:    h.specs[target].cid,
		PolicyVersion:  rtPolicy,
		SequenceIndex:  uint32(target),
		SealedPayload:  ct,
		Nonce:          nonce,
		RecipientKeyID: rtKIDRecipient,
		AuthorizedAt:   h.messages[target].AuthorizedAt,
		SigningKeyID:   rtKIDRelease,
	}
	require.NoError(t, fraudMsg.SignWith(h.store))
	require.NoError(t, fraudMsg.Validate())

	narrate(t, "T2.2", "Re-pinning both the envelope and the receive-side expected-wire-hash to match the forged envelope.")
	h.messages[target] = fraudMsg
	cb, err := fraudMsg.CanonicalBytes()
	require.NoError(t, err)
	h.wireH[target] = crypto.SHA256Slice(cb)

	o := rtNewOrchestrator(t, h)
	r := rtNewReassembler(t, h)
	require.NoError(t, o.Start())

	narrate(t, "T2.3", "Driving the Accept loop — tier 1 sees no tamper because the forged envelope's canonical hash is what we told it to expect.")
	for i, msg := range h.messages {
		_, err := o.Accept(msg)
		require.NoErrorf(t, err, "Accept #%d passes under tier 1 — no wire-level signal is available", i)
	}
	require.Equal(t, bootstrap.StateReassemble, o.State())
	narrate(t, "T2.3", "  All Accepts passed; state = "+string(o.State())+". Tier 1 alone is insufficient — proceeding to tier 2.")

	narrate(t, "T2.4", "Handing envelopes to the Reassembler. AES-GCM will open them all; the AGD's committed leaf hash will refuse the forged slot.")
	for i, msg := range h.messages {
		err := r.Admit(msg)
		if i == target {
			require.Errorf(t, err, "Admit #%d must catch the fraud", i)
			require.Equal(t, reassembly.CodeComponentHashMismatch, shared_errors.CodeOf(err))
			require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err),
				"plaintext-hash mismatch is an Integrity signal — the AGD is the authoritative binding")
			narrate(t, "T2.4", "  Admit #"+strconv.Itoa(i)+" REFUSED — code = "+string(shared_errors.CodeOf(err))+"; category = Integrity.")
			break
		}
		require.NoErrorf(t, err, "Admit #%d must pass (not the fraud slot)", i)
	}

	narrate(t, "T2.5", "Driver route on tier-2 failure: MarkReassemblyFailed → Decide emits a signed Accepted=false record.")
	require.NoError(t, o.MarkReassemblyFailed())
	dec, err := o.Decide()
	require.NoError(t, err)
	require.False(t, dec.Accepted)
	require.Equal(t, reconstitution_decision.ReasonReassemblyFailed, dec.Reason)
	require.NotEmpty(t, dec.AuditEventID)
	narrate(t, "T2.5", "  Tier 2 bound the wire to the genome. Forging the AGD's leaf hash would have required forging Ed25519.")
}
