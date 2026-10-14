// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package integration

// Phase 1 / Шаг 1 — End-to-end demo harness on the existing R-11 placeholder.
//
// This file is the executable realisation of docs/internal/phase1-v2-plan.md §2.2:
// the canonical eight-step lifecycle
//
//	1. Upload               → AGD + sealed component(s) for a LoRA-like adapter.
//	2. Steady state         → trust admission + session A under vault authority.
//	3. Simulated incident   → IncidentCoordinationService.HandleValidationHardFail;
//	                          session A invalidated, no zeroization (Error severity).
//	4. Recovery request     → fresh RecoveryRequest, attestation, session B,
//	                          disclosure, signed ReconstructionJobManifest.
//	5. Reconstruction       → the R-11 frozen interface (deterministic reference backend)
//	                          produces a CandidateOutput over the worker's
//	                          unsealed ComponentMaterial.
//	6. Three-dim validation → release-side service.ValidationService runs
//	                          operational + semantic + behavioral with a pre-
//	                          computed expected-fixture equal to the
//	                          deterministic reconstruction (byte-equality
//	                          semantic pass).
//	7. Release Decision     → signed ReleaseDecision with Release=true,
//	                          Reason=validation_pass, citing the
//	                          ValidationResultID and the RELEASE_DECIDED
//	                          audit event.
//	8. Controlled release   → byte-verification of the reconstruction
//	                          against the pre-computed fixture.
//
// The point of this file is to assemble every already-built piece into a
// single, narrated, deterministic trace so that `go test -v` on this
// package reads as a live end-to-end demo even while the wire protocol
// (task #73) and the daemons (tasks #74, #75) are still being written.
//
// The Reconstructor here is the deterministic reference backend
// (worker.DeterministicReconstructor): the production backend,
// worker.GenomeReconstructor, restores a real model through the vg_genome
// door and needs a genome, a base model and a Python runtime, which this
// in-process trace does without. R-11 freezes the interface, so the two
// are interchangeable behind it and nothing else in this file moves. The
// frozen-interface test in /internal/compute/worker enforces that promise
// from the compiler's side.
//
// Determinism discipline
//
// Every clock is a shared_time.FakeClock pinned to a fixed UTC moment;
// every AuditEventID and ValidationResultID is derived from either a
// fixed prefix + clock reading + monotonic counter or from the stable
// service-level prefixes. The deterministic reconstructor is pure by
// contract, so running this test twice produces byte-identical output.
// That is a pre-condition for the wire-protocol conformance suite
// (task #73) to use this harness as a golden fixture.

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/attestation_result"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/reconstruction_job_manifest"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/release_decision"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/session_object"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/validation/behavioral"
	"github.com/vault-genome/vaultgenome-core/internal/validation/operational"
	"github.com/vault-genome/vaultgenome-core/internal/validation/semantic"
	valservice "github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/session"
)

// ---- fixture constants (phase1_*) -----------------------------------------
//
// All identifiers are phase1-prefixed so a merged audit tape from this
// test can never be confused with the vertical or round-trip slices that
// share the integration package.

const (
	p1Policy = ids.PolicyVersion("policy-p1-v1")
	p1Family = "continuity-lora-adapter"

	p1KIDVault     = ids.KeyID("p1-vault-auth")
	p1KIDTrust     = ids.KeyID("p1-trust-auth")
	p1KIDAudit     = ids.KeyID("p1-vault-audit")
	p1KIDRecipient = ids.KeyID("p1-recipient-seal")
)

// p1LoRAAdapterBytes stands in for a real LoRA-rank-8 adapter blob. In
// Phase 6 this becomes an actual safetensors shard; here we need only
// a plausible, bounded blob that (a) has a shape the AGD machinery can
// commit to, and (b) is small enough that test output stays readable.
// The byte pattern is deliberate: a tiny header + repeating body so an
// auditor reading the demo script can eyeball the reconstruction bytes
// changing under any plaintext perturbation.
var p1LoRAAdapterBytes = func() []byte {
	header := []byte("LORA-r8-pythia70m-demo-v1;")
	body := bytes.Repeat([]byte{0x5A, 0xA5}, 128) // 256 bytes of alternating 0x5A/0xA5
	out := make([]byte, 0, len(header)+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out
}()

// p1Fixed32 returns a 32-byte slice whose every byte is b. Used for AGD
// fixture fields (ConfigHash, ProbeBatteryRoot, etc.) that are real
// commitments in production but just need to be bounded and stable
// here. Keeps the AGD structurally valid without reaching out to
// componenttree machinery for non-component fields.
func p1Fixed32(b byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = b
	}
	return h
}

// p1Clock builds the fake monotonic clock pinned to the canonical demo
// moment 2026-04-21 10:00:00 UTC. Every subsequent clock.Step call
// advances this single FakeClock.
func p1Clock() *shared_time.FakeClock {
	return shared_time.NewFakeClock(time.Date(2026, 4, 21, 10, 0, 0, 0, time.UTC))
}

// ---- behavioral probe suite (§3.4: at least three critical probes) -------

// p1Probes returns a deterministic, pass-under-the-reconstruction probe
// suite. Three critical probes plus one non-critical probe gives us a
// suite that satisfies §3.4 (≥3 critical) and exercises the blended
// pass-rate score (critTotal=3, nonTotal=1, all pass → score=1.0).
//
// Every probe is a pure function of the candidate bytes — no randomness,
// no external resources. This is non-negotiable: the aggregate CI-level
// repeatability guarantee (docs/doctrine/validation-thresholds.md §3.3) depends
// on it.
//
// The predicates are chosen so they pass against the deterministic
// reconstructor's output (iterated SHA-256 of the digest seed). None of
// them can pass by accident on a zero-length or all-zero candidate,
// which is the property we want for a "sanity suite".
func p1Probes(expectedLen uint64) []behavioral.Probe {
	return []behavioral.Probe{
		{
			ID:       "p1.bound.non_empty",
			Name:     "reconstruction is non-empty",
			Critical: true,
			Evaluate: func(candidate []byte) (bool, string) {
				if len(candidate) == 0 {
					return false, "candidate bytes empty; expected a bounded reconstruction"
				}
				return true, ""
			},
		},
		{
			ID:       "p1.bound.expected_length",
			Name:     "reconstruction matches manifest.ExpectedOutputMaxBytes",
			Critical: true,
			Evaluate: func(candidate []byte) (bool, string) {
				if uint64(len(candidate)) != expectedLen {
					return false, "candidate length " + strconv.Itoa(len(candidate)) +
						" != expected " + strconv.FormatUint(expectedLen, 10)
				}
				return true, ""
			},
		},
		{
			ID:       "p1.diversity.not_all_zero",
			Name:     "reconstruction is not the all-zero vector",
			Critical: true,
			Evaluate: func(candidate []byte) (bool, string) {
				for _, b := range candidate {
					if b != 0 {
						return true, ""
					}
				}
				return false, "candidate is all-zero; deterministic reconstructor would never emit this"
			},
		},
		{
			ID:       "p1.shape.deterministic_first_byte",
			Name:     "first byte is deterministic across re-runs (informational)",
			Critical: false,
			Evaluate: func(candidate []byte) (bool, string) {
				// The predicate is trivially satisfied by construction; the
				// probe exists to exercise the non-critical pass-rate code
				// path in behavioral.Run so the DimensionVerdict reports a
				// non-vacuous non-critical blend.
				return len(candidate) > 0, ""
			},
		},
	}
}

// ---- the integration test -------------------------------------------------

// TestPhase1Demo_LoRAAdapter_FullLifecycle is the canonical Phase 1
// demo: a single narrated end-to-end run of the eight-step lifecycle
// from docs/internal/phase1-v2-plan.md §2.2.
//
// Under `go test -v ./internal/integration/...` the t.Logf narration
// reads as the live demo script, with every stage marker lining up to
// the Phase 1 Plan's numbering so an operator demoing this to an
// investor can pause at any step and point to the corresponding plan
// paragraph.
//
// Determinism is load-bearing here: later Phase 1 tasks (#73 wire
// protocol, #77 Python SDK) will fold this harness's expected byte
// output into their own fixture suites. Flipping any of the seed values
// above must produce a byte-level divergence that the other tasks'
// golden fixtures catch.
func TestPhase1Demo_LoRAAdapter_FullLifecycle(t *testing.T) {
	t.Parallel()

	// ============================================================
	// Stage 0 — shared vault infrastructure
	// ============================================================
	//
	// One audit chain, one FakeClock, one keystore, one session
	// issuer, one incident service, one validation service — the
	// demo runs against the same wiring a single-node sagvd would
	// build at startup.

	narrate(t, "S.0", "Phase 1 demo begins. Wiring vault-side infrastructure: clock, keystore, audit chain, session issuer, incident service, validation service.")

	clk := p1Clock()
	store := keys.NewInMemoryStore(clk)
	_, err := store.GenerateSigning(p1KIDVault, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(p1KIDTrust, keys.PurposeSigningAuthority)
	require.NoError(t, err)
	_, err = store.GenerateSigning(p1KIDAudit, keys.PurposeSigningAudit)
	require.NoError(t, err)
	require.NoError(t, store.GenerateSealing(p1KIDRecipient))

	auditChain := chain.NewInMemoryChain()

	issuer, err := session.NewIssuer(clk, store, store, p1KIDVault, p1Policy, session.Options{
		IDPrefix: "sess-p1-",
	})
	require.NoError(t, err)

	// Zeroizer is a counter, not the real keystore, so a Critical
	// scenario that accidentally fires (which this test does not
	// schedule) does not wipe the store under our feet. The counter
	// is asserted to be zero below to prove ValidationHardFail is
	// Error-severity, not Critical — 00_R15_MVP.md §2.2.
	var zeroizes int
	zeroizer := incident.ZeroizerFunc(func() { zeroizes++ })

	// SessionInvalidator is wired to the real issuer — we want the
	// incident to actually flip the SessionObject's State so the
	// subsequent operational.CheckSessionValid (run against session A)
	// would catch the invalidation if the recovery flow leaked it.
	invalidator := incident.SessionInvalidatorFunc(func(sid ids.SessionID, reason string) error {
		_, err := issuer.Invalidate(sid)
		return err
	})

	incidentSvc, err := incident.NewService(incident.ServiceOptions{
		AuditChain:         auditChain,
		AuditSigner:        store,
		AuditKeyID:         p1KIDAudit,
		Clock:              clk,
		SessionInvalidator: invalidator,
		Zeroizer:           zeroizer,
		AuditIDPrefix:      "audit-p1-incident-",
	})
	require.NoError(t, err)

	valSvc, err := valservice.NewValidationService(valservice.ServiceOptions{
		AuditChain:     auditChain,
		AuditSigner:    store,
		AuditKeyID:     p1KIDAudit,
		Clock:          clk,
		AuditIDPrefix:  "audit-p1-val-",
		ResultIDPrefix: "vr-p1-",
	})
	require.NoError(t, err)

	narrate(t, "S.0", "  Vault wiring complete. Active policy = "+string(p1Policy)+"; audit chain empty.")

	// ============================================================
	// Stage 1 — Upload: AGD + sealed disclosure for the adapter
	// ============================================================

	narrate(t, "S.1", "Upload: operator publishes a LoRA-rank-8 adapter blob. Vault builds an AGD committing to the component and seals the plaintext under the recipient key.")

	componentID := ids.ComponentID("lora-adapter-r8")
	componentPath := "adapters/lora-r8/pythia-70m-dedup"
	pt := append([]byte(nil), p1LoRAAdapterBytes...)
	pthash := crypto.SHA256(pt)

	leaf := componenttree.Component{
		Path:     componentPath,
		Kind:     componenttree.KindTensor,
		ByteSize: uint64(len(pt)),
		Hash:     append([]byte(nil), pthash[:]...),
	}
	tree, err := componenttree.BuildTree([]componenttree.Component{leaf})
	require.NoError(t, err)

	agd := &genome_descriptor.GenomeDescriptor{
		SchemaVersion: genome_descriptor.SchemaVersionCurrent,
		FamilyName:    p1Family,
		Generation:    0,
		Kind:          genome_descriptor.KindTransformer,
		Architecture: genome_descriptor.ArchitectureDescriptor{
			Framework:      "pytorch-2.1",
			ModelClass:     "transformer-lora-adapter",
			ParameterCount: 65_536,
			PrecisionBits:  16,
			ConfigHash:     p1Fixed32(0xA1),
		},
		ComponentTreeRoot: tree.RootSlice(),
		ComponentCount:    1,
		TotalBytes:        leaf.ByteSize,
		Provenance: genome_descriptor.ProvenanceRecord{
			ProducerIdentity: "producer:phase1-demo",
			ProducedAt:       clk.Now(),
		},
		BehavioralFingerprint: genome_descriptor.ProbeBatteryRoot{
			BatteryID:            "llm-reasoning-phase1",
			BatterySchemaVersion: 1,
			BatteryMerkleRoot:    p1Fixed32(0xE6),
			CanonicalScoresRoot:  p1Fixed32(0xF7),
			ProbeCount:           4,
			MinPassingScore:      behavioral.PassThreshold,
		},
		IssuedAt:     clk.Now(),
		SigningKeyID: p1KIDVault,
	}
	gid, err := agd.DeriveID()
	require.NoError(t, err)
	agd.GenomeID = gid
	require.NoError(t, agd.SignWith(store))
	require.NoError(t, agd.Validate())

	narrate(t, "S.1", "  AGD signed; GenomeID = "+string(agd.GenomeID)+"; adapter SHA-256 = "+hex.EncodeToString(pthash[:8])+"… (first 8 bytes shown).")

	// ============================================================
	// Stage 2 — Steady state: session A under vault authority
	// ============================================================
	//
	// The operator-visible "steady state" is: a live TrustedSession,
	// minted by Trust Admission, active under the vault's policy.
	// Nothing has been disclosed yet; the session is the vault's
	// standing grant of authority to run a future reconstruction.

	narrate(t, "S.2", "Steady state: Trust Admission minted an attestation and the vault issued session A under the current policy. The vault is live and idle.")

	reqA := recovery_request.RecoveryRequest{
		SchemaVersion:     recovery_request.SchemaVersionCurrent,
		RequestID:         ids.RequestID("req-p1-a"),
		GenomeID:          agd.GenomeID,
		PolicyProfile:     "phase1-demo",
		RequesterIdentity: "operator:phase1-demo@example",
		Contour:           map[string]string{"demo": "phase1", "phase": "steady_state"},
		CreatedAt:         clk.Now(),
	}
	require.NoError(t, reqA.Validate())

	reqAEvt := makeAuditEvent(t, audit_event.KindRequestReceived, p1KIDAudit, clk,
		reqA.RequestID, "", "",
		map[string]string{"phase": "steady_state", "policy_profile": reqA.PolicyProfile})
	_, err = auditChain.Append(reqAEvt, store)
	require.NoError(t, err)

	clk.Step(50 * time.Millisecond)

	attA := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-p1-a"),
		RequestID:     reqA.RequestID,
		Outcome:       attestation_result.OutcomeAllow,
		Reason:        "trust.phase1_demo",
		IssuedAt:      clk.Now(),
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  p1KIDTrust,
	}
	require.NoError(t, attA.SignWith(store))
	require.NoError(t, attA.Validate())
	require.NoError(t, attA.VerifySignature(store))

	trustAEvt := makeAuditEvent(t, audit_event.KindTrustEvaluated, p1KIDAudit, clk,
		reqA.RequestID, "", "",
		map[string]string{"outcome": string(attA.Outcome), "attestation_id": attA.AttestationID.String()})
	_, err = auditChain.Append(trustAEvt, store)
	require.NoError(t, err)

	clk.Step(50 * time.Millisecond)

	sessA, err := issuer.Issue(session.IssueParams{
		RequestID: reqA.RequestID,
		GenomeID:  agd.GenomeID,
		TTL:       10 * time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, issuer.Verify(sessA))

	sessAEvt := makeAuditEvent(t, audit_event.KindSessionIssued, p1KIDAudit, clk,
		reqA.RequestID, "", sessA.SessionID,
		map[string]string{"policy_version": string(sessA.PolicyVersion), "phase": "steady_state"})
	_, err = auditChain.Append(sessAEvt, store)
	require.NoError(t, err)

	narrate(t, "S.2", "  Session A issued: "+string(sessA.SessionID)+"; state = "+string(sessA.State)+"; TTL = 10m.")

	// ============================================================
	// Stage 3 — Simulated incident: ValidationHardFail on session A
	// ============================================================
	//
	// Phase 1 Plan §2.2 step 3 asks the demo to exercise R-15 live.
	// We pick ScenarioValidationHardFail (Error severity) as the
	// doctrinally-clean way to trigger a session termination without
	// wiping keys: the keys were not compromised, the candidate just
	// failed policy. That is the exact scenario a pilot operator is
	// most likely to exercise during an incident-response drill.

	narrate(t, "S.3", "Simulated incident: the operator triggers a ValidationHardFail on session A. IncidentCoordinationService emits INCIDENT_DETECTED → invalidates session A → emits INCIDENT_TERMINATED. Error severity; no key wipe.")

	clk.Step(25 * time.Millisecond)

	incResult, err := incidentSvc.HandleValidationHardFail(incident.Trigger{
		SessionID:  sessA.SessionID,
		ManifestID: ids.ManifestID(""), // no manifest in flight at steady state
		Code:       operational.CodeManifestIntegrity,
		Detail:     "phase1 demo — operator-triggered drill of R-15 ScenarioValidationHardFail",
	})
	require.NoError(t, err)
	require.NotNil(t, incResult)
	require.Equal(t, incident.ScenarioValidationHardFail, incResult.Scenario)
	require.Equal(t, incident.SeverityError, incResult.Severity)
	require.True(t, incResult.SessionInvalidated, "SessionInvalidator must flip state on session A")
	require.False(t, incResult.Zeroized, "Error severity must NOT zeroize keys (§2.2 MVP mapping)")
	require.Equal(t, 0, zeroizes, "Zeroizer must be untouched for ScenarioValidationHardFail")
	require.NotEmpty(t, incResult.DetectedEventID)
	require.NotEmpty(t, incResult.TerminatedEventID)

	// Prove the incident's side-effect actually reached the vault
	// authority layer: Lookup the stored session and assert State is
	// Invalidated. (issuer.Verify intentionally does NOT consult the
	// internal map — per its own doc comment, an older active snapshot
	// held by a caller still passes Verify, so using Verify here would
	// be the wrong probe.)
	storedA, ok := issuer.Lookup(sessA.SessionID)
	require.True(t, ok, "issuer must still remember session A after invalidation")
	require.Equal(t, session_object.StateInvalidated, storedA.State,
		"session A's stored State must be Invalidated after the incident side-effect")

	narrate(t, "S.3", "  Incident terminated. DetectedEventID = "+string(incResult.DetectedEventID)+"; TerminatedEventID = "+string(incResult.TerminatedEventID)+"; zeroizer count = 0 (Error severity, correct mapping); stored State = "+string(storedA.State)+".")

	// ============================================================
	// Stage 4 — Recovery request: fresh session B, disclosure, manifest
	// ============================================================
	//
	// The operator now exercises the reconstruction path. This is the
	// "real" lifecycle stage the demo is about: a disclosure and
	// manifest issued to an external compute worker, keyed to a fresh
	// authoritative session that post-dates the incident.

	narrate(t, "S.4", "Recovery request: operator submits req-b for the same adapter genome. Trust Admission allows; vault issues session B; one disclosure authorized; ReconstructionJobManifest signed.")

	clk.Step(100 * time.Millisecond)

	reqB := recovery_request.RecoveryRequest{
		SchemaVersion:     recovery_request.SchemaVersionCurrent,
		RequestID:         ids.RequestID("req-p1-b"),
		GenomeID:          agd.GenomeID,
		PolicyProfile:     "phase1-demo-recovery",
		RequesterIdentity: "operator:phase1-demo@example",
		Contour:           map[string]string{"demo": "phase1", "phase": "recovery"},
		CreatedAt:         clk.Now(),
	}
	require.NoError(t, reqB.Validate())
	reqBEvt := makeAuditEvent(t, audit_event.KindRequestReceived, p1KIDAudit, clk,
		reqB.RequestID, "", "",
		map[string]string{"phase": "recovery"})
	_, err = auditChain.Append(reqBEvt, store)
	require.NoError(t, err)

	clk.Step(50 * time.Millisecond)

	attB := attestation_result.AttestationResult{
		SchemaVersion: attestation_result.SchemaVersionCurrent,
		AttestationID: ids.AttestationID("att-p1-b"),
		RequestID:     reqB.RequestID,
		Outcome:       attestation_result.OutcomeAllow,
		Reason:        "trust.phase1_recovery",
		IssuedAt:      clk.Now(),
		TTL:           attestation_result.DefaultTTL,
		SigningKeyID:  p1KIDTrust,
	}
	require.NoError(t, attB.SignWith(store))
	require.NoError(t, attB.VerifySignature(store))

	trustBEvt := makeAuditEvent(t, audit_event.KindTrustEvaluated, p1KIDAudit, clk,
		reqB.RequestID, "", "",
		map[string]string{"outcome": string(attB.Outcome), "attestation_id": attB.AttestationID.String()})
	_, err = auditChain.Append(trustBEvt, store)
	require.NoError(t, err)

	clk.Step(50 * time.Millisecond)

	sessB, err := issuer.Issue(session.IssueParams{
		RequestID: reqB.RequestID,
		GenomeID:  agd.GenomeID,
		TTL:       10 * time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, issuer.Verify(sessB))
	require.NotEqual(t, sessA.SessionID, sessB.SessionID,
		"recovery must mint a fresh SessionID; reusing the invalidated one would be a regression")

	sessBEvt := makeAuditEvent(t, audit_event.KindSessionIssued, p1KIDAudit, clk,
		reqB.RequestID, "", sessB.SessionID,
		map[string]string{"policy_version": string(sessB.PolicyVersion), "phase": "recovery"})
	_, err = auditChain.Append(sessBEvt, store)
	require.NoError(t, err)

	// Disclosure: seal the component plaintext under the recipient key,
	// AAD-bound to (manifestID | sessionID | componentID) per the
	// vertical-slice convention.
	clk.Step(50 * time.Millisecond)

	manifestID := ids.ManifestID("man-p1-b")
	disclosureID := ids.DisclosureID("disc-p1-b")

	aad := []byte(string(manifestID) + "|" + string(sessB.SessionID) + "|" + string(componentID))
	nonce, sealed, err := store.Seal(p1KIDRecipient, append([]byte(nil), pt...), aad)
	require.NoError(t, err)
	// Round-trip the seal to prove the recipient key is the only opener.
	opened, err := store.Open(p1KIDRecipient, nonce, sealed, aad)
	require.NoError(t, err)
	require.Equal(t, pt, opened)

	disc := disclosure_message.DisclosureMessage{
		SchemaVersion:  disclosure_message.SchemaVersionCurrent,
		DisclosureID:   disclosureID,
		SessionID:      sessB.SessionID,
		ComponentID:    componentID,
		PolicyVersion:  p1Policy,
		SequenceIndex:  0,
		SealedPayload:  sealed,
		Nonce:          nonce,
		RecipientKeyID: p1KIDRecipient,
		AuthorizedAt:   clk.Now(),
		SigningKeyID:   p1KIDVault,
	}
	require.NoError(t, disc.SignWith(store))
	require.NoError(t, disc.Validate())
	require.NoError(t, disc.VerifySignature(store))

	discEvt := makeAuditEvent(t, audit_event.KindDisclosureAuthorized, p1KIDAudit, clk,
		reqB.RequestID, manifestID, sessB.SessionID,
		map[string]string{
			"disclosure_id":  disc.DisclosureID.String(),
			"component_id":   disc.ComponentID.String(),
			"sequence_index": "0",
		})
	_, err = auditChain.Append(discEvt, store)
	require.NoError(t, err)

	// Manifest — signed so operational.CheckManifestIntegrity passes.
	clk.Step(50 * time.Millisecond)

	// ExpectedOutputMaxBytes is what the deterministic reconstructor
	// expands its seed into; it is ALSO the value the behavioral probe
	// p1.bound.expected_length checks against. A 4 KiB budget is
	// generous for a probe blob and bounded enough that the test output
	// stays small.
	const p1ExpectedOutputMaxBytes uint64 = 4096

	manIssuedAt := clk.Now()
	man := reconstruction_job_manifest.ReconstructionJobManifest{
		SchemaVersion:          reconstruction_job_manifest.SchemaVersionCurrent,
		ManifestID:             manifestID,
		SessionID:              sessB.SessionID,
		GenomeID:               agd.GenomeID,
		PolicyVersion:          p1Policy,
		DisclosureIDs:          []ids.DisclosureID{disclosureID},
		ExpectedOutputKind:     reconstruction_job_manifest.OutputKindBytesFixedLength,
		ExpectedOutputMaxBytes: p1ExpectedOutputMaxBytes,
		RecipientKeyID:         p1KIDRecipient,
		Deadline:               manIssuedAt.Add(10 * time.Minute),
		IssuedAt:               manIssuedAt,
		SigningKeyID:           p1KIDVault,
	}
	require.NoError(t, man.SignWith(store))
	require.NoError(t, man.Validate())
	require.NoError(t, man.VerifySignature(store))

	manEvt := makeAuditEvent(t, audit_event.KindManifestIssued, p1KIDAudit, clk,
		reqB.RequestID, man.ManifestID, sessB.SessionID,
		map[string]string{"deadline": man.Deadline.UTC().Format(time.RFC3339Nano)})
	_, err = auditChain.Append(manEvt, store)
	require.NoError(t, err)

	narrate(t, "S.4", "  Session B = "+string(sessB.SessionID)+"; disclosure = "+string(disc.DisclosureID)+"; manifest = "+string(man.ManifestID)+"; max output = "+strconv.FormatUint(p1ExpectedOutputMaxBytes, 10)+" bytes.")

	// ============================================================
	// Stage 5 — Reconstruction via the R-11 frozen interface
	// ============================================================
	//
	// This is the single most doctrinally-significant line in the
	// demo: the worker is invoked through the interface, not the
	// concrete type. The production backend is worker.GenomeReconstructor
	// (genome.go): it restores a sealed genome's model through the
	// vg_genome door and returns the model's outputs on the genome's
	// reference prompts, which the authority gates. It needs a genome, a
	// base model and a Python runtime, so this in-process demo drives
	// the same interface with the deterministic reference backend
	// (worker.DeterministicReconstructor); every other line of the
	// pipeline is the same either way — that is the point of freezing
	// the R-11 shape in iteration 5. The real backend runs end to end in
	// test/integration (a gate job over mutual TLS).
	//
	// We also pre-compute the expected bytes with a SECOND call to the
	// same reconstructor. The purity contract of the Reconstructor
	// interface (/internal/compute/worker/reconstruction.go §Contract
	// item 1) requires that identical inputs produce byte-identical
	// outputs; the equality assertion below is both a doctrinal
	// property test and the source of the semantic-dimension expected
	// fixture, regardless of which backend is installed.

	narrate(t, "S.5", "Reconstruction: the external compute worker unseals the disclosure and invokes the R-11 Reconstructor interface. Production backing is worker.GenomeReconstructor (a real model behind the vg_genome door); this in-process demo drives the same frozen interface with the deterministic reference backend.")

	var reconstructor worker.Reconstructor
	{
		refRec, err := worker.NewDeterministicReconstructor(clk)
		require.NoError(t, err)
		reconstructor = refRec
	}

	// Worker-side materials: the plaintext came out of the unseal
	// operation above. In production the worker receives the sealed
	// envelope over the wire and runs the same Open call; here we
	// shortcut the transport because task #73 (wire protocol) is the
	// next step.
	materials := []worker.ComponentMaterial{
		{
			ComponentID:   componentID,
			SequenceIndex: 0,
			Plaintext:     append([]byte(nil), opened...),
		},
	}

	ctx := context.Background()

	// Pre-computation: the "blessed" reconstruction a Phase 6 signing
	// ceremony would have produced. We invoke the reconstructor first
	// to capture this reference blob; by the determinism contract the
	// second call below produces byte-identical output.
	referenceOut, err := reconstructor.Reconstruct(ctx, man, materials)
	require.NoError(t, err)
	require.Equal(t, man.ManifestID, referenceOut.ManifestID)
	require.Equal(t, man.SessionID, referenceOut.SessionID)
	require.Equal(t, man.ExpectedOutputKind, referenceOut.OutputKind)
	require.Equal(t, p1ExpectedOutputMaxBytes, uint64(len(referenceOut.Bytes)))
	require.False(t, referenceOut.ProducedAt.IsZero())
	// Verify it is clearly NOT the all-zero vector (property test that
	// matches the behavioral probe p1.diversity.not_all_zero).
	allZero := true
	for _, b := range referenceOut.Bytes {
		if b != 0 {
			allZero = false
			break
		}
	}
	require.False(t, allZero, "deterministic reconstructor must not emit the all-zero vector")

	// Actual recovery-time reconstruction. Determinism says these bytes
	// equal referenceOut.Bytes exactly.
	candidateOut, err := reconstructor.Reconstruct(ctx, man, materials)
	require.NoError(t, err)
	require.Equal(t, referenceOut.Bytes, candidateOut.Bytes,
		"R-11 determinism: identical (manifest, components) must produce byte-identical output")

	refHash := crypto.SHA256(referenceOut.Bytes)
	candHash := crypto.SHA256(candidateOut.Bytes)
	require.Equal(t, refHash, candHash)

	// Emit the CANDIDATE_RECEIVED audit event — in production this is
	// fired by the Return Path inbound handler on the vault side as
	// soon as a CandidateOutput crosses the authority boundary. Here
	// the "return path" is an in-process handoff; the audit event
	// still must be emitted because §8 "audit is first-class".
	clk.Step(200 * time.Millisecond)
	candEvt := makeAuditEvent(t, audit_event.KindCandidateReceived, p1KIDAudit, clk,
		reqB.RequestID, man.ManifestID, sessB.SessionID,
		map[string]string{
			"candidate_bytes": toBase10(len(candidateOut.Bytes)),
			"candidate_hash":  hex.EncodeToString(candHash[:8]),
		})
	_, err = auditChain.Append(candEvt, store)
	require.NoError(t, err)

	narrate(t, "S.5", "  Reconstruction produced "+strconv.Itoa(len(candidateOut.Bytes))+" bytes; SHA-256[:8] = "+hex.EncodeToString(candHash[:8])+"…; determinism property verified against reference run.")

	// ============================================================
	// Stage 6 — Three-dimension validation via the release-side service
	// ============================================================
	//
	// This is the release-side Stage G + H + I in one service call.
	// The ValidationService emits STARTED, one DIMENSION_EVALUATED per
	// dimension, and COMPLETED. On a clean pass there are no FINDING
	// events. Every event is Signed and Chained inside the service.

	narrate(t, "S.6", "Three-dimension validation: service.ValidationService runs operational, semantic, and behavioral. All three must pass for OverallVerdict=pass.")

	valIn := valservice.ValidateInputs{
		SessionID:  sessB.SessionID,
		ManifestID: man.ManifestID,
		Semantic: semantic.Inputs{
			Candidate:    append([]byte(nil), candidateOut.Bytes...),
			Expected:     append([]byte(nil), referenceOut.Bytes...),
			HaveExpected: true,
		},
		Behavioral: behavioral.Inputs{
			Candidate: append([]byte(nil), candidateOut.Bytes...),
			Probes:    p1Probes(p1ExpectedOutputMaxBytes),
		},
		Operational: operational.Inputs{
			Attestation:     attB,
			Session:         sessB,
			Manifest:        man,
			ActivePolicy:    p1Policy,
			TamperSignalled: false,
			Now:             clk.Now(),
			Resolver:        store,
		},
	}

	vr, err := valSvc.Validate(valIn)
	require.NoError(t, err)
	require.NotNil(t, vr)
	require.Equal(t, validation_result.VerdictPass, vr.OverallVerdict,
		"clean recovery run must pass all three dimensions — findings: %+v", vr.Dimensions)
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionOperational].Score)
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionSemantic].Score)
	require.Equal(t, 1.0, vr.Dimensions[validation_result.DimensionBehavioral].Score,
		"suite of 4 all-pass probes blends to 1.0")
	require.Equal(t, sessB.SessionID, vr.SessionID)
	require.Equal(t, man.ManifestID, vr.ManifestID)

	narrate(t, "S.6", "  OverallVerdict = "+string(vr.OverallVerdict)+"; ValidationResultID = "+string(vr.ValidationResultID)+"; op=1.0, sem=1.0, beh=1.0.")

	// ============================================================
	// Stage 7 — Release Decision
	// ============================================================
	//
	// Per release_decision.validator §6 the RELEASE_DECIDED audit
	// event MUST be appended BEFORE the ReleaseDecision is signed,
	// so the Decision can cite a sealed EventID. Un-evidenced
	// decisions are structurally invalid.

	narrate(t, "S.7", "Release Decision: the vault consumes the ValidationResult and emits a signed ReleaseDecision. Reason=validation_pass, Release=true, citing both the ValidationResultID and the RELEASE_DECIDED audit event.")

	clk.Step(25 * time.Millisecond)

	releaseEvt := makeAuditEvent(t, audit_event.KindReleaseDecided, p1KIDAudit, clk,
		reqB.RequestID, man.ManifestID, sessB.SessionID,
		map[string]string{
			"release": "true",
			"reason":  string(release_decision.ReasonValidationPass),
		})
	sealedRelease, err := auditChain.Append(releaseEvt, store)
	require.NoError(t, err)

	dec := release_decision.ReleaseDecision{
		SchemaVersion:      release_decision.SchemaVersionCurrent,
		DecisionID:         ids.DecisionID("dec-p1-b"),
		SessionID:          sessB.SessionID,
		ManifestID:         man.ManifestID,
		ValidationResultID: vr.ValidationResultID,
		Release:            true,
		Reason:             release_decision.ReasonValidationPass,
		DecidedAt:          clk.Now(),
		SigningKeyID:       p1KIDVault,
		AuditEventID:       sealedRelease.EventID,
	}
	require.NoError(t, dec.SignWith(store))
	require.NoError(t, dec.Validate())
	require.NoError(t, dec.VerifySignature(store))

	narrate(t, "S.7", "  ReleaseDecision signed; DecisionID = "+string(dec.DecisionID)+"; cites "+string(vr.ValidationResultID)+" and AuditEventID = "+string(dec.AuditEventID)+".")

	// ============================================================
	// Stage 8 — Controlled release: byte-verification
	// ============================================================
	//
	// The "release" in ReleaseDecision is not the network transfer of
	// the reconstruction bytes — the bytes were already produced at
	// stage 5 and held candidate inside the vault boundary until this
	// gate. The verification is: the bytes the operator will receive
	// are exactly the pre-computed fixture the vault committed to.

	narrate(t, "S.8", "Controlled release: the reconstruction bytes the operator is authorized to receive are byte-equal to the pre-computed expected fixture. Any bit-level divergence would be caught at the semantic dimension above and would not have reached this gate.")

	require.True(t, dec.Release, "happy path must produce Release=true")
	require.Equal(t, release_decision.ReasonValidationPass, dec.Reason)
	require.True(t, bytes.Equal(referenceOut.Bytes, candidateOut.Bytes),
		"controlled release: output bytes must match the blessed fixture exactly")

	// Also surface the relationship to the uploaded genome: the AGD's
	// GenomeID propagated into the session, the manifest, the
	// ValidationResult, and the Decision. If any correlation breaks,
	// the chain verifies cryptographically but the demo is meaningless.
	require.Equal(t, agd.GenomeID, sessB.GenomeID)
	require.Equal(t, agd.GenomeID, man.GenomeID)
	require.Equal(t, sessB.SessionID, man.SessionID)
	require.Equal(t, sessB.SessionID, vr.SessionID)
	require.Equal(t, sessB.SessionID, dec.SessionID)
	require.Equal(t, man.ManifestID, vr.ManifestID)
	require.Equal(t, man.ManifestID, dec.ManifestID)
	require.Equal(t, vr.ValidationResultID, dec.ValidationResultID)
	require.Equal(t, sealedRelease.EventID, dec.AuditEventID)

	// ============================================================
	// Final assertions — audit chain integrity + event census
	// ============================================================
	//
	// The entire demo ran against one audit chain. If any event was
	// not signed, if any PrevHash was wrong, if any canonical
	// pre-image disagreed with its stored Hash, chain.Verify returns
	// a non-nil error. That single call is the cryptographic truth
	// of "the demo happened as narrated".

	require.NoError(t, auditChain.Verify(store),
		"release-side audit chain must verify end-to-end under the store's audit signing key")

	// Expected event census, in append order:
	//
	//	steady state (manual):
	//	  1 REQUEST_RECEIVED        (req-a)
	//	  2 TRUST_EVALUATED         (req-a)
	//	  3 SESSION_ISSUED          (sess-a)
	//
	//	incident (incident.Service):
	//	  4 INCIDENT_DETECTED       (validation_hard_fail, sess-a)
	//	  5 INCIDENT_TERMINATED     (validation_hard_fail, sess-a)
	//
	//	recovery (manual):
	//	  6 REQUEST_RECEIVED        (req-b)
	//	  7 TRUST_EVALUATED         (req-b)
	//	  8 SESSION_ISSUED          (sess-b)
	//	  9 DISCLOSURE_AUTHORIZED   (disc-b)
	//	 10 MANIFEST_ISSUED         (man-b)
	//	 11 CANDIDATE_RECEIVED      (sess-b)
	//
	//	validation (service.ValidationService — no findings on clean pass):
	//	 12 VALIDATION_STARTED
	//	 13 VALIDATION_DIMENSION_EVALUATED (operational)
	//	 14 VALIDATION_DIMENSION_EVALUATED (semantic)
	//	 15 VALIDATION_DIMENSION_EVALUATED (behavioral)
	//	 16 VALIDATION_COMPLETED
	//
	//	release (manual):
	//	 17 RELEASE_DECIDED
	//
	// Total: 17 events. Shifting this number is a doctrinal event —
	// either a new audit-event kind was introduced or the Service
	// changed its emission set. Either way, this assertion is the
	// canary that forces the demo narrative to be updated.
	require.Equal(t, 17, auditChain.Len(),
		"Phase 1 demo event count is a governance invariant; see the census table in the test")

	// Spot-check the incident segment: events 4 and 5 must be
	// INCIDENT_DETECTED and INCIDENT_TERMINATED in that order. If the
	// incident service ever re-orders these, the operator narration
	// above (stage S.3) becomes misleading; this check keeps the
	// narrative and the ledger in lockstep.
	evt4, ok := auditChain.EventAt(3)
	require.True(t, ok)
	evt5, ok := auditChain.EventAt(4)
	require.True(t, ok)
	require.Equal(t, audit_event.KindIncidentDetected, evt4.Kind)
	require.Equal(t, audit_event.KindIncidentTerminated, evt5.Kind)

	// Spot-check the validation segment: events 12..16 must be the
	// STARTED, three DIMENSIONs, COMPLETED sequence.
	expectedValKinds := []audit_event.Kind{
		audit_event.KindValidationStarted,
		audit_event.KindValidationDimension,
		audit_event.KindValidationDimension,
		audit_event.KindValidationDimension,
		audit_event.KindValidationCompleted,
	}
	for i, k := range expectedValKinds {
		e, ok := auditChain.EventAt(11 + i) // 0-indexed; event 12 is index 11
		require.True(t, ok)
		require.Equalf(t, k, e.Kind,
			"validation segment event %d should be %s, got %s", 11+i, k, e.Kind)
	}

	narrate(t, "END", "Phase 1 demo complete. 17 audit events, chain verifies, ReleaseDecision signed, bytes match the blessed fixture, and the Reconstructor swap point for task #78 is a single constructor call at stage S.5.")
}
