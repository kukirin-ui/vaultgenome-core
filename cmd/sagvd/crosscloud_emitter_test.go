// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// makeEmitterFixture wires a fresh in-memory chain + audit-purpose
// signing key + emitter. Returned values are independently usable
// for end-to-end emission round-trips.
func makeEmitterFixture(t *testing.T) (*chainAuditEmitter, chain.Chain, *keys.InMemoryStore) {
	t.Helper()
	clock := shared_time.NewFakeClock(time.Date(2026, 5, 9, 13, 0, 0, 0, time.UTC))
	store := keys.NewInMemoryStore(clock)
	if _, err := store.GenerateSigning(CrossCloudAuditSigningKeyID, keys.PurposeSigningAudit); err != nil {
		t.Fatalf("generate audit key: %v", err)
	}
	c := chain.NewInMemoryChain()
	emitter, err := newChainAuditEmitter(c, store, CrossCloudAuditSigningKeyID, clock, "xcc-evt-")
	if err != nil {
		t.Fatalf("newChainAuditEmitter: %v", err)
	}
	return emitter, c, store
}

// --- chainAuditEmitter constructor ---------------------------------

func TestNewChainAuditEmitter_RequiresAllFields(t *testing.T) {
	clock := shared_time.NewFakeClock(time.Now())
	store := keys.NewInMemoryStore(clock)
	if _, err := store.GenerateSigning(CrossCloudAuditSigningKeyID, keys.PurposeSigningAudit); err != nil {
		t.Fatalf("generate: %v", err)
	}
	c := chain.NewInMemoryChain()

	cases := []struct {
		name      string
		chain     chain.Chain
		signer    keys.Signer
		signerKID ids.KeyID
		clock     shared_time.Clock
		wantErr   string
	}{
		{"chain nil", nil, store, CrossCloudAuditSigningKeyID, clock, "chain required"},
		{"signer nil", c, nil, CrossCloudAuditSigningKeyID, clock, "signer required"},
		{"kid empty", c, store, "", clock, "signerKID required"},
		{"clock nil", c, store, CrossCloudAuditSigningKeyID, nil, "clock required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newChainAuditEmitter(tc.chain, tc.signer, tc.signerKID, tc.clock, "xcc-evt-")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("newChainAuditEmitter(%s): err = %v; want %q", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestNewChainAuditEmitter_EmptyPrefixDefaults(t *testing.T) {
	clock := shared_time.NewFakeClock(time.Now())
	store := keys.NewInMemoryStore(clock)
	store.GenerateSigning(CrossCloudAuditSigningKeyID, keys.PurposeSigningAudit)
	c := chain.NewInMemoryChain()
	emitter, err := newChainAuditEmitter(c, store, CrossCloudAuditSigningKeyID, clock, "")
	if err != nil {
		t.Fatalf("newChainAuditEmitter(empty prefix): %v", err)
	}
	id, err := emitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{"x":1}`), "", "", "")
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !strings.HasPrefix(string(id), "xcc-evt-") {
		t.Errorf("EventID %q must use default prefix xcc-evt-", id)
	}
}

// --- Emit semantics -------------------------------------------------

func TestChainAuditEmitter_Emit_HappyPath(t *testing.T) {
	emitter, c, _ := makeEmitterFixture(t)
	id, err := emitter.Emit(
		audit_event.KindCrossCloudHandshakeInitiated,
		[]byte(`{"decision_id":"dec-1"}`),
		ids.SessionID("sess-1"),
		ids.ManifestID("man-1"),
		ids.RequestID("req-1"),
	)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if id == "" {
		t.Fatal("Emit returned empty EventID")
	}
	if c.Len() != 1 {
		t.Errorf("chain.Len = %d; want 1", c.Len())
	}
	evt, ok := c.EventAt(0)
	if !ok {
		t.Fatal("EventAt(0) returned false")
	}
	if evt.Kind != audit_event.KindCrossCloudHandshakeInitiated {
		t.Errorf("Kind = %s; want CROSS_CLOUD_HANDSHAKE_INITIATED", evt.Kind)
	}
	if evt.SessionID != "sess-1" || evt.ManifestID != "man-1" || evt.RequestID != "req-1" {
		t.Errorf("correlators not propagated: %+v", evt)
	}
	if string(evt.Payload) != `{"decision_id":"dec-1"}` {
		t.Errorf("payload = %s; want JSON literal", evt.Payload)
	}
	if evt.SigningKeyID != CrossCloudAuditSigningKeyID {
		t.Errorf("SigningKeyID = %s; want %s", evt.SigningKeyID, CrossCloudAuditSigningKeyID)
	}
	if len(evt.Hash) != audit_event.HashSize {
		t.Errorf("Hash size = %d; want %d", len(evt.Hash), audit_event.HashSize)
	}
	if len(evt.Signature) == 0 {
		t.Error("Signature must be populated by chain.Append")
	}
}

func TestChainAuditEmitter_Emit_FourCrossCloudKindsInOrder(t *testing.T) {
	emitter, c, _ := makeEmitterFixture(t)
	kinds := []audit_event.Kind{
		audit_event.KindCrossCloudHandshakeInitiated,
		audit_event.KindCrossCloudAttestationVerified,
		audit_event.KindKeyReleaseAuthorized,
		audit_event.KindCrossCloudRestoreCompleted,
	}
	for i, k := range kinds {
		_, err := emitter.Emit(k, []byte(`{}`), "", "", "")
		if err != nil {
			t.Fatalf("Emit kind %d (%s): %v", i, k, err)
		}
	}
	if c.Len() != 4 {
		t.Errorf("chain.Len = %d; want 4", c.Len())
	}
	for i, want := range kinds {
		evt, _ := c.EventAt(i)
		if evt.Kind != want {
			t.Errorf("event[%d].Kind = %s; want %s", i, evt.Kind, want)
		}
	}
}

func TestChainAuditEmitter_Emit_UniqueEventIDs(t *testing.T) {
	emitter, _, _ := makeEmitterFixture(t)
	seen := make(map[ids.AuditEventID]struct{})
	for i := 0; i < 50; i++ {
		id, err := emitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{}`), "", "", "")
		if err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("EventID %s repeated at iteration %d", id, i)
		}
		seen[id] = struct{}{}
	}
}

func TestChainAuditEmitter_Emit_HashChainContinuity(t *testing.T) {
	emitter, c, _ := makeEmitterFixture(t)
	for i := 0; i < 5; i++ {
		_, err := emitter.Emit(audit_event.KindCrossCloudHandshakeInitiated, []byte(`{}`), "", "", "")
		if err != nil {
			t.Fatalf("Emit %d: %v", i, err)
		}
	}
	// Each event's PrevHash must equal previous event's Hash.
	for i := 1; i < c.Len(); i++ {
		curr, _ := c.EventAt(i)
		prev, _ := c.EventAt(i - 1)
		if string(curr.PrevHash) != string(prev.Hash) {
			t.Errorf("event[%d].PrevHash != event[%d].Hash", i, i-1)
		}
	}
}

// --- IDGenerator ---------------------------------------------------

func TestCryptoRandIDGenerator_RequestID_FreshAndPrefixed(t *testing.T) {
	g := newCryptoRandIDGenerator("xcc-req-", "xcc-dec-")
	seen := make(map[ids.RequestID]struct{})
	for i := 0; i < 50; i++ {
		id, err := g.NewRequestID()
		if err != nil {
			t.Fatalf("NewRequestID: %v", err)
		}
		if !strings.HasPrefix(string(id), "xcc-req-") {
			t.Errorf("missing prefix: %s", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("RequestID %s repeated", id)
		}
		seen[id] = struct{}{}
	}
}

func TestCryptoRandIDGenerator_DecisionID_FreshAndPrefixed(t *testing.T) {
	g := newCryptoRandIDGenerator("xcc-req-", "xcc-dec-")
	seen := make(map[ids.DecisionID]struct{})
	for i := 0; i < 50; i++ {
		id, err := g.NewDecisionID()
		if err != nil {
			t.Fatalf("NewDecisionID: %v", err)
		}
		if !strings.HasPrefix(string(id), "xcc-dec-") {
			t.Errorf("missing prefix: %s", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("DecisionID %s repeated", id)
		}
		seen[id] = struct{}{}
	}
}

func TestCryptoRandIDGenerator_DefaultPrefixes(t *testing.T) {
	g := newCryptoRandIDGenerator("", "")
	id, err := g.NewRequestID()
	if err != nil {
		t.Fatalf("NewRequestID: %v", err)
	}
	if !strings.HasPrefix(string(id), "xcc-req-") {
		t.Errorf("default request prefix: got %s", id)
	}
	id2, err := g.NewDecisionID()
	if err != nil {
		t.Fatalf("NewDecisionID: %v", err)
	}
	if !strings.HasPrefix(string(id2), "xcc-dec-") {
		t.Errorf("default decision prefix: got %s", id2)
	}
}

// --- freshNonceSource ----------------------------------------------

func TestFreshNonceSource_FreshPerCall(t *testing.T) {
	src := freshNonceSource()
	a, err := src(16)
	if err != nil {
		t.Fatalf("nonce(16): %v", err)
	}
	b, err := src(16)
	if err != nil {
		t.Fatalf("nonce(16) #2: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("two consecutive nonce calls must not return the same bytes")
	}
	if len(a) != 16 || len(b) != 16 {
		t.Errorf("len(a)=%d len(b)=%d; want 16", len(a), len(b))
	}
}

// --- LoadCrossCloudMaterials populates new fields ------------------

func TestLoadCrossCloudMaterials_PopulatesAuditAndIDGen(t *testing.T) {
	dir := t.TempDir()
	pubPath := writeFile(t, dir, "attestor.pub", generateEd25519PubRaw(t))
	measHex := makeMeasurementHex(0x77)
	regJSON := `{
		"verifiers": [
			{
				"provider": "simulated",
				"attestor_pubkey_path": "` + pubPath + `",
				"expected_measurement_hex": "` + measHex + `"
			}
		]
	}`
	regPath := writeFile(t, dir, "registry.json", []byte(regJSON))
	allowJSON := `{
		"version": "xcc-test-v1",
		"allowed": {"simulated": ["` + measHex + `"]}
	}`
	allowPath := writeFile(t, dir, "allow.json", []byte(allowJSON))

	cfg := Config{
		CrossCloud: CrossCloudConfig{
			Enabled:               true,
			PolicyVersion:         "xcc-test-v1",
			PolicyAllowListPath:   allowPath,
			VerifierRegistryPath:  regPath,
			RequestTimeoutSeconds: 30,
			// The test destinations are simulated.
			InsecureSimulatedDestinations: true,
		},
	}
	withAuditLog(t, dir, &cfg)
	clock := shared_time.NewFakeClock(time.Now())
	materials, err := LoadCrossCloudMaterials(cfg, clock)
	if err != nil {
		t.Fatalf("LoadCrossCloudMaterials: %v", err)
	}
	if materials == nil {
		t.Fatal("LoadCrossCloudMaterials returned nil")
	}
	defer func() { _ = materials.Close() }()
	// Phase 4 expansion: AuditChain, AuditEmitter, IDGenerator,
	// NonceSource MUST all be wired.
	if materials.AuditChain == nil {
		t.Error("AuditChain not populated")
	}
	if materials.AuditEmitter == nil {
		t.Error("AuditEmitter not populated")
	}
	if materials.IDGenerator == nil {
		t.Error("IDGenerator not populated")
	}
	if materials.NonceSource == nil {
		t.Error("NonceSource not populated")
	}
	// Round-trip: emit one event through the wired emitter, confirm
	// it lands in the wired chain.
	if _, err := materials.AuditEmitter.Emit(
		audit_event.KindCrossCloudHandshakeInitiated,
		[]byte(`{"smoke":"test"}`),
		"", "", "",
	); err != nil {
		t.Fatalf("end-to-end Emit through wired emitter: %v", err)
	}
	if materials.AuditChain.Len() != 1 {
		t.Errorf("after Emit: chain.Len = %d; want 1", materials.AuditChain.Len())
	}
}

func TestLoadCrossCloudMaterials_NilClockRejected(t *testing.T) {
	cfg := Config{
		CrossCloud: CrossCloudConfig{
			Enabled:              true,
			PolicyVersion:        "v1",
			PolicyAllowListPath:  "/dev/null",
			VerifierRegistryPath: "/dev/null",
		},
	}
	_, err := LoadCrossCloudMaterials(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "clock required") {
		t.Fatalf("LoadCrossCloudMaterials(nil clock): err = %v", err)
	}
}
