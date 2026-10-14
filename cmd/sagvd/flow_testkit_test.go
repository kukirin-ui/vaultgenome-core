// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/incident"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// testAuthority is an orchestration Authority wired the way runDaemon
// wires it: the authority key and the session-sealing key in one store,
// the audit log's chain and key behind it. With a nil audit the chain is
// in memory under a fresh audit key.
type testAuthority struct {
	authority *orchestration.Authority
	store     *keys.InMemoryStore
	authKID   ids.KeyID
	sealKID   ids.KeyID
	chain     chain.Chain
	auditKeys keys.Resolver
	clock     shared_time.Clock
}

func newTestAuthority(t *testing.T, audit *returnPathAudit) *testAuthority {
	t.Helper()
	clock := shared_time.NewSystemClock()
	store := keys.NewInMemoryStore(clock)
	authKID := ids.KeyID("authority-test-1")
	_, err := store.RegisterSigningFromSeed(authKID, keys.PurposeSigningAuthority, bytes.Repeat([]byte{7}, crypto.Ed25519SeedSize))
	require.NoError(t, err)
	sealKID := testRegisterSealing(t, store)

	ta := &testAuthority{store: store, authKID: authKID, sealKID: sealKID, clock: clock}
	var auditSigner keys.Signer
	var auditKID ids.KeyID
	if audit != nil {
		ta.chain, auditSigner, auditKID, ta.auditKeys = audit.Chain(), audit.Signer(), audit.KeyID(), audit.keys
	} else {
		ks := keys.NewInMemoryStore(clock)
		auditKID = "audit-mem-1"
		_, err := ks.GenerateSigning(auditKID, keys.PurposeSigningAudit)
		require.NoError(t, err)
		ta.chain, auditSigner, ta.auditKeys = chain.NewInMemoryChain(), ks, ks
	}
	ta.authority, err = orchestration.NewAuthority(orchestration.AuthorityOptions{
		Clock: clock, Signer: store, Sealer: store, Resolver: store, AuthorityKeyID: authKID, RecipientKeyID: sealKID,
		Audit: ta.chain, AuditSigner: auditSigner, AuditKeyID: auditKID,
		PolicyVersion: ids.PolicyVersion(DefaultConfig().PolicyVersion()), Profiles: []string{PolicyProfileGate},
		Zeroizer: incident.ZeroizerFunc(func() {}),
	})
	require.NoError(t, err)
	return ta
}

// request is a well-formed RecoveryRequest for genomeID.
func (ta *testAuthority) request(requestID, genomeID string) recovery_request.RecoveryRequest {
	return recovery_request.RecoveryRequest{
		SchemaVersion: recovery_request.SchemaVersionCurrent, RequestID: ids.RequestID(requestID), GenomeID: ids.GenomeID(genomeID),
		PolicyProfile: PolicyProfileGate, RequesterIdentity: "operator:test", CreatedAt: ta.clock.Now(),
	}
}

// flow admits a request for genomeID at intake and returns its flow.
func (ta *testAuthority) flow(t *testing.T, requestID, genomeID string) *orchestration.Flow {
	t.Helper()
	f, err := ta.authority.Intake(ta.request(requestID, genomeID), nil)
	require.NoError(t, err)
	return f
}

// testInfo is a genomeInfo a queue test can carry without a bundle.
func testInfo(genomeID string) genomeInfo {
	return genomeInfo{
		Ref:  genomeRef{Bundle: "gen-0.genome", KeyFile: "gen-0.key"},
		View: GenomeView{Bundle: "gen-0.genome", KeyID: genomeID, KeySource: "key_file", Fixtures: 3, Critical: 2, Files: 4, Bytes: 100},
		Gate: &gateSpec{GenomeID: genomeID}, Budget: 666, GenomeID: genomeID, BundleSHA256: strings.Repeat("ab", 32),
	}
}

// aMinute is the deadline queue tests give a job.
const aMinute = time.Minute

// trustPeer is an attested simulated peer, as the handshake reports it.
func trustPeer() trust.Peer {
	return trust.Peer{Provider: tee.ProviderSimulated, Measurement: bytes.Repeat([]byte{0xcd}, 32), RemoteAddr: "127.0.0.1:9", EvidenceAt: time.Now()}
}

// testRegisterSealing registers a fresh 32-byte AES-256 sealing
// material under a deterministic kid so sealing round-trips have
// something to work against.
func testRegisterSealing(t *testing.T, store *keys.InMemoryStore) ids.KeyID {
	t.Helper()
	kid := ids.KeyID("test-sealing-kid-1")
	material := make([]byte, 32)
	// Deterministic-but-non-zero pattern; keystore copies it
	// defensively so wiping our caller-side buffer is a no-op.
	for i := range material {
		material[i] = byte(i ^ 0xA5)
	}
	if err := store.RegisterSealing(kid, material); err != nil {
		t.Fatalf("RegisterSealing: %v", err)
	}
	return kid
}
