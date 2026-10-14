// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// materialFixture writes every file LoadMaterials reads, as the deploy
// keygen would, and returns a config pointing at them.
type materialFixture struct {
	dir      string
	cfg      Config
	authSeed []byte
	teeSeed  []byte
}

func newMaterialFixture(t *testing.T) *materialFixture {
	t.Helper()
	dir := t.TempDir()
	rnd := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	put := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	f := &materialFixture{dir: dir, authSeed: rnd(32), teeSeed: rnd(32)}
	workerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := json.Marshal(WorkerRegistryFile{Workers: []WorkerEntry{{KeyID: "worker-1", SigningPublicKeyHex: hex.EncodeToString(workerPub)}}})
	if err != nil {
		t.Fatal(err)
	}

	c := DefaultConfig()
	c.TEE.SeedPath = put("tee_seed", f.teeSeed)
	c.TEE.InsecureSimulation = true
	c.TEE.Peer.PublicKeyPath = put("peer_pub", rnd(32))
	c.TEE.Peer.MeasurementPath = put("peer_measurement", rnd(32))
	c.Keys.AuthoritySigning = SigningKeyConfig{KeyID: "authority-1", SeedPath: put("authority_seed", f.authSeed)}
	c.Keys.SessionSealing = SealingKeyConfig{KeyID: "sealing-1", MaterialPath: put("sealing.key", rnd(32))}
	c.Workers.RegistryPath = put("workers.json", registry)
	f.cfg = c
	return f
}

func (f *materialFixture) rewrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMaterials_Happy(t *testing.T) {
	f := newMaterialFixture(t)
	mat, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadMaterials: %v", err)
	}
	defer mat.Store.Zeroize()
	wantPub, _, _ := crypto.Ed25519FromSeed(f.authSeed)
	if mat.AuthoritySigningKeyID != "authority-1" || !bytes.Equal(mat.AuthoritySigningPublicKey, wantPub) {
		t.Fatalf("authority key: kid=%q pub=%x", mat.AuthoritySigningKeyID, mat.AuthoritySigningPublicKey)
	}
	if !mat.Producer.Measurement().Equal(tee.MeasurementOf([]byte(f.cfg.TEE.WorkloadDescriptor))) {
		t.Fatal("TEE producer measurement does not follow the workload descriptor")
	}
	if len(mat.WorkerEntries) != 1 || mat.WorkerResolver == nil {
		t.Fatalf("worker registry not loaded: %+v", mat.WorkerEntries)
	}
}

// A hardware worker's measurement (SEV-SNP, Nitro: 48 bytes) is pinned
// whole; a length no TEE reports is refused.
func TestLoadMaterials_PeerMeasurementLengths(t *testing.T) {
	for n, ok := range map[int]bool{32: true, 48: true, 64: true, 31: false, 33: false, 0: false} {
		f := newMaterialFixture(t)
		f.rewrite(t, f.cfg.TEE.Peer.MeasurementPath, make([]byte, n))
		_, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
		if (err == nil) != ok {
			t.Errorf("%d-byte peer measurement: err = %v, want ok=%v", n, err, ok)
		}
	}
}

func TestLoadMaterials_RefusesBadMaterial(t *testing.T) {
	cases := map[string]func(f *materialFixture){
		"short tee seed":       func(f *materialFixture) { f.rewrite(t, f.cfg.TEE.SeedPath, make([]byte, 31)) },
		"short peer key":       func(f *materialFixture) { f.rewrite(t, f.cfg.TEE.Peer.PublicKeyPath, make([]byte, 31)) },
		"short authority seed": func(f *materialFixture) { f.rewrite(t, f.cfg.Keys.AuthoritySigning.SeedPath, make([]byte, 31)) },
		"short sealing key":    func(f *materialFixture) { f.rewrite(t, f.cfg.Keys.SessionSealing.MaterialPath, make([]byte, 16)) },
		"missing measurement":  func(f *materialFixture) { f.cfg.TEE.Peer.MeasurementPath = filepath.Join(f.dir, "absent") },
		"empty registry":       func(f *materialFixture) { f.rewrite(t, f.cfg.Workers.RegistryPath, []byte(`{"workers":[]}`)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMaterialFixture(t)
			mutate(f)
			if _, err := LoadMaterials(f.cfg, shared_time.NewSystemClock()); err == nil {
				t.Fatal("LoadMaterials accepted bad material")
			}
		})
	}
}

// identity prints the authority key a destination pins as
// source_authority.public_key_path, in a form its loader accepts.
func TestIdentity_PrintsTheAuthorityKeyDestinationsPin(t *testing.T) {
	f := newMaterialFixture(t)
	b, err := json.Marshal(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(f.dir, "sagvd.json")
	f.rewrite(t, cfgPath, b)

	var out strings.Builder
	if err := runIdentityCmd([]string{"-config", cfgPath}, &out); err != nil {
		t.Fatal(err)
	}
	var id authorityIdentity
	if err := json.Unmarshal([]byte(out.String()), &id); err != nil {
		t.Fatalf("identity output is not JSON: %v\n%s", err, out.String())
	}
	wantPub, _, _ := crypto.Ed25519FromSeed(f.authSeed)
	block, _ := pem.Decode([]byte(id.AuthorityPublicKeyPEM))
	if block == nil {
		t.Fatalf("authority key is not PEM: %q", id.AuthorityPublicKeyPEM)
	}
	got, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil || !bytes.Equal(got.(ed25519.PublicKey), wantPub) {
		t.Fatalf("authority key does not round-trip: %v", err)
	}
	if id.AuthorityKID != "authority-1" || id.TEEMeasurementHex == "" || id.TEEPublicKeyPEM == "" {
		t.Fatalf("identity incomplete: %+v", id)
	}

	if err := runIdentityCmd(nil, io.Discard); err == nil {
		t.Fatal("identity without -config succeeded")
	}
	if err := runIdentityCmd([]string{"-config", filepath.Join(f.dir, "absent.json")}, io.Discard); err == nil {
		t.Fatal("identity with a missing config succeeded")
	}
}

// A SEV-SNP worker is pinned by its 48-byte launch measurement and the
// AMD chain its VCEK must chain to; the verifier is built without
// hardware, and identity names the vault's own provider.
func TestLoadMaterials_SEVSNPPeerVerifier(t *testing.T) {
	f := newMaterialFixture(t)
	chain := filepath.Join(f.dir, "amd-chain.pem")
	if err := os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.rewrite(t, f.cfg.TEE.Peer.MeasurementPath, bytes.Repeat([]byte{0x77}, 48))
	f.cfg.TEE.Peer = PeerTEEConfig{Provider: "gcp-sev-snp", MeasurementPath: f.cfg.TEE.Peer.MeasurementPath, AMDCertChainPath: chain}
	if err := f.cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	mat, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
	if err != nil {
		t.Fatalf("LoadMaterials: %v", err)
	}
	defer mat.Store.Zeroize()
	if mat.Provider != tee.ProviderSimulated || mat.PeerProvider != tee.ProviderGCPSEVSNP {
		t.Fatalf("providers: local %s, peer %s", mat.Provider, mat.PeerProvider)
	}
	if _, ok := mat.Verifier.(*tee.GCPSEVVerifier); !ok {
		t.Fatalf("verifier is %T, want the SEV-SNP verifier", mat.Verifier)
	}
	f.rewrite(t, f.cfg.TEE.Peer.MeasurementPath, bytes.Repeat([]byte{0x77}, 32))
	if _, err := LoadMaterials(f.cfg, shared_time.NewSystemClock()); err == nil || !strings.Contains(err.Error(), "48-byte SEV-SNP launch measurement") {
		t.Fatalf("a 32-byte measurement was accepted for a SEV-SNP peer: %v", err)
	}

	// Off a Confidential VM the SEV-SNP producer cannot start.
	g := newMaterialFixture(t)
	g.cfg.TEE = TEEConfig{Provider: "gcp-sev-snp", WorkloadDescriptor: "sagvd-sev", TSMReportDir: filepath.Join(g.dir, "no-tsm"), Peer: g.cfg.TEE.Peer}
	if err := g.cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, err := LoadMaterials(g.cfg, shared_time.NewSystemClock()); err == nil || !strings.Contains(err.Error(), "configfs-tsm") {
		t.Fatalf("SEV-SNP producer started without configfs-tsm: %v", err)
	}
}
