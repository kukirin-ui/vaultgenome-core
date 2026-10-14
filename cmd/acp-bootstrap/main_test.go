// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	krt "github.com/vault-genome/vaultgenome-core/internal/contracts/key_release_token"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// --- material on disk ------------------------------------------------

type destination struct {
	dir       string
	seed      []byte
	authority *keys.InMemoryStore // the source authority's signing keystore
	authKID   ids.KeyID
}

// newDestination writes a TEE seed and the source authority's public
// key, as an operator would before starting acp-bootstrap.
func newDestination(t *testing.T) *destination {
	t.Helper()
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "tee_seed"), seed)

	store := keys.NewInMemoryStore(shared_time.NewSystemClock())
	kid := ids.KeyID("authority-1")
	vk, err := store.GenerateSigning(kid, keys.PurposeSigningAuthority)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "authority.pub"), vk.PublicKey)
	return &destination{dir: dir, seed: seed, authority: store, authKID: kid}
}

func (d *destination) config() Config {
	c := DefaultConfig()
	c.HTTP.ListenAddress = "127.0.0.1:0"
	c.Health.ListenAddress = "127.0.0.1:0"
	c.TEE.Provider = "simulated"
	c.TEE.InsecureSimulation = true
	c.TEE.SeedPath = filepath.Join(d.dir, "tee_seed")
	c.SourceAuthority = SourceAuthorityConfig{KeyID: string(d.authKID), PublicKeyPath: filepath.Join(d.dir, "authority.pub")}
	return c
}

func (d *destination) producer(t *testing.T) *tee.Simulated {
	t.Helper()
	p, err := tee.NewSimulated([]byte(DefaultConfig().TEE.WorkloadDescriptor), d.seed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- a running daemon and a real source-side coordinator -------------

type running struct {
	d       *daemon
	url     string
	stop    context.CancelFunc
	stopped chan struct{} // closed when serve returns
	err     error         // serve's result, valid once stopped is closed
}

func start(t *testing.T, cfg Config) *running {
	t.Helper()
	d, err := newDaemon(cfg, quietLog)
	if err != nil {
		t.Fatalf("newDaemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{d: d, stop: cancel, stopped: make(chan struct{})}
	scheme := "http"
	if cfg.HTTP.TLS.Enabled {
		scheme = "https"
	}
	r.url = scheme + "://" + d.apiLn.Addr().String()
	go func() {
		r.err = d.serve(ctx)
		close(r.stopped)
	}()
	t.Cleanup(func() {
		cancel()
		if !r.waitStopped() {
			t.Error("daemon did not stop")
		}
	})
	return r
}

func (r *running) waitStopped() bool {
	select {
	case <-r.stopped:
		return true
	case <-time.After(15 * time.Second):
		return false
	}
}

type noAudit struct{}

func (noAudit) Emit(audit_event.Kind, []byte, ids.SessionID, ids.ManifestID, ids.RequestID) (ids.AuditEventID, error) {
	return "audit-noop", nil
}

type seqIDs struct{ n int }

func (g *seqIDs) NewRequestID() (ids.RequestID, error) {
	g.n++
	return ids.RequestID(fmt.Sprintf("req-%d", g.n)), nil
}

func (g *seqIDs) NewDecisionID() (ids.DecisionID, error) {
	g.n++
	return ids.DecisionID(fmt.Sprintf("tok-%d", g.n)), nil
}

// restore runs one cross-cloud restore of dek (as "dek-1") from a real
// kms.Coordinator to the daemon at url, over client.
func restore(t *testing.T, dst *destination, url string, client *http.Client, bearer string, dek []byte) (kms.CoordinationResult, error) {
	t.Helper()
	p := dst.producer(t)
	registry, err := tee.NewRegistry([]tee.RegistrySpec{{
		Provider: tee.ProviderSimulated,
		Spec:     tee.VerifierSpec{Provider: tee.ProviderSimulated, AttestorPubKey: p.PublicKey(), ExpectedMeasurement: p.Measurement()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := kms.NewAllowListPolicy("drill-policy-v1", map[tee.Provider][][]byte{tee.ProviderSimulated: {p.Measurement()}})
	if err != nil {
		t.Fatal(err)
	}
	coord, err := kms.NewCoordinator(kms.Config{
		AuditChain:   noAudit{},
		Signer:       dst.authority,
		Verifiers:    registry,
		Policy:       policy,
		Transport:    kms.NewHTTPTransport(kms.HTTPTransportConfig{HTTPClient: client, BearerToken: bearer, RequestTimeout: 10 * time.Second}),
		IDGenerator:  &seqIDs{},
		NonceSource:  func(n int) ([]byte, error) { b := make([]byte, n); _, err := rand.Read(b); return b, err },
		Clock:        shared_time.NewSystemClock(),
		SigningKeyID: dst.authKID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coord.CoordinateRestore(context.Background(), kms.CoordinationRequest{
		DecisionID:          "decision-1",
		DestinationKind:     tee.ProviderSimulated,
		DestinationEndpoint: url,
		KeysToRelease:       []kms.KeyMaterial{{KeyID: "dek-1", Purpose: krt.PurposeSealing, Plaintext: dek}},
	})
}

func requireRegistered(t *testing.T, d *daemon, kid ids.KeyID) {
	t.Helper()
	if _, _, err := d.keystore.Seal(kid, []byte("ping"), nil); err != nil {
		t.Fatalf("DEK %s not registered at the destination: %v", kid, err)
	}
}

// --- end to end --------------------------------------------------------

// A loopback destination completes a restore end to end: the DEK arrives,
// encapsulated to the key the destination attested, and lands in its
// keystore; the health listener answers; shutdown is clean.
func TestDaemon_LoopbackRestoreEndToEnd(t *testing.T) {
	dst := newDestination(t)
	r := start(t, dst.config())

	res, err := restore(t, dst, r.url, http.DefaultClient, "", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(res.RecipientKeySHA256) != 32 {
		t.Fatalf("restore result lacks the recipient key digest: %+v", res)
	}
	requireRegistered(t, r.d, "dek-1")
	if n := r.d.receiver.Outstanding(); n != 0 {
		t.Fatalf("%d handshake keys still outstanding after the token was used", n)
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get("http://" + r.d.healthLn.Addr().String() + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: HTTP %d", path, resp.StatusCode)
		}
	}

	r.stop()
	if !r.waitStopped() {
		t.Fatal("daemon did not stop on cancel")
	}
	if r.err != nil {
		t.Fatalf("serve returned %v on shutdown", r.err)
	}
}

// Beyond loopback: TLS 1.3, a client certificate, and a bearer token.
// Each missing piece is refused; with all of them the restore completes.
func TestDaemon_MutualTLSAndTokenEndToEnd(t *testing.T) {
	dst := newDestination(t)
	pki := newPKI(t, dst.dir)
	token := strongToken()

	cfg := dst.config()
	cfg.HTTP.TLS = TLSServerConfig{Enabled: true, ServerCert: pki.serverCert, ServerKey: pki.serverKey, ClientCAs: pki.caCert}
	cfg.HTTP.BearerTokenFile = filepath.Join(dst.dir, "api_token")
	writeFile(t, cfg.HTTP.BearerTokenFile, []byte(token+"\n"))
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ResolveSecrets(); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)
	dek := []byte("fedcba9876543210fedcba9876543210")

	if _, err := restore(t, dst, r.url, pki.client(t, false, tls.VersionTLS13), token, dek); err == nil {
		t.Fatal("a caller without a client certificate completed a restore")
	}
	if _, err := restore(t, dst, r.url, pki.client(t, true, tls.VersionTLS13), "", dek); err == nil {
		t.Fatal("a caller without the bearer token completed a restore")
	}
	if _, err := restore(t, dst, r.url, pki.client(t, true, tls.VersionTLS12), token, dek); err == nil {
		t.Fatal("a TLS 1.2 caller completed a restore")
	}
	if _, err := restore(t, dst, r.url, pki.client(t, true, tls.VersionTLS13), token, dek); err != nil {
		t.Fatalf("restore with client certificate and token: %v", err)
	}
	requireRegistered(t, r.d, "dek-1")
}

func TestNewDaemon_FailsFastOnBadMaterial(t *testing.T) {
	dst := newDestination(t)
	cases := map[string]func(*Config){
		"missing seed":      func(c *Config) { c.TEE.SeedPath = filepath.Join(dst.dir, "absent") },
		"missing authority": func(c *Config) { c.SourceAuthority.PublicKeyPath = filepath.Join(dst.dir, "absent") },
		"hardware provider": func(c *Config) { c.TEE.Provider = string(tee.ProviderGCPSEVSNP) },
		"bad tls material": func(c *Config) {
			c.HTTP.TLS = TLSServerConfig{Enabled: true, ServerCert: filepath.Join(dst.dir, "absent.crt"), ServerKey: filepath.Join(dst.dir, "absent.key")}
		},
		"busy port": func(c *Config) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			c.HTTP.ListenAddress = ln.Addr().String()
		},
		"busy health port": func(c *Config) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			c.Health.ListenAddress = ln.Addr().String()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := dst.config()
			mutate(&cfg)
			if d, err := newDaemon(cfg, quietLog); err == nil {
				_ = d.apiLn.Close()
				t.Fatal("newDaemon accepted bad material")
			}
		})
	}
}

func TestRun_RefusesBadInvocations(t *testing.T) {
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "-config is required") {
		t.Fatalf("run without -config: %v", err)
	}
	if err := run([]string{"-config", filepath.Join(t.TempDir(), "absent.json")}); err == nil {
		t.Fatal("run with a missing config file succeeded")
	}
	bad := filepath.Join(t.TempDir(), "open.json")
	b, _ := json.Marshal(map[string]any{
		"http":             map[string]any{"listen_address": "0.0.0.0:8443"},
		"source_authority": map[string]any{"kid": "k", "public_key_path": "/p"},
		"tee":              map[string]any{"provider": "simulated", "insecure_simulation": true, "workload_descriptor": "w", "seed_path": "/s"},
	})
	writeFile(t, bad, b)
	if err := run([]string{"-config", bad}); err == nil || !strings.Contains(err.Error(), "http.tls.enabled required") {
		t.Fatalf("run with an exposed plaintext listener: %v", err)
	}
	if err := run([]string{"-bogus"}); err == nil {
		t.Fatal("run accepted an unknown flag")
	}
}

// --- loaders -----------------------------------------------------------

func TestLoadAttestorPubKey(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "raw")
	writeFile(t, raw, pub)
	if got, err := loadAttestorPubKey(raw); err != nil || string(got) != string(pub) {
		t.Fatalf("raw key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(dir, "pem")
	writeFile(t, pemPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if got, err := loadAttestorPubKey(pemPath); err != nil || string(got) != string(pub) {
		t.Fatalf("PEM key: %v", err)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"ecdsa":       pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}),
		"broken pem":  []byte("-----BEGIN PUBLIC KEY-----\nnot base64\n"),
		"garbage der": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")}),
		"short raw":   pub[:31],
	} {
		p := filepath.Join(dir, name)
		writeFile(t, p, content)
		if _, err := loadAttestorPubKey(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := loadAttestorPubKey(filepath.Join(dir, "absent")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestPubkeyResolver(t *testing.T) {
	r := &pubkeyResolver{kid: "k1", purpose: keys.PurposeSigningAuthority, pub: make([]byte, 32)}
	if _, err := r.Resolve("k1", keys.PurposeSigningAuthority); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve("k2", keys.PurposeSigningAuthority); err == nil {
		t.Fatal("unknown kid resolved")
	}
	if _, err := r.Resolve("k1", keys.PurposeSigningAuthority+1); err == nil {
		t.Fatal("wrong purpose resolved")
	}
}

func TestReadExactly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	writeFile(t, p, make([]byte, 32))
	if _, err := readExactly(p, 32, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := readExactly(p, 31, "k"); err == nil {
		t.Fatal("wrong size accepted")
	}
	if _, err := readExactly("", 32, "k"); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := readExactly(filepath.Join(dir, "absent"), 32, "k"); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestBuildLogger(t *testing.T) {
	for _, c := range []LogConfig{{Level: "debug", Format: "text"}, {Level: "warn", Format: "json"}, {Level: "error"}, {Level: "info"}} {
		if buildLogger(c) == nil {
			t.Fatalf("buildLogger(%+v) = nil", c)
		}
	}
}

// --- TLS -------------------------------------------------------------

type pki struct {
	caCert, serverCert, serverKey string
	ca                            *x509.Certificate
	caKey                         *ecdsa.PrivateKey
	pool                          *x509.CertPool
}

// newPKI writes a throwaway CA and a server certificate for 127.0.0.1.
func newPKI(t *testing.T, dir string) *pki {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "drill-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	p := &pki{
		caCert: filepath.Join(dir, "ca.crt"), serverCert: filepath.Join(dir, "server.crt"), serverKey: filepath.Join(dir, "server.key"),
		ca: ca, caKey: caKey, pool: x509.NewCertPool(),
	}
	p.pool.AddCert(ca)
	writeFile(t, p.caCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	certPEM, keyPEM := p.issue(t, "acp-bootstrap", x509.ExtKeyUsageServerAuth)
	writeFile(t, p.serverCert, certPEM)
	writeFile(t, p.serverKey, keyPEM)
	return p
}

func (p *pki) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// client trusts the drill CA, presents a client certificate when
// withCert, and speaks at most maxVersion.
func (p *pki) client(t *testing.T, withCert bool, maxVersion uint16) *http.Client {
	t.Helper()
	cfg := &tls.Config{RootCAs: p.pool, MaxVersion: maxVersion, MinVersion: tls.VersionTLS12}
	if withCert {
		certPEM, keyPEM := p.issue(t, "sagvd", x509.ExtKeyUsageClientAuth)
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func TestBuildHTTPServer_RejectsUnusableClientCAs(t *testing.T) {
	dst := newDestination(t)
	p := newPKI(t, dst.dir)
	notPEM := filepath.Join(dst.dir, "not.pem")
	writeFile(t, notPEM, []byte("no certificates here"))
	for name, cas := range map[string]string{"no PEM": notPEM, "missing": filepath.Join(dst.dir, "absent.pem")} {
		t.Run(name, func(t *testing.T) {
			cfg := HTTPConfig{ListenAddress: "127.0.0.1:0", TLS: TLSServerConfig{Enabled: true, ServerCert: p.serverCert, ServerKey: p.serverKey, ClientCAs: cas}}
			if _, ln, err := buildHTTPServer(TEEConfig{}, cfg, http.NewServeMux(), quietLog); err == nil {
				_ = ln.Close()
				t.Fatal("accepted")
			}
		})
	}
}

// identity prints exactly what the source pins: the measurement and the
// attestation key a verifier accepts this destination's Evidence under.
func TestIdentity_PrintsWhatTheSourcePins(t *testing.T) {
	dst := newDestination(t)
	cfgPath := filepath.Join(dst.dir, "config.json")
	b, err := json.Marshal(dst.config())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgPath, b)

	var out strings.Builder
	if err := runIdentity([]string{"-config", cfgPath}, &out); err != nil {
		t.Fatal(err)
	}
	var id destinationIdentity
	if err := json.Unmarshal([]byte(out.String()), &id); err != nil {
		t.Fatalf("identity output is not JSON: %v\n%s", err, out.String())
	}
	p := dst.producer(t)
	if id.TEEProvider != "simulated" || !id.InsecureSimulation || id.MeasurementHex != fmt.Sprintf("%x", p.Measurement()) {
		t.Fatalf("identity %+v does not match the producer", id)
	}
	pemPath := filepath.Join(dst.dir, "attestor.pem")
	writeFile(t, pemPath, []byte(id.AttestorPublicKeyPEM))
	pub, err := loadAttestorPubKey(pemPath)
	if err != nil || string(pub) != string(p.PublicKey()) {
		t.Fatalf("printed attestor key does not load back as the producer's key: %v", err)
	}

	if err := runIdentity(nil, io.Discard); err == nil {
		t.Fatal("identity without -config succeeded")
	}
	bad := filepath.Join(dst.dir, "bad.json")
	writeFile(t, bad, []byte(`{"tee":{"provider":"nope"}}`))
	if err := runIdentity([]string{"-config", bad}, io.Discard); err == nil {
		t.Fatal("identity with an invalid config succeeded")
	}
}
