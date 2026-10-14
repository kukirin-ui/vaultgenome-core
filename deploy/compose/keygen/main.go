// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command keygen provisions every piece of key material the sagvd +
// acp-compute deployment in deploy/compose needs: simulated-TEE seeds,
// signing keys, the pre-shared session sealing key, a private mTLS PKI
// for the Return Path, and the operator REST API bearer token.
//
// # What it writes (under -out, default deploy/compose/secrets)
//
//	shared/
//	  sealing.key               32 B AES-256 session sealing key (pre-shared)
//	  workers.json              worker signing registry consumed by sagvd
//	  tls/ca.crt                private CA certificate, trusted by both sides
//	sagvd/
//	  tee_seed                  32 B Ed25519 seed (vault simulated TEE)
//	  authority_signing_seed    32 B Ed25519 seed (authority signing)
//	  audit_signing_seed        32 B Ed25519 seed (cross-cloud audit log)
//	  peer_worker_pubkey        32 B Ed25519 public key (pinned worker TEE)
//	  peer_worker_measurement   32 B SHA-256 (pinned worker workload)
//	  api_token                 REST API bearer token (64 hex chars, 128+ bits)
//	  tls/server.crt|.key       Return Path server certificate (ECDSA P-256)
//	acp-compute/
//	  tee_seed                  32 B Ed25519 seed (worker simulated TEE)
//	  worker_signing_seed       32 B Ed25519 seed (CandidateOutput signing)
//	  peer_vault_pubkey         32 B Ed25519 public key (pinned vault TEE)
//	  peer_vault_measurement    32 B SHA-256 (pinned vault workload)
//	  tls/client.crt|.key       Return Path client certificate (ECDSA P-256)
//
// The CA private key signs the two leaf certificates in memory and is
// never written to disk: rotating the PKI means re-running keygen with
// -force. The server certificate names the Compose service ("sagvd",
// which acp-compute verifies as tls.server_name) and the loopback
// addresses, so the same tree serves a containerised run and a
// single-host run (bare-metal demo, integration tests).
//
// The two workload-descriptor strings MUST match tee.workload_descriptor
// in sagvd/config.json and acp-compute/config.json: peer measurements are
// SHA-256 of those strings (the derivation tee.MeasurementOf uses), so a
// mismatch fails every handshake Authority-classified.
//
// # Usage
//
//	cd deploy/compose/keygen && go run . -out ../secrets
//
// keygen refuses to overwrite an existing tree unless -force is passed:
// regenerating secrets under a running pair desynchronises it (sealed
// material stops opening, TEE evidence stops pinning, TLS stops
// verifying).
//
// # Security posture
//
// LOCAL DEPLOYMENT ONLY. Files are written 0644 and directories 0755
// because the daemons run in distroless containers as uid 65532 and read
// this tree through a read-only bind mount that preserves host
// ownership; a 0600 file owned by the operator would be unreadable to the
// container user. The tree is git-ignored and docker-ignored. A
// production deployment does not use this tool: its key material comes
// from a secrets manager, and its TEE keys are generated inside attested
// hardware rather than on the operator's disk.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Canonical workload descriptors and key IDs. See the package comment
// for the files these must stay in lock-step with.
const (
	vaultWorkloadDescriptor  = "sagvd-phase1-demo-v1"
	workerWorkloadDescriptor = "acp-compute-phase1-demo-v1"

	// session_sealing.kid MUST be identical across both daemons (sagvd
	// writes it into JobRequest.SealedMaterialRef.RecipientKeyID;
	// acp-compute's Opener resolves the same kid from its keystore).
	kidAuthoritySigning = "sagvd-authority-demo"
	kidSessionSealing   = "session-sealing-demo"
	kidWorkerSigning    = "acp-compute-worker-demo"

	// TLS identities: vaultTLSName is what acp-compute dials and
	// verifies (tls.server_name); workerTLSName is the client identity.
	vaultTLSName  = "sagvd"
	workerTLSName = "acp-compute"

	leafValidity = 365 * 24 * time.Hour
	caValidity   = leafValidity + 24*time.Hour
	clockSkew    = 5 * time.Minute
)

type layout struct {
	root string

	sharedDir, sagvdDir, workerDir          string
	sharedTLSDir, sagvdTLSDir, workerTLSDir string

	sealingKey  string // shared/sealing.key
	workersJSON string // shared/workers.json
	caCert      string // shared/tls/ca.crt

	sagvdTEESeed              string
	sagvdAuthoritySigningSeed string
	sagvdAuditSigningSeed     string
	sagvdPeerWorkerPubkey     string
	sagvdPeerWorkerMeasure    string
	sagvdAPIToken             string
	sagvdTLSCert              string
	sagvdTLSKey               string

	workerTEESeed         string
	workerSigningSeed     string
	workerPeerVaultPubkey string
	workerPeerVaultMeas   string
	workerTLSCert         string
	workerTLSKey          string
}

func newLayout(root string) layout {
	l := layout{
		root:      root,
		sharedDir: filepath.Join(root, "shared"),
		sagvdDir:  filepath.Join(root, "sagvd"),
		workerDir: filepath.Join(root, "acp-compute"),
	}
	l.sharedTLSDir = filepath.Join(l.sharedDir, "tls")
	l.sagvdTLSDir = filepath.Join(l.sagvdDir, "tls")
	l.workerTLSDir = filepath.Join(l.workerDir, "tls")

	l.sealingKey = filepath.Join(l.sharedDir, "sealing.key")
	l.workersJSON = filepath.Join(l.sharedDir, "workers.json")
	l.caCert = filepath.Join(l.sharedTLSDir, "ca.crt")

	l.sagvdTEESeed = filepath.Join(l.sagvdDir, "tee_seed")
	l.sagvdAuthoritySigningSeed = filepath.Join(l.sagvdDir, "authority_signing_seed")
	l.sagvdAuditSigningSeed = filepath.Join(l.sagvdDir, "audit_signing_seed")
	l.sagvdPeerWorkerPubkey = filepath.Join(l.sagvdDir, "peer_worker_pubkey")
	l.sagvdPeerWorkerMeasure = filepath.Join(l.sagvdDir, "peer_worker_measurement")
	l.sagvdAPIToken = filepath.Join(l.sagvdDir, "api_token")
	l.sagvdTLSCert = filepath.Join(l.sagvdTLSDir, "server.crt")
	l.sagvdTLSKey = filepath.Join(l.sagvdTLSDir, "server.key")

	l.workerTEESeed = filepath.Join(l.workerDir, "tee_seed")
	l.workerSigningSeed = filepath.Join(l.workerDir, "worker_signing_seed")
	l.workerPeerVaultPubkey = filepath.Join(l.workerDir, "peer_vault_pubkey")
	l.workerPeerVaultMeas = filepath.Join(l.workerDir, "peer_vault_measurement")
	l.workerTLSCert = filepath.Join(l.workerTLSDir, "client.crt")
	l.workerTLSKey = filepath.Join(l.workerTLSDir, "client.key")
	return l
}

func (l layout) dirs() []string {
	return []string{
		l.sharedDir, l.sagvdDir, l.workerDir,
		l.sharedTLSDir, l.sagvdTLSDir, l.workerTLSDir,
	}
}

func (l layout) files() []string {
	return []string{
		l.sealingKey, l.workersJSON, l.caCert,
		l.sagvdTEESeed, l.sagvdAuthoritySigningSeed, l.sagvdAuditSigningSeed,
		l.sagvdPeerWorkerPubkey, l.sagvdPeerWorkerMeasure,
		l.sagvdAPIToken, l.sagvdTLSCert, l.sagvdTLSKey,
		l.workerTEESeed, l.workerSigningSeed,
		l.workerPeerVaultPubkey, l.workerPeerVaultMeas,
		l.workerTLSCert, l.workerTLSKey,
	}
}

// workersRegistry mirrors cmd/sagvd/workers.go:WorkerRegistryFile — a
// divergence here silently breaks sagvd startup.
type workersRegistry struct {
	Workers []workerEntry `json:"workers"`
}

type workerEntry struct {
	KeyID               string `json:"kid"`
	SigningPublicKeyHex string `json:"signing_pubkey_hex"`
	Note                string `json:"note,omitempty"`
}

func main() {
	var (
		outDir = flag.String("out", "deploy/compose/secrets",
			"output directory for the secrets tree")
		force = flag.Bool("force", false,
			"overwrite any existing files under -out")
		quiet = flag.Bool("quiet", false,
			"suppress non-error stdout")
	)
	flag.Parse()

	if err := run(*outDir, *force, *quiet); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
}

func run(outDir string, force, quiet bool) error {
	lo := newLayout(outDir)
	if err := preflight(lo, force); err != nil {
		return err
	}
	for _, d := range lo.dirs() {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
		// MkdirAll leaves a pre-existing directory's mode alone; force
		// it so a -force re-run cannot produce a mixed-permission tree.
		if err := os.Chmod(d, 0o755); err != nil {
			return fmt.Errorf("chmod %s: %w", d, err)
		}
	}

	seeds := make(map[string][]byte, 5)
	for _, name := range []string{"sagvdTEE", "sagvdAuthority", "sagvdAudit", "workerTEE", "workerSigning"} {
		b, err := randomBytes(ed25519.SeedSize)
		if err != nil {
			return err
		}
		seeds[name] = b
	}
	sealingKey, err := randomBytes(32)
	if err != nil {
		return err
	}
	tokenBytes, err := randomBytes(32)
	if err != nil {
		return err
	}
	apiToken := hex.EncodeToString(tokenBytes)

	// Each side pins the OTHER side's TEE public key: the Return Path
	// verifier rejects evidence signed by anything but the expected seed.
	sagvdTEEPub := ed25519.NewKeyFromSeed(seeds["sagvdTEE"]).Public().(ed25519.PublicKey)
	workerTEEPub := ed25519.NewKeyFromSeed(seeds["workerTEE"]).Public().(ed25519.PublicKey)
	workerSigningPub := ed25519.NewKeyFromSeed(seeds["workerSigning"]).Public().(ed25519.PublicKey)

	sagvdMeasurement := sha256.Sum256([]byte(vaultWorkloadDescriptor))
	workerMeasurement := sha256.Sum256([]byte(workerWorkloadDescriptor))

	pki, err := newPKI(time.Now())
	if err != nil {
		return err
	}

	reg := workersRegistry{Workers: []workerEntry{{
		KeyID:               kidWorkerSigning,
		SigningPublicKeyHex: hex.EncodeToString(workerSigningPub),
		Note:                "Local-deployment worker. Regenerate with deploy/compose/keygen -force.",
	}}}
	regBytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal workers.json: %w", err)
	}

	writes := []struct {
		path string
		data []byte
	}{
		{lo.sealingKey, sealingKey},
		{lo.workersJSON, append(regBytes, '\n')},
		{lo.caCert, pki.caPEM},

		{lo.sagvdTEESeed, seeds["sagvdTEE"]},
		{lo.sagvdAuthoritySigningSeed, seeds["sagvdAuthority"]},
		{lo.sagvdAuditSigningSeed, seeds["sagvdAudit"]},
		{lo.sagvdPeerWorkerPubkey, workerTEEPub},
		{lo.sagvdPeerWorkerMeasure, workerMeasurement[:]},
		{lo.sagvdAPIToken, []byte(apiToken + "\n")},
		{lo.sagvdTLSCert, pki.serverCertPEM},
		{lo.sagvdTLSKey, pki.serverKeyPEM},

		{lo.workerTEESeed, seeds["workerTEE"]},
		{lo.workerSigningSeed, seeds["workerSigning"]},
		{lo.workerPeerVaultPubkey, sagvdTEEPub},
		{lo.workerPeerVaultMeas, sagvdMeasurement[:]},
		{lo.workerTLSCert, pki.clientCertPEM},
		{lo.workerTLSKey, pki.clientKeyPEM},
	}
	for _, w := range writes {
		if err := writeBytes(w.path, w.data); err != nil {
			return err
		}
	}

	if !quiet {
		// Identity lines operators can eyeball against the daemons'
		// startup logs. The bearer token itself is never printed.
		fmt.Printf("keygen: wrote secrets under %q\n", outDir)
		fmt.Printf("  authority signing kid:       %s\n", kidAuthoritySigning)
		fmt.Printf("  session sealing kid:         %s\n", kidSessionSealing)
		fmt.Printf("  worker signing kid:          %s\n", kidWorkerSigning)
		fmt.Printf("  sagvd TEE pubkey:            %s\n", hex.EncodeToString(sagvdTEEPub))
		fmt.Printf("  worker TEE pubkey:           %s\n", hex.EncodeToString(workerTEEPub))
		fmt.Printf("  worker signing pubkey:       %s\n", hex.EncodeToString(workerSigningPub))
		fmt.Printf("  sagvd expected measurement:  %s\n", hex.EncodeToString(sagvdMeasurement[:]))
		fmt.Printf("  worker expected measurement: %s\n", hex.EncodeToString(workerMeasurement[:]))
		fmt.Printf("  mTLS: CA + server (%s, localhost, 127.0.0.1, ::1) + client (%s), valid %s\n",
			vaultTLSName, workerTLSName, leafValidity)
		fmt.Printf("  REST API bearer token:       %s (not printed)\n", lo.sagvdAPIToken)
	}
	return nil
}

// pkiMaterial is the PEM-encoded output of newPKI.
type pkiMaterial struct {
	caPEM                       []byte
	serverCertPEM, serverKeyPEM []byte
	clientCertPEM, clientKeyPEM []byte
}

// newPKI creates a private CA and issues the Return Path server and
// client certificates. The CA key exists only in memory.
func newPKI(now time.Time) (pkiMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("generate CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return pkiMaterial{}, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "acp-local-deployment-ca", Organization: []string{"AI Continuity Platform"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	serverCert, serverKey, err := issueLeaf(caCert, caKey, now, &x509.Certificate{
		Subject:     pkix.Name{CommonName: vaultTLSName},
		DNSNames:    []string{vaultTLSName, "localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("issue server certificate: %w", err)
	}
	clientCert, clientKey, err := issueLeaf(caCert, caKey, now, &x509.Certificate{
		Subject:     pkix.Name{CommonName: workerTLSName},
		DNSNames:    []string{workerTLSName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return pkiMaterial{}, fmt.Errorf("issue client certificate: %w", err)
	}
	return pkiMaterial{
		caPEM:         pemBlock("CERTIFICATE", caDER),
		serverCertPEM: serverCert,
		serverKeyPEM:  serverKey,
		clientCertPEM: clientCert,
		clientKeyPEM:  clientKey,
	}, nil
}

// issueLeaf signs tmpl with the CA and returns PEM certificate + PKCS#8
// private key.
func issueLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time, tmpl *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = now.Add(-clockSkew)
	tmpl.NotAfter = now.Add(leafValidity)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
}

// preflight enforces the -force requirement without touching the tree.
func preflight(lo layout, force bool) error {
	if _, err := os.Stat(lo.root); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", lo.root, err)
	}
	var found int
	for _, p := range lo.files() {
		if _, err := os.Stat(p); err == nil {
			found++
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}
	if found > 0 && !force {
		return fmt.Errorf(
			"refusing to overwrite existing secrets (%d files under %q); "+
				"re-run with -force to regenerate (this WILL desynchronise any running daemons)",
			found, lo.root)
	}
	return nil
}

// randomBytes returns n bytes from crypto/rand; failure is fatal rather
// than a fallback to weaker randomness.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

func randomSerial() (*big.Int, error) {
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certificate serial: %w", err)
	}
	return s, nil
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// writeBytes writes data with mode 0644, truncating any existing file,
// and re-applies the mode so a -force re-run cannot leave a stale one.
func writeBytes(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return f.Close()
}
