// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/compute/worker"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// tlsMaterial is a throwaway PKI for one test: a CA, a server certificate
// for 127.0.0.1 and a client certificate, the client's half on disk the
// way the operator provisions it.
type tlsMaterial struct {
	caPEM      string // the CA bundle file
	clientCert string
	clientKey  string
	server     tls.Certificate
	caPool     *x509.CertPool
}

func newTLSMaterial(t *testing.T, dir string) tlsMaterial {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acp-compute test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leaf := func(name string, usage x509.ExtKeyUsage, ips []net.IP) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: ips,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		require.NoError(t, err)
		return pair, certPEM, keyPEM
	}
	server, _, _ := leaf("vault", x509.ExtKeyUsageServerAuth, []net.IP{net.IPv4(127, 0, 0, 1)})
	_, clientPEM, clientKeyPEM := leaf("worker", x509.ExtKeyUsageClientAuth, nil)

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return tlsMaterial{
		caPEM:      write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		clientCert: write("client.crt", clientPEM),
		clientKey:  write("client.key", clientKeyPEM),
		server:     server,
		caPool:     pool,
	}
}

// A vault that speaks TLS: accepts, completes the handshake and hangs up.
// Returns the address; the listener closes with the test.
func hangUpTLSVault(t *testing.T, m tlsMaterial) string {
	t.Helper()
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{m.server}, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = c.Close()
			}(c)
		}
	}()
	return lis.Addr().String()
}

func tlsDaemon(t *testing.T, f *testFixture) *Daemon {
	t.Helper()
	mat, err := LoadMaterials(f.cfg, f.clock)
	require.NoError(t, err)
	recon, err := worker.NewDeterministicReconstructor(f.clock)
	require.NoError(t, err)
	d, err := NewDaemon(f.cfg, mat, f.clock, silentLogger(), recon, NewRegistry())
	require.NoError(t, err)
	return d
}

// With TLS on, the daemon loads the operator's client material, pins the
// CA bundle and speaks TLS 1.3 only; the dialer and health state it
// exposes are the ones the daemon runs with.
func TestNewDaemon_TLSEnabled_LoadsTheClientMaterial(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	m := newTLSMaterial(t, f.dir)
	f.cfg.Vault.TLS = TLSConfig{Enabled: true, ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: m.caPEM, ServerName: "127.0.0.1"}
	require.NoError(t, f.cfg.Validate())
	d := tlsDaemon(t, f)
	require.NotNil(t, d.tlsConfig)
	require.EqualValues(t, tls.VersionTLS13, d.tlsConfig.MinVersion)
	require.Equal(t, "127.0.0.1", d.tlsConfig.ServerName)
	require.Len(t, d.tlsConfig.Certificates, 1)
	require.NotNil(t, d.Health())
	before := d.dialer
	require.Same(t, d, d.WithDialer(nil))
	require.Equal(t, before, d.dialer, "a nil dialer changes nothing")
}

// The worker dials a vault it can verify — and refuses one it cannot: a
// vault under another CA is an error at the handshake, before a byte of
// the Return Path is spoken.
func TestDaemon_DialTLS_VerifiesTheVault(t *testing.T) {
	t.Parallel()
	f := newTestFixture(t)
	m := newTLSMaterial(t, f.dir)
	addr := hangUpTLSVault(t, m)
	f.cfg.Vault.Address = addr
	f.cfg.Vault.TLS = TLSConfig{Enabled: true, ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: m.caPEM, ServerName: "127.0.0.1"}
	require.NoError(t, f.cfg.Validate())
	d := tlsDaemon(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), daemonTestTimeout)
	defer cancel()
	conn, err := d.dial(ctx)
	require.NoError(t, err)
	_, isTLS := conn.(*tls.Conn)
	require.True(t, isTLS, "the connection to the vault is TLS")
	_ = conn.Close()

	// Another CA signed the vault's certificate: the worker hangs up.
	other := newTLSMaterial(t, t.TempDir())
	f.cfg.Vault.TLS.CABundle = other.caPEM
	stranger := tlsDaemon(t, f)
	_, err = stranger.dial(ctx)
	require.Error(t, err)
	var unknown x509.UnknownAuthorityError
	require.True(t, errors.As(err, &unknown), "want an unknown-authority refusal, got %v", err)
}

func TestLoadClientTLS_Refusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m := newTLSMaterial(t, dir)
	garbage := filepath.Join(dir, "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a certificate\n"), 0o600))
	empty := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))

	for name, tc := range map[string]struct {
		cfg  TLSConfig
		want string
	}{
		"missing keypair": {TLSConfig{ClientCert: filepath.Join(dir, "no.crt"), ClientKey: m.clientKey, CABundle: m.caPEM}, "load client keypair"},
		"missing bundle":  {TLSConfig{ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: filepath.Join(dir, "no.pem")}, "read CA bundle"},
		"garbage bundle":  {TLSConfig{ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: garbage}, "no valid PEM certificates"},
		"empty bundle":    {TLSConfig{ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: empty}, "CA bundle empty"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadClientTLS(TEEConfig{}, tc.cfg)
			require.ErrorContains(t, err, tc.want)
		})
	}
	pool, err := newCertPool(nil)
	require.Nil(t, pool)
	require.ErrorContains(t, err, "empty")
}

// The metric label a failed job carries follows the error's category:
// what the worker rejected is "reject", what broke is "fail".
func TestJobOutcomeFromError(t *testing.T) {
	t.Parallel()
	cause := errors.New("cause")
	for _, tc := range []struct {
		err  error
		want string
	}{
		{shared_errors.Operational("deadline", "manifest deadline passed", cause), "reject"},
		{shared_errors.Structural("frame", "malformed frame", cause), "reject"},
		{shared_errors.Authority("denied", "policy denied", cause), "fail"},
		{shared_errors.Integrity("hash", "hash mismatch", cause), "fail"},
		{shared_errors.Incident("incident", "incident", cause), "fail"},
		{errors.New("unclassified"), "fail"},
	} {
		require.Equal(t, tc.want, jobOutcomeFromError(tc.err), "%v", tc.err)
	}
}
