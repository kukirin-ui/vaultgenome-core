// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// selfSignedPair writes a self-signed ECDSA certificate and its key
// beside each other, and returns their paths.
func selfSignedPair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPath, keyPath = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// `sagvd seal-keys` seals the TLS server key and the REST API token too,
// and the daemon's loaders open them: the vault's mTLS listener, the
// REST token; a key sealed for the cross-cloud transport opens there and
// nowhere else; another host opens none of them.
func TestSealKeys_SealsTheTLSKeysAndTheTokenToo(t *testing.T) {
	f := newMaterialFixture(t)
	cfg := f.cfg
	serverCert, serverKey := selfSignedPair(t, f.dir, "vault")
	clientCert, clientKey := selfSignedPair(t, f.dir, "xcc-client")
	cfg.Vault.TLS = TLSConfig{Enabled: true, ServerCert: serverCert, ServerKey: serverKey, ClientCAs: serverCert}
	cfg.HTTPAPI.BearerTokenFile = filepath.Join(f.dir, "api_token")
	require.NoError(t, os.WriteFile(cfg.HTTPAPI.BearerTokenFile, []byte("  api-token-for-the-rest-endpoint-0123456789  \n"), 0o600))
	require.NoError(t, cfg.Validate())
	serverKeyPEM, err := os.ReadFile(serverKey)
	require.NoError(t, err)

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "sagvd.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))
	var stdout, stderr bytes.Buffer
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	var out sealKeysOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	names := make([]string, 0, len(out.Sealed))
	for _, e := range out.Sealed {
		names = append(names, e.Name)
	}
	require.Contains(t, names, "vault.tls.server_key")
	require.Contains(t, names, "http_api.bearer_token_file")
	require.NotContains(t, names, "crosscloud.transport_tls.client_key", "not configured, not sealed")
	sealedKey, err := os.ReadFile(serverKey)
	require.NoError(t, err)
	require.True(t, tee.IsSealedSecret(sealedKey))
	require.False(t, bytes.Contains(sealedKey, serverKeyPEM))

	// The daemon's loaders open the sealed files.
	tc, err := loadServerTLS(cfg.TEE, cfg.Vault.TLS)
	require.NoError(t, err)
	require.Len(t, tc.Certificates, 1)
	require.NoError(t, cfg.ResolveSecrets())
	require.Equal(t, "api-token-for-the-rest-endpoint-0123456789", cfg.HTTPAPI.BearerToken, "trimmed, from the sealed file")

	// A key sealed for the cross-cloud transport, by hand under its name,
	// opens for the transport; the vault's listener refuses it.
	sealer, closer, provider, err := hostSealer(cfg.TEE)
	require.NoError(t, err)
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	_, producer, err := buildTEEProducer(cfg.TEE)
	require.NoError(t, err)
	clientKeyPEM, err := os.ReadFile(clientKey)
	require.NoError(t, err)
	sealedClient, err := tee.SealSecret(clientKeyPEM, sealer, provider, producer.Measurement(), "crosscloud.transport_tls.client_key")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(clientKey, sealedClient, 0o600))
	ctc, err := buildClientTLSConfig(cfg.TEE, TLSClientConfig{Enabled: true, ClientCert: clientCert, ClientKey: clientKey, CABundle: serverCert})
	require.NoError(t, err)
	require.Len(t, ctc.Certificates, 1)
	_, err = loadServerTLS(cfg.TEE, TLSConfig{Enabled: true, ServerCert: clientCert, ServerKey: clientKey, ClientCAs: serverCert})
	require.Error(t, err, "a key sealed for the transport is not the vault's")
	require.Contains(t, err.Error(), "vault.tls.server_key")

	// Another host opens none of them.
	other := cfg
	other.TEE.WorkloadDescriptor = cfg.TEE.WorkloadDescriptor + "-elsewhere"
	_, err = loadServerTLS(other.TEE, other.Vault.TLS)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.tls.server_key")
	other.HTTPAPI.BearerToken = ""
	require.Error(t, other.ResolveSecrets())
	_, err = buildClientTLSConfig(other.TEE, TLSClientConfig{Enabled: true, ClientCert: clientCert, ClientKey: clientKey, CABundle: serverCert})
	require.Error(t, err)

	// A bare PEM key still loads (nothing sealed): the plain deployment.
	bareCert, bareKey := selfSignedPair(t, f.dir, "bare")
	_, err = loadServerTLS(cfg.TEE, TLSConfig{Enabled: true, ServerCert: bareCert, ServerKey: bareKey, ClientCAs: bareCert})
	require.NoError(t, err)
}
