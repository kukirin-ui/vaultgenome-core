// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// `acp-compute seal-keys` seals the worker's mTLS client key too, and the
// dialer opens it; another host does not; a bare key still loads.
func TestSealKeys_SealsTheClientTLSKeyToo(t *testing.T) {
	f := newTestFixture(t)
	cfg := f.cfg
	m := newTLSMaterial(t, f.dir)
	cfg.Vault.TLS = TLSConfig{Enabled: true, ClientCert: m.clientCert, ClientKey: m.clientKey, CABundle: m.caPEM, ServerName: "127.0.0.1"}
	require.NoError(t, cfg.Validate())
	keyPEM, err := os.ReadFile(m.clientKey)
	require.NoError(t, err)

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	cfgPath := filepath.Join(f.dir, "worker.json")
	require.NoError(t, os.WriteFile(cfgPath, raw, 0o600))
	var stdout, stderr bytes.Buffer
	require.NoError(t, runSealKeysCmd([]string{"-config", cfgPath}, &stdout, &stderr))
	var out sealKeysOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.Len(t, out.Sealed, 3)
	require.Equal(t, "vault.tls.client_key", out.Sealed[2].Name)
	sealed, err := os.ReadFile(m.clientKey)
	require.NoError(t, err)
	require.True(t, tee.IsSealedSecret(sealed))
	require.False(t, bytes.Contains(sealed, keyPEM))

	tc, err := loadClientTLS(cfg.TEE, cfg.Vault.TLS)
	require.NoError(t, err)
	require.Len(t, tc.Certificates, 1)

	other := cfg.TEE
	other.WorkloadDescriptor = cfg.TEE.WorkloadDescriptor + "-elsewhere"
	_, err = loadClientTLS(other, cfg.Vault.TLS)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.tls.client_key")

	bare := newTLSMaterial(t, t.TempDir())
	_, err = loadClientTLS(cfg.TEE, TLSConfig{Enabled: true, ClientCert: bare.clientCert, ClientKey: bare.clientKey, CABundle: bare.caPEM, ServerName: "127.0.0.1"})
	require.NoError(t, err)
}
