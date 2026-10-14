// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

func TestSealedSecret_RoundTripsAndBindsNameProviderAndHost(t *testing.T) {
	t.Parallel()
	host, err := NewSimulated([]byte("sagvd-v1"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	seed := bytes.Repeat([]byte{0xAB}, 32)

	raw, err := SealSecret(seed, host, ProviderSimulated, host.Measurement(), "keys.authority_signing.seed_path")
	require.NoError(t, err)
	require.True(t, IsSealedSecret(raw))
	require.False(t, IsSealedSecret(seed), "bare key bytes are not a sealed file")
	require.NotContains(t, string(raw), string(seed))
	s, err := ParseSealedSecret(raw)
	require.NoError(t, err)
	require.Equal(t, "keys.authority_signing.seed_path", s.Name)
	require.Equal(t, "simulated", s.TEE)

	got, err := OpenSecret(raw, host, ProviderSimulated, "keys.authority_signing.seed_path")
	require.NoError(t, err)
	require.Equal(t, seed, got)

	// Read as another key: refused by name before the TPM or chip is asked.
	_, err = OpenSecret(raw, host, ProviderSimulated, "keys.audit_signing.seed_path")
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, `read as "keys.audit_signing.seed_path"`)

	// Another provider named: refused.
	_, err = OpenSecret(raw, host, ProviderGCPSEVSNP, "keys.authority_signing.seed_path")
	require.ErrorContains(t, err, "this host is gcp-sev-snp")

	// Another host (another image, so another simulated measurement and
	// sealing key): the sealer refuses.
	other, err := NewSimulated([]byte("sagvd-v2"), bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	_, err = OpenSecret(raw, other, ProviderSimulated, "keys.authority_signing.seed_path")
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, "does not open it")

	// A touched file.
	touched := bytes.Replace(raw, []byte(`"name": "keys.authority_signing.seed_path"`), []byte(`"name": "keys.audit_signing.seed_path"`), 1)
	_, err = OpenSecret(touched, host, ProviderSimulated, "keys.audit_signing.seed_path")
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err), "the name is in the AEAD's associated data, not only in the file")

	for name, bad := range map[string][]byte{
		"not json":      []byte("not a file"),
		"other schema":  []byte(`{"schema":"vault-genome/sealed-secret/v0","tee":"simulated","measurement_hex":"00","name":"n","sealed":"AA=="}`),
		"incomplete":    []byte(`{"schema":"` + SealedSecretSchema + `","tee":"simulated","measurement_hex":"","name":"n","sealed":"AA=="}`),
		"unknown field": []byte(`{"schema":"` + SealedSecretSchema + `","tee":"simulated","measurement_hex":"00","name":"n","sealed":"AA==","x":1}`),
	} {
		_, err := OpenSecret(bad, host, ProviderSimulated, "n")
		require.Error(t, err, name)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), name)
	}
	_, err = SealSecret(nil, host, ProviderSimulated, host.Measurement(), "n")
	require.Error(t, err)
}

func TestSealerFor(t *testing.T) {
	t.Parallel()
	sim, err := NewSimulated([]byte("w"), bytes.Repeat([]byte{3}, 32))
	require.NoError(t, err)
	s, closer, err := SealerFor(sim, SealerOptions{})
	require.NoError(t, err)
	require.Nil(t, closer)
	require.Same(t, sim, s.(*Simulated))

	s, closer, err = SealerFor(&GCPTDXProducer{}, SealerOptions{TPM2ToolsDir: "/opt/tpm2", VTPMSealPCRs: "sha256:0,7"})
	require.NoError(t, err)
	require.Nil(t, closer)
	require.Equal(t, "sha256:0,7", s.(*VTPMSealer).PCRs())
	_, _, err = SealerFor(&AzureCGPUProducer{}, SealerOptions{VTPMSealPCRs: "sha1:0"})
	require.Error(t, err)

	_, _, err = SealerFor(&GCPSEVProducer{}, SealerOptions{SEVGuestDevice: "/nonexistent/sev-guest"})
	require.ErrorContains(t, err, "sev-guest")
	_, _, err = SealerFor(nil, SealerOptions{})
	require.ErrorContains(t, err, "no sealer")
}
