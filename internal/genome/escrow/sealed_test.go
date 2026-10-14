// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

func simulatedTEE(t *testing.T, descriptor string) *tee.Simulated {
	t.Helper()
	s, err := tee.NewSimulated([]byte(descriptor), bytes.Repeat([]byte{3}, 32))
	require.NoError(t, err)
	return s
}

// The escrow key sealed on one host opens there — after a restart, with
// a fresh sealer of the same identity — and nowhere else. Its public half
// is readable without unsealing.
func TestSealedKeyOpensOnlyWhereItWasSealed(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	host := simulatedTEE(t, "release-host-v1")
	sealed, err := SealKey(priv, host, tee.ProviderSimulated, host.Measurement())
	require.NoError(t, err)
	require.Equal(t, SealedSchema, sealed.Schema)
	require.Equal(t, "simulated", sealed.TEE)
	require.Equal(t, hex.EncodeToString(host.Measurement()), sealed.MeasurementHex)
	require.Equal(t, KeyTag(priv.PublicKey()), sealed.EscrowKey)
	require.NotContains(t, string(sealed.Sealed), string(priv.Bytes()))

	raw, err := sealed.Marshal()
	require.NoError(t, err)
	require.True(t, IsSealed(raw))
	require.False(t, IsSealed(priv.Bytes()))
	require.False(t, IsSealed(append([]byte("{"), bytes.Repeat([]byte{1}, 31)...)), "a raw key that begins with '{' is still a raw key")
	parsed, err := ParseSealed(raw)
	require.NoError(t, err)
	pub, err := parsed.PublicKey()
	require.NoError(t, err)
	require.Equal(t, priv.PublicKey().Bytes(), pub.Bytes())

	restarted := simulatedTEE(t, "release-host-v1")
	got, err := parsed.Open(restarted, tee.ProviderSimulated, restarted.Measurement())
	require.NoError(t, err)
	require.Equal(t, priv.Bytes(), got.Bytes())

	other := simulatedTEE(t, "release-host-v2")
	_, err = parsed.Open(other, tee.ProviderSimulated, other.Measurement())
	require.ErrorContains(t, err, "sealed at measurement")
	_, err = parsed.Open(other, tee.ProviderGCPSEVSNP, host.Measurement())
	require.ErrorContains(t, err, "sealed to simulated")
	// The same measurement claimed, another sealer behind it: the AEAD says no.
	_, err = parsed.Open(other, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "unseal on simulated")
	_, err = parsed.Open(nil, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "no TEE sealer")
}

// Every clear field is bound into the seal: a file edited on disk fails
// to open instead of opening as something else.
func TestSealedKeyFieldsAreBound(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	host := simulatedTEE(t, "release-host-v1")
	sealed, err := SealKey(priv, host, tee.ProviderSimulated, host.Measurement())
	require.NoError(t, err)

	other, err := GenerateKey()
	require.NoError(t, err)
	otherPEM, err := PublicPEM(other.PublicKey())
	require.NoError(t, err)

	swapped := sealed
	swapped.PublicKeyPEM, swapped.EscrowKey = string(otherPEM), KeyTag(other.PublicKey())
	_, err = swapped.Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "unseal")

	mismatched := sealed
	mismatched.PublicKeyPEM = string(otherPEM)
	_, err = mismatched.PublicKey()
	require.ErrorContains(t, err, "its tag says")

	raw, err := sealed.Marshal()
	require.NoError(t, err)
	_, err = ParseSealed(bytes.Replace(raw, []byte(SealedSchema), []byte("vault-genome/sealed-escrow-key/v0"), 1))
	require.ErrorContains(t, err, "schema")
	_, err = ParseSealed(append(raw[:len(raw)-2], []byte(`,"extra":1}`)...))
	require.ErrorContains(t, err, "unknown field")
	_, err = ParseSealed([]byte(`{"schema":"` + SealedSchema + `"}`))
	require.ErrorContains(t, err, "incomplete")
	_, err = SealKey(nil, host, tee.ProviderSimulated, host.Measurement())
	require.Error(t, err)
}

// The recovery envelope: the escrow key wrapped to the operator's recovery
// key, opened only with it, and only as the key it names.
func TestRecoveryEnvelope(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	recovery, err := GenerateKey()
	require.NoError(t, err)
	env, err := WrapRecovery(priv, recovery.PublicKey())
	require.NoError(t, err)
	require.Equal(t, RecoverySchema, env.Schema)
	require.Equal(t, KeyTag(priv.PublicKey()), env.EscrowKey)
	require.Equal(t, KeyTag(recovery.PublicKey()), env.RecoveryKey)

	raw, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := ParseRecovery(raw)
	require.NoError(t, err)
	got, err := parsed.Open(recovery)
	require.NoError(t, err)
	require.Equal(t, priv.Bytes(), got.Bytes())

	wrong, err := GenerateKey()
	require.NoError(t, err)
	_, err = parsed.Open(wrong)
	require.ErrorContains(t, err, "wrapped to recovery key")

	// The tags are bound: an envelope relabelled for another recovery key
	// does not open with it, and a swapped public key is caught.
	relabelled := parsed
	relabelled.RecoveryKey = KeyTag(wrong.PublicKey())
	_, err = relabelled.Open(wrong)
	require.ErrorContains(t, err, "open recovery envelope")
	other, err := GenerateKey()
	require.NoError(t, err)
	otherPEM, err := PublicPEM(other.PublicKey())
	require.NoError(t, err)
	swapped := parsed
	swapped.PublicKeyPEM = string(otherPEM)
	_, err = swapped.Open(recovery)
	require.ErrorContains(t, err, "its tag says")

	_, err = ParseRecovery([]byte(strings.Replace(string(raw), RecoverySchema, "x", 1)))
	require.ErrorContains(t, err, "schema")
	_, err = ParseRecovery([]byte(`{"schema":"` + RecoverySchema + `"}`))
	require.ErrorContains(t, err, "incomplete")
	_, err = WrapRecovery(priv, nil)
	require.Error(t, err)
	_, err = parsed.Open(nil)
	require.Error(t, err)
}
