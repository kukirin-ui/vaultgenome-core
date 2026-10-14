// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// lowOrderPublicKey is a 32-byte X25519 point of low order: the curve
// accepts it as a key, the KEM refuses it as a recipient.
func lowOrderPublicKey(t *testing.T) *ecdh.PublicKey {
	t.Helper()
	pub, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	require.NoError(t, err)
	return pub
}

// TestSeal_RefusesAnUnusableEscrowKey proves a genome key is never
// encapsulated to a public key the KEM cannot use.
func TestSeal_RefusesAnUnusableEscrowKey(t *testing.T) {
	kid, dek := sealed(t)
	_, err := Seal(dek, kid, lowOrderPublicKey(t))
	require.ErrorContains(t, err, "escrow: seal:")
}

// TestReadPrivate_RefusesWhatItCannotRead proves the failure modes of a
// key file beyond its mode: a directory where a file should be, and a
// file the process may not open.
func TestReadPrivate_RefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	asDir := filepath.Join(dir, "escrow.key")
	require.NoError(t, os.Mkdir(asDir, 0o700))
	_, err := ReadPrivate(asDir)
	require.Error(t, err, "a directory is not a key file")

	if os.Geteuid() == 0 {
		t.Skip("root opens files regardless of their mode")
	}
	priv, err := GenerateKey()
	require.NoError(t, err)
	unreadable := filepath.Join(dir, "unreadable.key")
	require.NoError(t, os.WriteFile(unreadable, priv.Bytes(), 0o000))
	_, err = ReadPrivate(unreadable)
	require.ErrorIs(t, err, os.ErrPermission)
}

// TestParsePublicPEM_Refusals pins each way a PEM can fail to be a
// usable escrow key: the wrong block type, a block that is not a
// public key at all, and a well-formed X25519 point the KEM refuses.
func TestParsePublicPEM_Refusals(t *testing.T) {
	lowOrder, err := PublicPEM(lowOrderPublicKey(t))
	require.NoError(t, err)
	cases := []struct {
		name string
		pem  []byte
		want string
	}{
		{"wrong block type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}}), "not a PEM public key"},
		{"not a public key", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}), "escrow: "},
		{"low-order point", lowOrder, "kms:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := ParsePublicPEM(tc.pem)
			require.Nil(t, pub)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestRecovery_Refusals pins the recovery envelope's refusals beyond the
// happy path: an unusable recovery key at wrap time, and at open time
// the wrong schema, a public key that does not parse, and contents
// that are not the private half of the key the envelope names.
func TestRecovery_Refusals(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	recovery, err := GenerateKey()
	require.NoError(t, err)

	_, err = WrapRecovery(priv, lowOrderPublicKey(t))
	require.ErrorContains(t, err, "kms:")

	env, err := WrapRecovery(priv, recovery.PublicKey())
	require.NoError(t, err)

	// wrapTo re-encapsulates raw under the tags env carries, the way a
	// forged or corrupted envelope would.
	wrapTo := func(raw []byte) Recovery {
		ct, err := kms.X25519KeyWrapper{}.Wrap(raw, recovery.PublicKey().Bytes(), recoveryAAD(env.EscrowKey, env.RecoveryKey))
		require.NoError(t, err)
		forged := env
		forged.Ciphertext = ct
		return forged
	}
	other, err := GenerateKey()
	require.NoError(t, err)

	cases := []struct {
		name string
		env  func() Recovery
		want string
	}{
		{"wrong schema", func() Recovery { e := env; e.Schema = "v0"; return e }, "recovery schema"},
		{"public key does not parse", func() Recovery { e := env; e.PublicKeyPEM = "nope"; return e }, "not a PEM public key"},
		{"contents are not a key", func() Recovery { return wrapTo([]byte("short")) }, "not an X25519 key"},
		{"contents are another key", func() Recovery { return wrapTo(other.Bytes()) }, "not the private half"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.env().Open(recovery)
			require.Nil(t, got)
			require.ErrorContains(t, err, tc.want)
		})
	}

	_, err = ParseRecovery([]byte("{not json"))
	require.ErrorContains(t, err, "recovery envelope")
	raw, err := env.Marshal()
	require.NoError(t, err)
	_, err = ParseRecovery(append(raw[:len(raw)-3], []byte(`,"extra":1}`)...))
	require.ErrorContains(t, err, "unknown field")
}

// failingSealer is a TEE whose sealing primitive is down.
type failingSealer struct{}

var errSealDown = errors.New("sealing device unavailable")

func (failingSealer) Seal([]byte, []byte) ([]byte, error)   { return nil, errSealDown }
func (failingSealer) Unseal([]byte, []byte) ([]byte, error) { return nil, errSealDown }

// TestSealedKey_Refusals pins the sealed escrow key's refusals beyond
// the happy path: a key of another curve, a sealer that fails, a file
// of the wrong schema, a public key that does not parse, and unsealed
// contents that are not the private half of the key the file names.
func TestSealedKey_Refusals(t *testing.T) {
	host := simulatedTEE(t, "release-host-v1")
	priv, err := GenerateKey()
	require.NoError(t, err)

	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = SealKey(p256, host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "not an X25519 key")

	_, err = SealKey(priv, failingSealer{}, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "escrow: seal to simulated")
	require.ErrorIs(t, err, errSealDown)

	s, err := SealKey(priv, host, tee.ProviderSimulated, host.Measurement())
	require.NoError(t, err)

	wrongSchema := s
	wrongSchema.Schema = "v0"
	_, err = wrongSchema.PublicKey()
	require.ErrorContains(t, err, "schema")
	_, err = wrongSchema.Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "schema")

	unparsable := s
	unparsable.PublicKeyPEM = "nope"
	_, err = unparsable.PublicKey()
	require.ErrorContains(t, err, "not a PEM public key")

	// sealTo seals raw under the file's own AAD, the way a forged or
	// corrupted file would.
	sealTo := func(raw []byte) SealedKey {
		blob, err := host.Seal(raw, sealedAAD(tee.ProviderSimulated, host.Measurement(), s.EscrowKey))
		require.NoError(t, err)
		forged := s
		forged.Sealed = blob
		return forged
	}
	_, err = sealTo([]byte("short")).Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "not an X25519 key")
	other, err := GenerateKey()
	require.NoError(t, err)
	_, err = sealTo(other.Bytes()).Open(host, tee.ProviderSimulated, host.Measurement())
	require.ErrorContains(t, err, "not the private half")

	_, err = ParseSealed([]byte("{not json"))
	require.ErrorContains(t, err, "sealed key")
}

// TestShort proves long digests are abbreviated for messages and short
// ones are left alone.
func TestShort(t *testing.T) {
	require.Equal(t, "0123456789ab…", short("0123456789abcdef"))
	require.Equal(t, "0123456789ab", short("0123456789ab"))
	require.Equal(t, "", short(""))
}

// TestOpen_RefusesAKeyThatIsNotTheOneNamed proves that an envelope whose
// ciphertext opens cleanly is still refused when the key inside is not
// the genome key its KeyID names.
func TestOpen_RefusesAKeyThatIsNotTheOneNamed(t *testing.T) {
	kid, _ := sealed(t)
	_, otherDEK := sealed(t)
	authority, err := GenerateKey()
	require.NoError(t, err)
	ct, err := kms.X25519KeyWrapper{}.Wrap(otherDEK, authority.PublicKey().Bytes(), aad(kid))
	require.NoError(t, err)
	forged := Envelope{Schema: Schema, KeyID: kid, EscrowKey: KeyTag(authority.PublicKey()), Ciphertext: ct}
	dek, err := Open(forged, authority)
	require.Nil(t, dek)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "escrow: open", "the envelope opened; the key inside is what was refused")
}
