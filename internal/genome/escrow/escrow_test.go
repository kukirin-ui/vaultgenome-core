// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package escrow

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
)

func sealed(t *testing.T) (string, []byte) {
	t.Helper()
	blob, dek, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/a", ContentSnapshot: []byte(`{}`)}, []byte("lora"))
	require.NoError(t, err)
	r, err := bundle.Identify(writeTemp(t, blob))
	require.NoError(t, err)
	return r.Header.KeyID, dek
}

func writeTemp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "g.genome")
	require.NoError(t, os.WriteFile(p, b, 0o644))
	return p
}

// The authority, and only it, gets the genome key back.
func TestSealOpen(t *testing.T) {
	kid, dek := sealed(t)
	authority, err := GenerateKey()
	require.NoError(t, err)
	env, err := Seal(dek, kid, authority.PublicKey())
	require.NoError(t, err)
	require.Equal(t, Schema, env.Schema)
	require.Equal(t, KeyTag(authority.PublicKey()), env.EscrowKey)
	require.NotContains(t, string(env.Ciphertext), string(dek))

	raw, err := env.Marshal()
	require.NoError(t, err)
	back, err := Parse(raw)
	require.NoError(t, err)
	got, err := Open(back, authority)
	require.NoError(t, err)
	require.Equal(t, dek, got)

	other, err := GenerateKey()
	require.NoError(t, err)
	_, err = Open(back, other)
	require.ErrorContains(t, err, "this authority holds")
}

func TestRefusals(t *testing.T) {
	kid, dek := sealed(t)
	authority, err := GenerateKey()
	require.NoError(t, err)

	_, err = Seal(dek[:16], kid, authority.PublicKey())
	require.Error(t, err, "a key that is not the id's")
	_, err = Seal(dek, "genome-dek-1", authority.PublicKey())
	require.Error(t, err)

	env, err := Seal(dek, kid, authority.PublicKey())
	require.NoError(t, err)
	for name, mutate := range map[string]func(e *Envelope){
		"schema":     func(e *Envelope) { e.Schema = "v0" },
		"not a kid":  func(e *Envelope) { e.KeyID = "genome-dek-1" },
		"other kid":  func(e *Envelope) { kid2, _ := sealed(t); e.KeyID = kid2 },
		"ciphertext": func(e *Envelope) { e.Ciphertext = append([]byte(nil), e.Ciphertext...); e.Ciphertext[40] ^= 1 },
		"escrow key": func(e *Envelope) { e.EscrowKey = "0000000000000000" },
	} {
		t.Run(name, func(t *testing.T) {
			e := env
			mutate(&e)
			_, err := Open(e, authority)
			require.Error(t, err)
		})
	}
	_, err = Parse([]byte(`{"schema":"x","extra":1}`))
	require.Error(t, err)
}

func TestKeyFiles(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	dir := t.TempDir()
	p := filepath.Join(dir, "escrow.key")
	require.NoError(t, os.WriteFile(p, priv.Bytes(), 0o600))
	got, err := ReadPrivate(p)
	require.NoError(t, err)
	require.True(t, got.Equal(priv))

	require.NoError(t, os.Chmod(p, 0o644))
	_, err = ReadPrivate(p)
	require.ErrorContains(t, err, "chmod 600")
	short := filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(short, []byte("short"), 0o600))
	_, err = ReadPrivate(short)
	require.ErrorContains(t, err, "not a 32-byte")
	_, err = ReadPrivate(filepath.Join(dir, "absent"))
	require.Error(t, err)

	pemBytes, err := PublicPEM(priv.PublicKey())
	require.NoError(t, err)
	pub, err := ParsePublicPEM(pemBytes)
	require.NoError(t, err)
	require.True(t, pub.Equal(priv.PublicKey()))
	_, err = ParsePublicPEM([]byte("nope"))
	require.Error(t, err)
	ec, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	b, err := PublicPEM(ec.PublicKey())
	require.NoError(t, err)
	_, err = ParsePublicPEM(b)
	require.Error(t, err, "not X25519")
}
