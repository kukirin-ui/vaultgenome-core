// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// A sealed escrow key opens only through this host's sealer, and only
// when the file is a sealed escrow key: a host without a sealer, or a
// file that merely looks sealed, is refused with the reason.
func TestLoadEscrowKey_SealedShapes(t *testing.T) {
	dir := t.TempDir()
	sim, err := tee.NewSimulated([]byte("escrow-host"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	host := &materials{Provider: tee.ProviderSimulated, Producer: sim, tee: TEEConfig{}}
	priv, err := escrow.GenerateKey()
	require.NoError(t, err)
	sealed, err := escrow.SealKey(priv, sim, tee.ProviderSimulated, sim.Measurement())
	require.NoError(t, err)
	raw, err := sealed.Marshal()
	require.NoError(t, err)
	good := filepath.Join(dir, "escrow.sealed")
	require.NoError(t, os.WriteFile(good, raw, 0o600))
	notSealed := filepath.Join(dir, "other.sealed")
	require.NoError(t, os.WriteFile(notSealed, []byte(`{"schema":"something-else"}`), 0o600))

	got, source, err := loadEscrowKey(good, host)
	require.NoError(t, err)
	require.Equal(t, "sealed:simulated", source)
	require.Equal(t, priv.Bytes(), got.Bytes())

	_, _, err = loadEscrowKey(notSealed, host)
	require.ErrorContains(t, err, "sealed key schema")
	noSealer := &materials{Provider: tee.ProviderSimulated}
	_, _, err = loadEscrowKey(good, noSealer)
	require.ErrorContains(t, err, "has no sealer")
}

// The public half is read without unsealing: from a sealed file as
// written, by arithmetic from a plaintext key; a file that is neither, or
// a sealed file whose public key is not the one its tag names, is refused.
func TestEscrowPublicFromFile_Shapes(t *testing.T) {
	dir := t.TempDir()
	priv, err := escrow.GenerateKey()
	require.NoError(t, err)
	plain := filepath.Join(dir, "escrow.key")
	require.NoError(t, os.WriteFile(plain, priv.Bytes(), 0o600))
	pub, source, err := escrowPublicFromFile(plain)
	require.NoError(t, err)
	require.Equal(t, escrowSourcePlaintext, source)
	require.Equal(t, escrow.KeyTag(priv.PublicKey()), escrow.KeyTag(pub))

	short := filepath.Join(dir, "short.key")
	require.NoError(t, os.WriteFile(short, []byte("31 bytes are not a key........."), 0o600))
	_, _, err = escrowPublicFromFile(short)
	require.Error(t, err)

	badSchema := filepath.Join(dir, "bad.sealed")
	require.NoError(t, os.WriteFile(badSchema, []byte(`{"schema":"x"}`), 0o600))
	_, _, err = escrowPublicFromFile(badSchema)
	require.ErrorContains(t, err, "sealed key schema")

	sim, err := tee.NewSimulated([]byte("escrow-host"), bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	sealed, err := escrow.SealKey(priv, sim, tee.ProviderSimulated, sim.Measurement())
	require.NoError(t, err)
	sealed.EscrowKey = "escrow-" + strings.Repeat("0", 12)
	raw, err := json.Marshal(sealed)
	require.NoError(t, err)
	mismatched := filepath.Join(dir, "mismatched.sealed")
	require.NoError(t, os.WriteFile(mismatched, raw, 0o600))
	_, _, err = escrowPublicFromFile(mismatched)
	require.ErrorContains(t, err, "its tag says")
}

// escrow-provision writes nothing it cannot stand behind: a config that
// does not validate, a recovery key it cannot read, material it cannot
// load, a key it cannot read from stdin; and it never replaces a recovery
// envelope that is already there.
func TestEscrowProvision_Refusals(t *testing.T) {
	f := newMaterialFixture(t)
	writeCfg := func(name string, cfg Config) string {
		raw, err := json.Marshal(cfg)
		require.NoError(t, err)
		p := filepath.Join(f.dir, name)
		require.NoError(t, os.WriteFile(p, raw, 0o600))
		return p
	}
	good := writeCfg("sagvd.json", f.cfg)
	invalid := f.cfg
	invalid.TEE.Provider = "vmware"
	noPeer := f.cfg
	noPeer.TEE.Peer.MeasurementPath = filepath.Join(f.dir, "absent")
	recovery, err := escrow.GenerateKey()
	require.NoError(t, err)
	recoveryPEM, err := escrow.PublicPEM(recovery.PublicKey())
	require.NoError(t, err)
	recoveryPub := filepath.Join(f.dir, "recovery.pem")
	require.NoError(t, os.WriteFile(recoveryPub, recoveryPEM, 0o644))
	notAKey := filepath.Join(f.dir, "not-a-key.pem")
	require.NoError(t, os.WriteFile(notAKey, []byte("nope"), 0o644))
	existing := filepath.Join(f.dir, "existing.recovery")
	require.NoError(t, os.WriteFile(existing, []byte("keep me"), 0o600))
	out := func(name string) string { return filepath.Join(f.dir, name) }

	for name, tc := range map[string]struct {
		args  []string
		stdin io.Reader
		want  string
	}{
		"undefined flag":       {[]string{"-nope"}, nil, "flag provided but not defined"},
		"missing config":       {[]string{"-config", filepath.Join(f.dir, "absent.json"), "-out", out("z"), "-pub", out("z.pem")}, nil, "absent.json"},
		"invalid config":       {[]string{"-config", writeCfg("invalid.json", invalid), "-out", out("a"), "-pub", out("a.pem")}, nil, "escrow-provision: config validation"},
		"recovery key missing": {[]string{"-config", good, "-out", out("b"), "-pub", out("b.pem"), "-recovery-to", out("absent.pem"), "-recovery-out", out("b.rec")}, nil, "-recovery-to"},
		"recovery key not PEM": {[]string{"-config", good, "-out", out("c"), "-pub", out("c.pem"), "-recovery-to", notAKey, "-recovery-out", out("c.rec")}, nil, "-recovery-to"},
		"materials missing":    {[]string{"-config", writeCfg("nopeer.json", noPeer), "-out", out("d"), "-pub", out("d.pem")}, nil, "tee.peer.measurement_path"},
		"stdin fails":          {[]string{"-config", good, "-out", out("e"), "-pub", out("e.pem"), "-stdin"}, iotest.ErrReader(errors.New("pipe broke")), "-stdin: pipe broke"},
		"pub dir missing":      {[]string{"-config", good, "-out", out("f"), "-pub", filepath.Join(f.dir, "missing", "f.pem")}, nil, "-pub"},
		"recovery out exists":  {[]string{"-config", good, "-out", out("g"), "-pub", out("g.pem"), "-recovery-to", recoveryPub, "-recovery-out", existing}, nil, "-recovery-out"},
	} {
		t.Run(name, func(t *testing.T) {
			stdin := tc.stdin
			if stdin == nil {
				stdin = strings.NewReader("")
			}
			err := runEscrowProvisionCmd(tc.args, stdin, io.Discard, io.Discard)
			require.ErrorContains(t, err, tc.want)
		})
	}
	kept, err := os.ReadFile(existing)
	require.NoError(t, err)
	require.Equal(t, []byte("keep me"), kept, "the envelope that was there is still there")
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		_, err := os.Stat(out(name))
		require.True(t, os.IsNotExist(err), "%s: nothing was written", name)
	}

	require.ErrorContains(t, writeExclusive(f.dir, []byte("x"), 0o600), "exist", "a path that is taken, even by a directory")
}
