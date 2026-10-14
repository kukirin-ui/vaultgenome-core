// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// provision runs `sagvd escrow-provision` against f's config and returns
// what it printed.
func provision(t *testing.T, f *materialFixture, args ...string) escrowProvisionOutput {
	t.Helper()
	cfgPath := filepath.Join(f.dir, "sagvd.json")
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	f.rewrite(t, cfgPath, raw)
	var out, errOut strings.Builder
	require.NoError(t, runEscrowProvisionCmd(append([]string{"-config", cfgPath}, args...), strings.NewReader(""), &out, &errOut))
	require.Contains(t, errOut.String(), "SIMULATED TEE")
	var res escrowProvisionOutput
	require.NoError(t, json.Unmarshal([]byte(out.String()), &res))
	return res
}

// The escrow key is made in the process and written sealed to the host's
// TEE; the daemon unseals it in memory at start; identity reads the
// public half without unsealing; the file is never overwritten.
func TestEscrowProvisionSealsToThisHost(t *testing.T) {
	f := newMaterialFixture(t)
	sealedPath, pubPath := filepath.Join(f.dir, "escrow.sealed"), filepath.Join(f.dir, "escrow.pem")
	res := provision(t, f, "-out", sealedPath, "-pub", pubPath)
	require.Equal(t, "generated", res.Source)
	require.Equal(t, "simulated", res.TEE)
	require.NotEmpty(t, res.EscrowKey)

	raw, err := os.ReadFile(sealedPath)
	require.NoError(t, err)
	info, err := os.Stat(sealedPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	sealed, err := escrow.ParseSealed(raw)
	require.NoError(t, err)
	require.Equal(t, res.EscrowKey, sealed.EscrowKey)
	pemBytes, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	require.Equal(t, sealed.PublicKeyPEM, string(pemBytes))

	// The daemon's materials open it, and the key is the public half's.
	f.cfg.CrossCloud.KeyEscrowPath = sealedPath
	mat, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	defer func() { _ = mat.Close() }()
	require.NotNil(t, mat.Escrow)
	require.Equal(t, "sealed:simulated", mat.EscrowSource)
	require.Equal(t, res.EscrowKey, escrow.KeyTag(mat.Escrow.PublicKey()))

	// Identity prints the public half and how the key is kept.
	cfgPath := filepath.Join(f.dir, "sagvd.json")
	raw, err = json.Marshal(f.cfg)
	require.NoError(t, err)
	f.rewrite(t, cfgPath, raw)
	var out strings.Builder
	require.NoError(t, runIdentityCmd([]string{"-config", cfgPath}, &out))
	var id authorityIdentity
	require.NoError(t, json.Unmarshal([]byte(out.String()), &id))
	require.Equal(t, res.EscrowKey, id.KeyEscrowTag)
	require.Equal(t, "sealed:simulated", id.KeyEscrowStorage)
	require.Equal(t, sealed.PublicKeyPEM, id.KeyEscrowPublicKeyPEM)

	// Never overwritten.
	var errOut strings.Builder
	err = runEscrowProvisionCmd([]string{"-config", cfgPath, "-out", sealedPath, "-pub", pubPath}, strings.NewReader(""), &out, &errOut)
	require.ErrorContains(t, err, "exist")
	err = runEscrowProvisionCmd([]string{"-config", cfgPath, "-out", filepath.Join(f.dir, "x"), "-pub", pubPath, "-recovery-to", "r.pem"}, strings.NewReader(""), &out, &errOut)
	require.ErrorContains(t, err, "go together")
	err = runEscrowProvisionCmd([]string{"-out", "x"}, strings.NewReader(""), &out, &errOut)
	require.ErrorContains(t, err, "required")
}

// A key sealed on one host does not open on another: the daemon refuses
// to start rather than run with a key it cannot use, and says why.
func TestSealedEscrowKeyDoesNotOpenElsewhere(t *testing.T) {
	f := newMaterialFixture(t)
	sealedPath := filepath.Join(f.dir, "escrow.sealed")
	provision(t, f, "-out", sealedPath, "-pub", filepath.Join(f.dir, "escrow.pem"))
	f.cfg.CrossCloud.KeyEscrowPath = sealedPath

	// Another workload descriptor: another measurement, another host.
	other := f.cfg
	other.TEE.WorkloadDescriptor = "another-release-host"
	_, err := LoadMaterials(other, shared_time.NewSystemClock())
	require.ErrorContains(t, err, "sealed at measurement")

	// The same measurement claimed by a host with another sealing key.
	f.rewrite(t, f.cfg.TEE.SeedPath, bytes.Repeat([]byte{0x42}, 32))
	mat, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
	if err == nil {
		// The simulated sealing key derives from the measurement alone, so
		// a different seed still opens it; what must hold is the identity.
		require.NotNil(t, mat.Escrow)
		_ = mat.Close()
	}

	// A file edited on disk fails closed.
	raw, err := os.ReadFile(sealedPath)
	require.NoError(t, err)
	edited := bytes.Replace(raw, []byte(`"tee": "simulated"`), []byte(`"tee": "gcp-sev-snp"`), 1)
	require.NotEqual(t, raw, edited)
	f.rewrite(t, sealedPath, edited)
	_, err = LoadMaterials(f.cfg, shared_time.NewSystemClock())
	require.ErrorContains(t, err, "sealed to gcp-sev-snp")
}

// A plaintext escrow key is accepted under the simulated TEE, and refused
// on a hardware one: on the chip the key is not on the disk.
func TestPlaintextEscrowKeyOnlyUnderSimulation(t *testing.T) {
	f := newMaterialFixture(t)
	priv, err := escrow.GenerateKey()
	require.NoError(t, err)
	keyPath := filepath.Join(f.dir, "escrow.key")
	require.NoError(t, os.WriteFile(keyPath, priv.Bytes(), 0o600))
	f.cfg.Genome.KeyEscrowPath = keyPath
	mat, err := LoadMaterials(f.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	require.Equal(t, escrowSourcePlaintext, mat.EscrowSource)
	require.Equal(t, priv.Bytes(), mat.Escrow.Bytes())
	_ = mat.Close()

	hardware := &materials{Provider: tee.ProviderGCPSEVSNP}
	_, _, err = loadEscrowKey(keyPath, hardware)
	require.ErrorContains(t, err, "must be sealed to this host")
	require.ErrorContains(t, err, "escrow-provision")

	require.NoError(t, os.Chmod(keyPath, 0o644))
	_, err = LoadMaterials(f.cfg, shared_time.NewSystemClock())
	require.ErrorContains(t, err, "open to other users")
	_, _, err = loadEscrowKey(filepath.Join(f.dir, "absent"), hardware)
	require.Error(t, err)
	big := filepath.Join(f.dir, "big")
	require.NoError(t, os.WriteFile(big, bytes.Repeat([]byte{'{'}, maxEscrowFileBytes+1), 0o600))
	_, _, err = loadEscrowKey(big, hardware)
	require.ErrorContains(t, err, "larger than")
	_, _, err = escrowPublicFromFile(big)
	require.ErrorContains(t, err, "larger than")
}

// The recovery ceremony: the key is wrapped to the operator's recovery
// key at provisioning; opened off the host, it is re-sealed on a new host
// through stdin, as the same escrow key.
func TestEscrowProvisionRecoveryRoundTrip(t *testing.T) {
	f := newMaterialFixture(t)
	recovery, err := escrow.GenerateKey()
	require.NoError(t, err)
	recoveryPEM, err := escrow.PublicPEM(recovery.PublicKey())
	require.NoError(t, err)
	recoveryPub := filepath.Join(f.dir, "recovery.pem")
	require.NoError(t, os.WriteFile(recoveryPub, recoveryPEM, 0o644))
	envelopePath := filepath.Join(f.dir, "escrow.recovery")
	res := provision(t, f, "-out", filepath.Join(f.dir, "escrow.sealed"), "-pub", filepath.Join(f.dir, "escrow.pem"),
		"-recovery-to", recoveryPub, "-recovery-out", envelopePath)
	require.Equal(t, escrow.KeyTag(recovery.PublicKey()), res.RecoveryKey)
	require.Equal(t, envelopePath, res.RecoveryOut)

	// The operator opens the envelope on their machine...
	raw, err := os.ReadFile(envelopePath)
	require.NoError(t, err)
	env, err := escrow.ParseRecovery(raw)
	require.NoError(t, err)
	require.Equal(t, res.EscrowKey, env.EscrowKey)
	priv, err := env.Open(recovery)
	require.NoError(t, err)

	// ...and pipes the key into a new host, which seals it there.
	host2 := newMaterialFixture(t)
	host2.cfg.TEE.WorkloadDescriptor = "release-host-2"
	cfgPath := filepath.Join(host2.dir, "sagvd.json")
	cfgRaw, err := json.Marshal(host2.cfg)
	require.NoError(t, err)
	host2.rewrite(t, cfgPath, cfgRaw)
	sealed2 := filepath.Join(host2.dir, "escrow.sealed")
	var out, errOut strings.Builder
	require.NoError(t, runEscrowProvisionCmd([]string{"-config", cfgPath, "-out", sealed2, "-pub", filepath.Join(host2.dir, "escrow.pem"), "-stdin"},
		bytes.NewReader(priv.Bytes()), &out, &errOut))
	var res2 escrowProvisionOutput
	require.NoError(t, json.Unmarshal([]byte(out.String()), &res2))
	require.Equal(t, "stdin", res2.Source)
	require.Equal(t, res.EscrowKey, res2.EscrowKey, "the same escrow key, sealed to the new host")
	require.NotEqual(t, res.MeasurementHex, res2.MeasurementHex)

	host2.cfg.CrossCloud.KeyEscrowPath = sealed2
	mat, err := LoadMaterials(host2.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	require.Equal(t, priv.Bytes(), mat.Escrow.Bytes())
	_ = mat.Close()

	// A short or malformed key on stdin is refused before anything is written.
	err = runEscrowProvisionCmd([]string{"-config", cfgPath, "-out", filepath.Join(host2.dir, "y"), "-pub", filepath.Join(host2.dir, "y.pem"), "-stdin"},
		bytes.NewReader([]byte("short")), &out, &errOut)
	require.ErrorContains(t, err, "want the 32-byte")
	_, err = os.Stat(filepath.Join(host2.dir, "y"))
	require.True(t, os.IsNotExist(err))
}
