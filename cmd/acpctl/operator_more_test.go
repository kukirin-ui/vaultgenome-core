// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

// operatorKey makes an operator key pair in dir with `stop keygen`.
func operatorKey(t *testing.T, dir string) (seed, pub string) {
	t.Helper()
	seed, pub = filepath.Join(dir, "operator.seed"), filepath.Join(dir, "operator.pem")
	code, _, stderr := runStop("keygen", "-out", seed, "-pub", pub)
	require.Equal(t, 0, code, stderr)
	return seed, pub
}

// The stop commands report a file they cannot write or read, with the
// exit code of a failure rather than a usage error.
func TestStop_FileFailures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")
	seed, _ := operatorKey(t, dir)

	code, _, stderr := runStop("keygen", "-out", filepath.Join(dir, "k2.seed"), "-pub", filepath.Join(absent, "k2.pem"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "write public key")
	info, err := os.Stat(filepath.Join(dir, "k2.seed"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the seed was written first")

	code, _, stderr = runStop("keygen", "-out", filepath.Join(absent, "k3.seed"), "-pub", filepath.Join(dir, "k3.pem"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl stop keygen:")
	_, err = os.Stat(filepath.Join(dir, "k3.pem"))
	require.True(t, os.IsNotExist(err), "no public key without its seed")

	code, _, stderr = runStop("issue", "-key", seed, "-kid", "operator-1", "-serial", "1", "-all", "-out", filepath.Join(absent, "stop.json"))
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl stop issue: write:")

	list := filepath.Join(dir, "stop.json")
	code, _, stderr = runStop("issue", "-key", seed, "-kid", "operator-1", "-serial", "1", "-all", "-out", list)
	require.Equal(t, 0, code, stderr)
	code, _, stderr = runStop("verify", "-in", list, "-pubkey", filepath.Join(absent, "op.pem"), "-kid", "operator-1")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "read pubkey")

	for _, sub := range []string{"keygen", "issue", "verify"} {
		code, _, stderr = runStop(sub, "-nope")
		require.Equal(t, 2, code, sub)
		require.Contains(t, stderr, "flag provided but not defined")
	}
}

// A list without a reason or revocations prints its state alone.
func TestStop_VerifyTextWithoutReason(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seed, pub := operatorKey(t, dir)
	list := filepath.Join(dir, "stop.json")
	code, _, stderr := runStop("issue", "-key", seed, "-kid", "operator-1", "-serial", "4", "-revoke", "gcp-sev-snp:"+strings.Repeat("ab", 48), "-out", list)
	require.Equal(t, 0, code, stderr)
	code, stdout, stderr := runStop("verify", "-in", list, "-pubkey", pub, "-kid", "operator-1")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "valid list, serial 4, issued ")
	require.Contains(t, stdout, ": releases allowed (except revoked measurements)\n")
	require.Contains(t, stdout, "  revoked gcp-sev-snp "+strings.Repeat("ab", 48)+"\n")
	require.NotContains(t, stdout, "reason:")
}

// The failover commands report a file they cannot write or read.
func TestFailover_FileFailures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	absent := filepath.Join(dir, "absent")
	opSeed, opPub := operatorKey(t, dir)
	_, spub, _ := sentinelKeys(t, dir)
	issue := func(extra ...string) []string {
		return append([]string{"issue", "--key", opSeed, "--kid", "operator-1", "--serial", "1", "--sentinel-pub", spub,
			"--standby-kind", "gcp-sev-snp", "--standby-endpoint", "https://standby.example:8443", "--standby-measurement", strings.Repeat("ab", 48)}, extra...)
	}

	code, _, stderr := runCmd(failoverRun, issue("--out", filepath.Join(absent, "policy.json"))...)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl failover issue: write:")

	code, _, stderr = runCmd(failoverRun, issue("--out", filepath.Join(dir, "p.json"), "--primary-kind", "simulated",
		"--primary-measurement", strings.Repeat("ab", 32), "--primary-attestor-pub", filepath.Join(absent, "attestor.pem"))...)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl failover issue: --primary-attestor-pub: read pubkey")

	policy := filepath.Join(dir, "policy.json")
	code, _, stderr = runCmd(failoverRun, issue("--out", policy)...)
	require.Equal(t, 0, code, stderr)

	code, _, stderr = runCmd(failoverRun, "verify", "--in", filepath.Join(absent, "policy.json"), "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl failover verify: open")

	code, _, stderr = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", filepath.Join(absent, "op.pem"), "--kid", "operator-1")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "acpctl failover verify: read pubkey")

	for _, sub := range []string{"issue", "verify"} {
		code, _, stderr = runCmd(failoverRun, sub, "--nope")
		require.Equal(t, 2, code, sub)
		require.Contains(t, stderr, "flag provided but not defined")
	}
}

// verify says when a policy no longer stands: it verifies, and its
// standing is the expiry, in both forms.
func TestFailover_VerifyReportsAnExpiredPolicy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	opSeed, opPub := operatorKey(t, dir)
	seedBytes, err := os.ReadFile(opSeed)
	require.NoError(t, err)
	spubBytes, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	issued := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	p, err := failover.Sign(failover.Policy{
		Serial: 9, IssuedAt: issued, NotAfter: issued.Add(24 * time.Hour), SentinelPublicKey: spubBytes,
		Standby:  failover.Standby{Kind: "gcp-sev-snp", Endpoint: "https://standby.example:8443", Measurements: []string{strings.Repeat("ab", 48)}},
		Triggers: failover.Triggers{CompromiseReport: true}, SigningKeyID: "operator-1",
	}, ed25519.NewKeyFromSeed(seedBytes))
	require.NoError(t, err)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	policy := filepath.Join(dir, "expired.json")
	require.NoError(t, os.WriteFile(policy, raw, 0o644))

	code, stdout, stderr := runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "valid failover policy, serial 9, issued 2025-01-01T00:00:00Z, until 2025-01-02T00:00:00Z: failover: policy serial 9 expired at 2025-01-02T00:00:00Z\n")
	require.Contains(t, stdout, "  triggers:         compromise report\n")
	require.Contains(t, stdout, "  required gate:    none; quarantine 0s; max RPO 0s (0: no bound)\n")
	require.NotContains(t, stdout, "reason:")

	code, stdout, _ = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1", "--json")
	require.Equal(t, 0, code)
	var v struct {
		Standing string `json:"standing"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	require.Contains(t, v.Standing, "expired at 2025-01-02T00:00:00Z")
}

// brokenPipe is a writer that takes nothing, as a closed pipe would.
type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// The recovered escrow key goes to stdout alone; when stdout takes
// nothing, the command fails rather than printing the key elsewhere.
func TestEscrowRecover_StdoutFailure(t *testing.T) {
	t.Parallel()
	work := t.TempDir()
	recoverySeed, recoveryPub := filepath.Join(work, "recovery.seed"), filepath.Join(work, "recovery.pem")
	var out, errOut bytes.Buffer
	require.Equal(t, 0, escrowCmd([]string{"recovery-keygen", "--out", recoverySeed, "--pub", recoveryPub}, &out, &errOut), errOut.String())
	pemBytes, err := os.ReadFile(recoveryPub)
	require.NoError(t, err)
	rpub, err := escrow.ParsePublicPEM(pemBytes)
	require.NoError(t, err)
	escrowKey, err := escrow.GenerateKey()
	require.NoError(t, err)
	env, err := escrow.WrapRecovery(escrowKey, rpub)
	require.NoError(t, err)
	raw, err := env.Marshal()
	require.NoError(t, err)
	envelope := filepath.Join(work, "escrow.recovery")
	require.NoError(t, os.WriteFile(envelope, raw, 0o600))

	errOut.Reset()
	require.Equal(t, 1, escrowCmd([]string{"recover", "--in", envelope, "--key", recoverySeed}, brokenPipe{}, &errOut))
	require.Contains(t, errOut.String(), "acpctl escrow recover: broken pipe")
	require.NotContains(t, errOut.String(), "recovered")

	// Missing files are usage errors, named by flag.
	errOut.Reset()
	require.Equal(t, 2, escrowCmd([]string{"recover", "--in", filepath.Join(work, "absent"), "--key", recoverySeed}, &out, &errOut))
	require.Contains(t, errOut.String(), "acpctl escrow recover: --in:")
	errOut.Reset()
	require.Equal(t, 2, escrowCmd([]string{"recover", "--in", envelope, "--key", filepath.Join(work, "absent")}, &out, &errOut))
	require.Contains(t, errOut.String(), "acpctl escrow recover: --key:")

	// keygen writes the private key before the public one, and reports
	// either failing.
	errOut.Reset()
	require.Equal(t, 1, escrowCmd([]string{"keygen", "--out", filepath.Join(work, "e.key"), "--pub", filepath.Join(work, "absent", "e.pem")}, &out, &errOut))
	require.Contains(t, errOut.String(), "acpctl escrow keygen:")
	info, err := os.Stat(filepath.Join(work, "e.key"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	for _, sub := range []string{"keygen", "recovery-keygen", "recover"} {
		errOut.Reset()
		require.Equal(t, 2, escrowCmd([]string{sub, "--nope"}, &out, &errOut), sub)
		require.Contains(t, errOut.String(), "flag provided but not defined")
	}
}
