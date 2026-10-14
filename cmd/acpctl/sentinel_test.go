// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/failover"
)

func runCmd(f func([]string, *bytes.Buffer, *bytes.Buffer) int, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := f(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func sentinelRun(args []string, out, errOut *bytes.Buffer) int { return sentinelCmd(args, out, errOut) }
func failoverRun(args []string, out, errOut *bytes.Buffer) int { return failoverCmd(args, out, errOut) }

// sentinelKeys makes a sentinel key and an escrow public key in dir.
func sentinelKeys(t *testing.T, dir string) (seed, pub, escrowPEM string) {
	t.Helper()
	seed, pub = filepath.Join(dir, "sentinel.seed"), filepath.Join(dir, "sentinel.pem")
	code, stdout, stderr := runCmd(sentinelRun, "keygen", "--out", seed, "--pub", pub)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "sentinel-")
	info, err := os.Stat(seed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	code, _, stderr = runCmd(sentinelRun, "keygen", "--out", seed, "--pub", pub)
	require.NotEqual(t, 0, code, "a sentinel key is never overwritten")
	require.Contains(t, stderr, "exists")

	esc, err := escrow.GenerateKey()
	require.NoError(t, err)
	pemBytes, err := escrow.PublicPEM(esc.PublicKey())
	require.NoError(t, err)
	escrowPEM = filepath.Join(dir, "escrow.pem")
	require.NoError(t, os.WriteFile(escrowPEM, pemBytes, 0o644))
	return seed, pub, escrowPEM
}

// The sentinel seals the state, then a tripwire fires: it stops sealing,
// reports, and exits 3.
func TestSentinel_WatchSealsThenReportsCompromise(t *testing.T) {
	dir := t.TempDir()
	seed, pub, escrowPEM := sentinelKeys(t, dir)
	state, outbox := filepath.Join(dir, "state"), filepath.Join(dir, "outbox")
	require.NoError(t, os.MkdirAll(state, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(state, "adapter.safetensors"), []byte("weights"), 0o644))
	canary := filepath.Join(dir, "canary")
	require.NoError(t, os.WriteFile(canary, []byte("quiet"), 0o600))

	go func() {
		// Once the first genome is sealed, the intruder touches the canary.
		for {
			if m, _ := filepath.Glob(filepath.Join(outbox, "gen-*.seal.json")); len(m) > 0 {
				_ = os.WriteFile(canary, []byte("touched"), 0o600)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	code, stdout, stderr := runCmd(sentinelRun, "watch", "--content-dir", state, "--outbox", outbox, "--escrow-to", escrowPEM,
		"--key", seed, "--tripwire", canary, "--probe", "true", "--interval", "20ms", "--settle", "0s")
	require.Equal(t, 3, code, stderr)
	var res struct {
		Outcome    string `json:"outcome"`
		Sentinel   string `json:"sentinel"`
		Generation int    `json:"generations_sealed"`
		Compromise *struct {
			Tripped []struct {
				Target string `json:"target"`
			} `json:"tripped"`
		} `json:"compromise"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	require.Equal(t, "compromised", res.Outcome)
	require.Equal(t, 1, res.Generation)
	require.Equal(t, canary, res.Compromise.Tripped[0].Target)
	require.Contains(t, stderr, "genome sealed")

	pk, err := readEd25519PublicKey(pub)
	require.NoError(t, err)
	chain, rejected, err := sentinel.ReadChain(outbox, ed25519.PublicKey(pk))
	require.NoError(t, err)
	require.Empty(t, rejected)
	require.Len(t, chain, 1)
	require.Equal(t, res.Sentinel, chain[0].Sentinel)

	// The outbox is closed: a restart refuses it.
	code, _, stderr = runCmd(sentinelRun, "watch", "--content-dir", state, "--outbox", outbox, "--escrow-to", escrowPEM, "--key", seed)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "compromise report")
}

func TestSentinel_WatchRefusesBadArguments(t *testing.T) {
	dir := t.TempDir()
	seed, _, escrowPEM := sentinelKeys(t, dir)
	open := filepath.Join(dir, "open.seed")
	raw, err := os.ReadFile(seed)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(open, raw, 0o644))
	state := t.TempDir()
	base := []string{"watch", "--content-dir", state, "--outbox", filepath.Join(dir, "o"), "--escrow-to", escrowPEM}
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"no source":     {[]string{"watch", "--outbox", "o", "--escrow-to", escrowPEM, "--key", seed}, 2, "exactly one of"},
		"two sources":   {append(append([]string{}, base...), "--key", seed, "--model", "m:1"), 2, "exactly one of"},
		"no key":        {base, 2, "are required"},
		"open key":      {append(append([]string{}, base...), "--key", open), 2, "open to other users"},
		"bad escrow":    {[]string{"watch", "--content-dir", state, "--outbox", "o", "--escrow-to", seed, "--key", seed}, 2, "--escrow-to"},
		"empty probe":   {append(append([]string{}, base...), "--key", seed, "--probe", " "), 2, "empty --probe"},
		"bad parent":    {append(append([]string{}, base...), "--key", seed, "--parent", filepath.Join(dir, "absent")), 2, "--parent"},
		"missing wire":  {append(append([]string{}, base...), "--key", seed, "--tripwire", filepath.Join(dir, "absent")), 1, "tripwire"},
		"failing probe": {append(append([]string{}, base...), "--key", seed, "--probe", "false"), 1, "does not pass"},
		"unknown sub":   {[]string{"sit"}, 2, "unknown subcommand"},
		"bare":          {nil, 2, "usage"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCmd(sentinelRun, tc.args...)
			require.Equal(t, tc.code, code, stderr)
			require.Contains(t, stderr, tc.want)
		})
	}
	code, stdout, _ := runCmd(sentinelRun, "help")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "keygen")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"simulated without seed": {append(append([]string{}, base...), "--key", seed, "--tee", "simulated"), "--tee-seed"},
		"unknown tee":            {append(append([]string{}, base...), "--key", seed, "--tee", "quantum"), "--tee"},
		"open tee seed":          {append(append([]string{}, base...), "--key", seed, "--tee", "simulated", "--tee-seed", open), "open to other users"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCmd(sentinelRun, tc.args...)
			require.Equal(t, 2, code, stderr)
			require.Contains(t, stderr, tc.want)
		})
	}
}

// With --tee the sentinel attests every record with the primary's TEE;
// `sentinel identity` prints what the operator pins for it.
func TestSentinel_IdentityAndAttestedWatch(t *testing.T) {
	dir := t.TempDir()
	seed, pub, escrowPEM := sentinelKeys(t, dir)
	teeSeed := filepath.Join(dir, "tee.seed")
	require.NoError(t, os.WriteFile(teeSeed, bytes.Repeat([]byte{0x31}, 32), 0o600))

	code, stdout, stderr := runCmd(sentinelRun, "identity", "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "primary-drill", "--key", seed)
	require.Equal(t, 0, code, stderr)
	var id sentinelIdentity
	require.NoError(t, json.Unmarshal([]byte(stdout), &id))
	require.Equal(t, "simulated", id.TEE)
	require.Len(t, id.MeasurementHex, 64)
	require.Contains(t, id.AttestorPublicKeyPEM, "PUBLIC KEY")
	require.True(t, strings.HasPrefix(id.SentinelKeyID, "sentinel-"))
	attestorPub := filepath.Join(dir, "attestor.pem")
	require.NoError(t, os.WriteFile(attestorPub, []byte(id.AttestorPublicKeyPEM), 0o644))
	code, _, stderr = runCmd(sentinelRun, "identity")
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "--tee is required")

	// The watch: sealed once, then stopped; every record carries the report.
	state, outbox := filepath.Join(dir, "state"), filepath.Join(dir, "outbox")
	require.NoError(t, os.MkdirAll(state, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(state, "adapter.safetensors"), []byte("weights"), 0o644))
	canary := filepath.Join(dir, "canary")
	require.NoError(t, os.WriteFile(canary, []byte("quiet"), 0o600))
	go func() {
		for {
			if m, _ := filepath.Glob(filepath.Join(outbox, "gen-*.seal.json")); len(m) > 0 {
				_ = os.WriteFile(canary, []byte("touched"), 0o600)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	code, stdout, stderr = runCmd(sentinelRun, "watch", "--content-dir", state, "--outbox", outbox, "--escrow-to", escrowPEM, "--key", seed,
		"--tripwire", canary, "--interval", "20ms", "--settle", "0s", "--tee", "simulated", "--tee-seed", teeSeed, "--workload-descriptor", "primary-drill")
	require.Equal(t, 3, code, stderr)
	var res struct {
		TEE            string `json:"tee"`
		MeasurementHex string `json:"measurement_hex"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &res))
	require.Equal(t, "simulated", res.TEE)
	require.Equal(t, id.MeasurementHex, res.MeasurementHex)
	require.Contains(t, stderr, "attests every record")

	pk, err := readEd25519PublicKey(pub)
	require.NoError(t, err)
	chain, _, err := sentinel.ReadChain(outbox, ed25519.PublicKey(pk))
	require.NoError(t, err)
	require.Len(t, chain, 1)
	attestor, err := readEd25519PublicKey(attestorPub)
	require.NoError(t, err)
	meas, err := hex.DecodeString(id.MeasurementHex)
	require.NoError(t, err)
	verifier := tee.NewSimulatedVerifier(attestor, meas)
	m, err := chain[0].Attested(verifier)
	require.NoError(t, err)
	require.Equal(t, id.MeasurementHex, hex.EncodeToString(m))
	c, _, err := sentinel.ReadCompromise(outbox, ed25519.PublicKey(pk))
	require.NoError(t, err)
	_, err = c.Attested(verifier)
	require.NoError(t, err)
	h, _, err := sentinel.ReadHeartbeat(outbox, ed25519.PublicKey(pk))
	require.NoError(t, err)
	_, err = h.Attested(verifier)
	require.NoError(t, err)
}

// The operator's flow: sign a failover policy pinning the sentinel, check it.
func TestFailover_IssueVerify(t *testing.T) {
	dir := t.TempDir()
	_, spub, _ := sentinelKeys(t, dir)
	opSeed, opPub := filepath.Join(dir, "operator.seed"), filepath.Join(dir, "operator.pem")
	code, _, stderr := runStop("keygen", "-out", opSeed, "-pub", opPub)
	require.Equal(t, 0, code, stderr)
	policy := filepath.Join(dir, "failover.json")
	measurement := strings.Repeat("AB", 48)
	issue := []string{"issue", "--key", opSeed, "--kid", "operator-1", "--serial", "3", "--sentinel-pub", spub,
		"--standby-kind", "gcp-sev-snp", "--standby-endpoint", "https://standby.example:8443", "--standby-measurement", measurement,
		"--heartbeat-timeout", "90s", "--quarantine", "10s", "--max-rpo", "1h", "--reason", "drill", "--out", policy}
	code, stdout, stderr := runCmd(failoverRun, issue...)
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "serial 3")

	code, stdout, stderr = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 0, code, stderr)
	for _, want := range []string{"serial 3", "stands", "gcp-sev-snp https://standby.example:8443", strings.ToLower(measurement),
		"compromise report, no heartbeat for 90s", "required gate:    EQUIVALENT; quarantine 10s; max RPO 3600s", "reason:           drill",
		"primary TEE:      not pinned"} {
		require.Contains(t, stdout, want)
	}

	// The primary pinned by its TEE, and `stopped` bounded (ADR 0017).
	pinned := filepath.Join(dir, "failover-pinned.json")
	primaryMeas := strings.Repeat("cd", 48)
	code, _, stderr = runCmd(failoverRun, append(replace(issue, policy, pinned), "--primary-kind", "gcp-sev-snp", "--primary-measurement", strings.ToUpper(primaryMeas),
		"--stopped-grace", "5m")...)
	require.Equal(t, 0, code, stderr)
	code, stdout, stderr = runCmd(failoverRun, "verify", "--in", pinned, "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 0, code, stderr)
	require.Contains(t, stdout, "primary TEE:      gcp-sev-snp, measurements "+primaryMeas+" (every record must carry its report)")
	require.Contains(t, stdout, "stopped and not back within 300s")
	code, stdout, _ = runCmd(failoverRun, "verify", "--in", pinned, "--pubkey", opPub, "--kid", "operator-1", "--json")
	require.Equal(t, 0, code)
	var pv struct {
		Policy failover.Policy `json:"policy"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &pv))
	require.NotNil(t, pv.Policy.Primary)
	require.Equal(t, []string{primaryMeas}, pv.Policy.Primary.Measurements)
	require.Equal(t, int64(300), pv.Policy.Triggers.StoppedGraceSeconds)

	// A simulated primary is pinned by its attestation key too.
	simPinned := filepath.Join(dir, "failover-sim.json")
	code, _, stderr = runCmd(failoverRun, append(replace(issue, policy, simPinned), "--primary-kind", "simulated", "--primary-measurement", strings.Repeat("ab", 32),
		"--primary-attestor-pub", spub)...)
	require.Equal(t, 0, code, stderr)
	code, _, stderr = runCmd(failoverRun, append(replace(issue, policy, filepath.Join(dir, "x.json")), "--primary-kind", "simulated", "--primary-measurement", strings.Repeat("ab", 32))...)
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "attestation key")
	code, _, stderr = runCmd(failoverRun, append(replace(issue, policy, filepath.Join(dir, "y.json")), "--primary-kind", "gcp-sev-snp")...)
	require.Equal(t, 2, code)
	require.Contains(t, stderr, "go together")
	code, stdout, _ = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1", "--json")
	require.Equal(t, 0, code)
	var v struct {
		Policy   failover.Policy `json:"policy"`
		Sentinel string          `json:"sentinel"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &v))
	require.Equal(t, uint64(3), v.Policy.Serial)
	require.True(t, v.Policy.Triggers.CompromiseReport)

	// Another operator's ID, an edited policy: exit 4.
	code, _, _ = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-2")
	require.Equal(t, 4, code)
	raw, err := os.ReadFile(policy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policy, bytes.Replace(raw, []byte("standby.example"), []byte("elsewhere.example"), 1), 0o644))
	code, _, stderr = runCmd(failoverRun, "verify", "--in", policy, "--pubkey", opPub, "--kid", "operator-1")
	require.Equal(t, 4, code)
	require.Contains(t, stderr, "signature")

	// Refused before signing: plain http, no trigger, a gate level that is
	// not one, missing flags, a bad key.
	for name, tc := range map[string]struct {
		args []string
		code int
		want string
	}{
		"plain http":  {replace(issue, "https://standby.example:8443", "http://standby.example:8443"), 1, "https required"},
		"no trigger":  {append(replace(issue, "90s", "0s"), "--no-compromise-trigger"), 1, "no trigger"},
		"bad gate":    {append(append([]string{}, issue...), "--require-gate", "CLOSE"), 1, "require_gate"},
		"missing":     {[]string{"issue", "--key", opSeed}, 2, "are required"},
		"bad key":     {replace(issue, opSeed, spub), 1, "seed file"},
		"bad pub":     {replace(issue, spub, filepath.Join(dir, "escrow.pem")), 1, "--sentinel-pub"},
		"unknown sub": {[]string{"pause"}, 2, "unknown subcommand"},
		"bare":        {nil, 2, "usage"},
		"verify args": {[]string{"verify"}, 2, "are required"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCmd(failoverRun, tc.args...)
			require.Equal(t, tc.code, code, stderr)
			require.Contains(t, stderr, tc.want)
		})
	}
	code, _, stderr = runCmd(failoverRun, append(append([]string{}, issue...), "--require-gate", "none")...)
	require.Equal(t, 0, code, stderr)
	code, stdout, _ = runCmd(failoverRun, "help")
	require.Equal(t, 0, code)
	require.Contains(t, stdout, "issue")
}

// replace returns args with one value swapped.
func replace(args []string, old, new string) []string {
	out := append([]string{}, args...)
	for i, a := range out {
		if a == old {
			out[i] = new
		}
	}
	return out
}
