// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// goodConfig returns a minimal Config that passes Validate. Every
// test below starts from this and mutates the one field it wants to
// exercise, ensuring that no test accidentally fails on an unrelated
// validation rule.
func goodConfig() Config {
	c := DefaultConfig()
	c.TEE.SeedPath = "/tmp/acp-compute-test/tee.seed"
	c.TEE.InsecureSimulation = true
	c.TEE.Peer.PublicKeyPath = "/tmp/acp-compute-test/peer.pub"
	c.TEE.Peer.MeasurementPath = "/tmp/acp-compute-test/peer.meas"
	c.Keys.WorkerSigning.KeyID = "worker-sign-1"
	c.Keys.WorkerSigning.SeedPath = "/tmp/acp-compute-test/worker.seed"
	c.Keys.SessionSealing.KeyID = "session-seal-1"
	c.Keys.SessionSealing.MaterialPath = "/tmp/acp-compute-test/session.key"
	c.Genome.Door.Command = []string{"python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", "/models/base"}
	return c
}

func TestConfig_Validate_RequiresADoor(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Genome.Door.Command = nil
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "genome.door.command required")

	c = goodConfig()
	c.Genome.Door.Command = []string{"  "}
	require.ErrorContains(t, c.Validate(), "genome.door.command required")

	c = goodConfig()
	c.Genome.Door.Env = []string{"PYTHONPATH=/opt/vg", "BROKEN"}
	require.ErrorContains(t, c.Validate(), `genome.door.env entry "BROKEN"`)

	c = goodConfig()
	c.Genome.Door.TimeoutSeconds = -1
	require.ErrorContains(t, c.Validate(), "genome.door.timeout_seconds")

	c = goodConfig()
	c.Genome.Door.TimeoutSeconds = 90
	require.NoError(t, c.Validate())
	require.Equal(t, 90*time.Second, c.Genome.Door.Timeout())
}

func TestDefaultConfig_IsSelfConsistent(t *testing.T) {
	t.Parallel()
	c := DefaultConfig()
	// Default is partial; it is specifically meant as an overlay
	// target for JSON decoding, and expectedly fails Validate because
	// path fields are empty.
	err := c.Validate()
	require.Error(t, err, "DefaultConfig alone must not validate")
	require.Contains(t, err.Error(), "tee.seed_path")
}

func TestConfig_Validate_Happy(t *testing.T) {
	t.Parallel()
	require.NoError(t, goodConfig().Validate())
}

func TestConfig_Validate_RejectsEmptyVaultAddress(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.Address = ""
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.address required")
}

func TestConfig_Validate_RejectsMalformedVaultAddress(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.Address = "not-a-host-port"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.address invalid")
}

func TestConfig_Validate_TLSFieldsRequiredWhenEnabled(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.TLS.Enabled = true
	err := c.Validate()
	require.Error(t, err)
	for _, want := range []string{
		"vault.tls.client_cert",
		"vault.tls.client_key",
		"vault.tls.ca_bundle",
		"vault.tls.server_name",
	} {
		require.Contains(t, err.Error(), want, "expected missing-field complaint: %s", want)
	}
}

func TestConfig_Validate_TLSIgnoredWhenDisabled(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Vault.TLS.Enabled = false
	c.Vault.TLS.ClientCert = "" // still empty — must not complain
	require.NoError(t, c.Validate())
}

func TestConfig_Validate_RejectsEmptyWorkloadDescriptor(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.TEE.WorkloadDescriptor = ""
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "tee.workload_descriptor required")
}

func TestConfig_Validate_RejectsEmptyKeyIDs(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Keys.WorkerSigning.KeyID = ""
	c.Keys.SessionSealing.KeyID = ""
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "keys.worker_signing.kid required")
	require.Contains(t, err.Error(), "keys.session_sealing.kid required")
}

func TestConfig_Validate_RejectsNonPositiveTimeouts(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Runtime.JobTimeoutSeconds = 0
	c.Runtime.HandshakeTimeoutSeconds = -5
	c.Runtime.DialBackoffInitialMs = 0
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "job_timeout_seconds")
	require.Contains(t, err.Error(), "handshake_timeout_seconds")
	require.Contains(t, err.Error(), "dial_backoff_initial_ms")
}

func TestConfig_Validate_RejectsBackoffInversion(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Runtime.DialBackoffInitialMs = 1000
	c.Runtime.DialBackoffMaxMs = 500
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "dial_backoff_max_ms")
}

func TestConfig_Validate_RejectsNegativeIdle(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Runtime.IdleBetweenJobsMs = -1
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "idle_between_jobs_ms")
}

func TestConfig_Validate_RejectsInvalidLogLevel(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Log.Level = "louder"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "log.level")
}

func TestConfig_Validate_RejectsInvalidLogFormat(t *testing.T) {
	t.Parallel()
	c := goodConfig()
	c.Log.Format = "xml"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "log.format")
}

func TestConfig_Validate_AggregatesAllProblems(t *testing.T) {
	t.Parallel()
	// Intentionally break two unrelated rules and assert BOTH appear.
	c := goodConfig()
	c.Vault.Address = ""
	c.Log.Level = "shouting"
	err := c.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault.address required")
	require.Contains(t, err.Error(), "log.level")
}

func TestRuntime_DurationAccessors(t *testing.T) {
	t.Parallel()
	r := RuntimeConfig{
		JobTimeoutSeconds:       5,
		HandshakeTimeoutSeconds: 7,
		DialBackoffInitialMs:    250,
		DialBackoffMaxMs:        9000,
		IdleBetweenJobsMs:       42,
	}
	require.Equal(t, 5*time.Second, r.JobTimeout())
	require.Equal(t, 7*time.Second, r.HandshakeTimeout())
	require.Equal(t, 250*time.Millisecond, r.DialBackoffInitial())
	require.Equal(t, 9*time.Second, r.DialBackoffMax())
	require.Equal(t, 42*time.Millisecond, r.IdleBetweenJobs())
}

func TestDecodeConfig_OverlaysDefaults(t *testing.T) {
	t.Parallel()
	// Only set a few overrides; everything else must come from
	// DefaultConfig. We verify by asserting an unset runtime knob keeps
	// its default value.
	jsonBody := `{
		"vault": {"address": "10.0.0.5:7443"},
		"tee":   {"workload_descriptor": "custom-worker-v2"}
	}`
	c, err := DecodeConfig(strings.NewReader(jsonBody))
	require.NoError(t, err)
	require.Equal(t, "10.0.0.5:7443", c.Vault.Address)
	require.Equal(t, "custom-worker-v2", c.TEE.WorkloadDescriptor)
	require.Equal(t, 120, c.Runtime.JobTimeoutSeconds, "default must survive partial override")
	require.Equal(t, "info", c.Log.Level)
}

func TestDecodeConfig_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	// An operator typo — `vault.addres` (missing 's') — must fail loud
	// at startup, not silently ignore the key and use the default.
	jsonBody := `{"vault": {"addres": "x:1"}}`
	_, err := DecodeConfig(strings.NewReader(jsonBody))
	require.Error(t, err)
}

func TestLoadConfigFile_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "acp-compute.json")
	body := `{
		"vault":   {"address": "127.0.0.1:6443"},
		"tee":     {
			"workload_descriptor": "test-worker",
			"seed_path": "/x/tee.seed",
			"insecure_simulation": true,
			"peer": {"public_key_path": "/x/peer.pub", "measurement_path": "/x/peer.meas"}
		},
		"keys": {
			"worker_signing":  {"kid": "wk-1", "seed_path": "/x/w.seed"},
			"session_sealing": {"kid": "ss-1", "material_path": "/x/ss.key"}
		},
		"genome": {
			"door": {"command": ["python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", "/x/base"],
			         "env": ["PYTHONPATH=/x/workers/genome"], "timeout_seconds": 600}
		}
	}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	c, err := LoadConfigFile(path)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:6443", c.Vault.Address)
	require.Equal(t, "wk-1", c.Keys.WorkerSigning.KeyID)
	require.Equal(t, []string{"python3", "-m", "vg_genome", "door", "--stdin-genome", "--base", "/x/base"}, c.Genome.Door.Command)
	require.Equal(t, []string{"PYTHONPATH=/x/workers/genome"}, c.Genome.Door.Env)
	require.Equal(t, 600, c.Genome.Door.TimeoutSeconds)

	// End-to-end with validation: default timeouts + supplied paths
	// must pass the full check.
	require.NoError(t, c.Validate())
}

func TestLoadConfigFile_MissingFileErrors(t *testing.T) {
	t.Parallel()
	_, err := LoadConfigFile("/no/such/path/acp-compute.json")
	require.Error(t, err)
}

func TestConfig_Validate_TEEProviders(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate func(c *Config)
		want   []string
	}{
		"simulated by default":              {func(c *Config) {}, nil},
		"unknown provider":                  {func(c *Config) { c.TEE.Provider = "tdx" }, []string{"tee.provider invalid"}},
		"unsupported provider":              {func(c *Config) { c.TEE.Provider = "aws-nitro" }, []string{"not available in this build"}},
		"simulated without acknowledgement": {func(c *Config) { c.TEE.InsecureSimulation = false }, []string{"tee.insecure_simulation=true"}},
		"simulated without seed":            {func(c *Config) { c.TEE.SeedPath = "" }, []string{"tee.seed_path required"}},
		"tsm dir on simulated":              {func(c *Config) { c.TEE.TSMReportDir = "/sys/kernel/config/tsm/report" }, []string{"tsm_report_dir applies to gcp-sev-snp"}},
		"sev-snp with simulated leftovers": {func(c *Config) { c.TEE.Provider = "gcp-sev-snp" },
			[]string{"tee.seed_path applies to the simulated provider", "tee.insecure_simulation applies to the simulated provider"}},
		"sev-snp clean":                  {func(c *Config) { c.TEE.Provider = "gcp-sev-snp"; c.TEE.SeedPath = ""; c.TEE.InsecureSimulation = false }, nil},
		"peer unknown":                   {func(c *Config) { c.TEE.Peer.Provider = "sgx?" }, []string{"tee.peer.provider invalid"}},
		"peer unsupported":               {func(c *Config) { c.TEE.Peer.Provider = "azure-sgx" }, []string{"no verifier this build can run"}},
		"simulated peer without key":     {func(c *Config) { c.TEE.Peer.PublicKeyPath = "" }, []string{"tee.peer.public_key_path required"}},
		"simulated peer with AMD fields": {func(c *Config) { c.TEE.Peer.AMDCertChainPath = "/x/chain.pem" }, []string{"apply to a gcp-sev-snp or azure-cgpu peer only"}},
		"sev-snp peer without chain": {func(c *Config) { c.TEE.Peer.Provider = "gcp-sev-snp"; c.TEE.Peer.PublicKeyPath = "" },
			[]string{"tee.peer.amd_cert_chain_path required"}},
		"sev-snp peer with a key": {func(c *Config) {
			c.TEE.Peer.Provider = "gcp-sev-snp"
			c.TEE.Peer.AMDCertChainPath = "/x/chain.pem"
		}, []string{"tee.peer.public_key_path applies to a simulated peer"}},
		"sev-snp peer clean": {func(c *Config) {
			c.TEE.Peer.Provider = "gcp-sev-snp"
			c.TEE.Peer.PublicKeyPath = ""
			c.TEE.Peer.AMDCertChainPath = "/x/chain.pem"
			c.TEE.Peer.VCEKCacheDir = "/var/lib/acp/vcek"
			c.TEE.Peer.MinReportedTCB = 7
		}, nil},
		"no peer measurement": {func(c *Config) { c.TEE.Peer.MeasurementPath = "" }, []string{"tee.peer.measurement_path required"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := goodConfig()
			tc.mutate(&c)
			err := c.Validate()
			if len(tc.want) == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, w := range tc.want {
				require.Contains(t, err.Error(), w)
			}
		})
	}
}

func TestPCRDigests(t *testing.T) {
	t.Parallel()
	good := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	out, err := pcrDigests([]string{good, " " + good + "\n"})
	require.NoError(t, err)
	require.Len(t, out, 2)
	require.Len(t, out[0], 32)
	require.Equal(t, out[0], out[1], "whitespace around a digest is not part of it")
	for _, bad := range []string{"zz", good[:62], good + "00"} {
		_, err := pcrDigests([]string{good, bad})
		require.ErrorContains(t, err, "not a 32-byte hex digest", bad)
	}
	out, err = pcrDigests(nil)
	require.NoError(t, err)
	require.Empty(t, out)
}
