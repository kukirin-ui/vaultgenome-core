// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixture under testdata/nitro is a document signed by a synthetic
// five-certificate P-384 chain at 2026-09-22T12:00:00Z (the tee package's
// test fixture wrote it), with its root beside it. Its PCR0 is the SHA-384
// the fixture derives for "cli-fixture".
const (
	fixtureDoc  = "testdata/nitro/synthetic-attestation-document.bin"
	fixtureRoot = "testdata/nitro/synthetic-root.pem"
	fixtureAt   = "2026-09-22T12:00:00Z"
)

func fixturePCR0() string {
	h := sha512.Sum384([]byte("vg-nitro-pcr-cli-fixture-0"))
	return hex.EncodeToString(h[:])
}

func TestAttestNitro_VerifiesFixtureAtCaptureTime(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := attestCmd([]string{"nitro", "--doc", fixtureDoc, "--root", fixtureRoot, "--expected-pcr0", fixturePCR0()}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	out := stdout.String()
	require.Contains(t, out, "VERIFIED at 2026-09-22T12:00:00Z")
	require.Contains(t, out, "module      i-0e35190ae3157095d-enc019e0512a5715d4f")
	require.Contains(t, out, "root        CN=aws.nitro-enclaves")
	require.Contains(t, out, "pcr0 match  true")
	require.Contains(t, out, "nonce       "+hex.EncodeToString([]byte("0123456789abcdef")))
	require.Contains(t, out, "debug       false")
}

func TestAttestNitro_JSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := attestCmd([]string{"nitro", "--doc", fixtureDoc, "--root", fixtureRoot, "--at", fixtureAt, "--json"}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())
	var out nitroAuditOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.True(t, out.Verified)
	require.Equal(t, fixturePCR0(), out.PCRs["0"])
	require.Len(t, out.Chain, 5)
	require.Equal(t, hex.EncodeToString([]byte("acpctl attest nitro fixture")), out.UserData)
	require.Nil(t, out.ExpectedPCR0Matches)
	require.Empty(t, out.Error)
}

func TestAttestNitro_Refusals(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"expired_at_now", []string{"nitro", "--doc", fixtureDoc, "--root", fixtureRoot, "--at", "now"}, 5, "NOT VERIFIED"},
		{"expired_a_day_later", []string{"nitro", "--doc", fixtureDoc, "--root", fixtureRoot, "--at", "2026-09-23T12:00:00Z"}, 5, "certificate chain"},
		{"builtin_root_does_not_anchor_synthetic_chain", []string{"nitro", "--doc", fixtureDoc}, 5, "cabundle[0] is not a pinned root"},
		{"pcr0_mismatch", []string{"nitro", "--doc", fixtureDoc, "--root", fixtureRoot, "--expected-pcr0", strings.Repeat("ab", 48)}, 5, "PCR0 is not the expected value"},
		{"doc_missing_flag", []string{"nitro"}, 2, "--doc is required"},
		{"doc_absent_file", []string{"nitro", "--doc", "testdata/nitro/no-such-file"}, 1, "no such file"},
		{"bad_at", []string{"nitro", "--doc", fixtureDoc, "--at", "yesterday"}, 2, "RFC 3339"},
		{"bad_expected_pcr0", []string{"nitro", "--doc", fixtureDoc, "--expected-pcr0", "zz"}, 2, "hex"},
		{"bad_root_file", []string{"nitro", "--doc", fixtureDoc, "--root", fixtureDoc}, 2, "no CERTIFICATE block"},
		{"unknown_subcommand", []string{"sgx"}, 2, "unknown subcommand"},
		{"no_subcommand", nil, 2, "usage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := attestCmd(tc.args, &stdout, &stderr)
			require.Equal(t, tc.code, code)
			require.Contains(t, stdout.String()+stderr.String(), tc.want)
		})
	}
}

func TestAttestNitro_TamperedFixture(t *testing.T) {
	raw, err := os.ReadFile(fixtureDoc)
	require.NoError(t, err)
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0x01
	path := filepath.Join(t.TempDir(), "tampered.bin")
	require.NoError(t, os.WriteFile(path, tampered, 0o600))
	var stdout, stderr bytes.Buffer
	code := attestCmd([]string{"nitro", "--doc", path, "--root", fixtureRoot, "--json"}, &stdout, &stderr)
	require.Equal(t, 5, code)
	var out nitroAuditOutput
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
	require.False(t, out.Verified)
	require.Contains(t, out.Error, "COSE signature")
}
