// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Off its host a hardware producer cannot be built, and the refusal says
// what is missing: configfs-tsm for a SEV-SNP or TDX guest, tpm2-tools or
// the attest command for an Azure confidential GPU VM. A family this build
// has no producer for, or no provider at all, is refused by name.
func TestBuildTEEProducer_Refusals(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		cfg  TEEConfig
		want string
	}{
		"tdx without configfs-tsm":              {TEEConfig{Provider: "gcp-tdx", TSMReportDir: filepath.Join(dir, "no-such-tsm")}, "configfs-tsm"},
		"sev-snp without configfs-tsm":          {TEEConfig{Provider: "gcp-sev-snp", TSMReportDir: filepath.Join(dir, "no-such-tsm")}, "configfs-tsm"},
		"azure-cgpu without tpm2-tools":         {TEEConfig{Provider: "azure-cgpu", GPUAttestCommand: []string{"/opt/nvidia/attest"}, TPM2ToolsDir: dir}, "tpm2_nvread"},
		"azure-cgpu without the attest command": {TEEConfig{Provider: "azure-cgpu", TPM2ToolsDir: dir}, "GPUAttestCommand required"},
		"a family without a producer here":      {TEEConfig{Provider: "aws-nitro"}, `tee.provider "aws-nitro" is not available in this build`},
		"no provider":                           {TEEConfig{}, `tee.provider "" is not available in this build`},
		"simulated without its seed":            {TEEConfig{Provider: "simulated", SeedPath: filepath.Join(dir, "absent")}, "read tee.seed_path"},
		"simulated with no seed path":           {TEEConfig{Provider: "simulated"}, "tee.seed_path required"},
	} {
		if _, err := buildTEEProducer(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err=%v, want an error mentioning %q", name, err, tc.want)
		}
	}
}

// A TDX producer's identity is what its measurement is made of — MRTD and
// the four RTMRs, hex, 48 bytes each — and every other producer has none;
// only an Azure confidential GPU producer has a vTPM boot to report.
func TestTDXAndVTPMIdentityOf(t *testing.T) {
	sim, err := tee.NewSimulated([]byte("w"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tdx := &tee.GCPTDXProducer{}
	if tdxIdentityOf(sim) != nil || tdxIdentityOf(nil) != nil {
		t.Fatal("a producer that is not TDX has a TDX identity")
	}
	id := tdxIdentityOf(tdx)
	if id == nil || id.MRTDHex != strings.Repeat("00", 48) || len(id.RTMRHex) != 4 {
		t.Fatalf("TDX identity: %+v", id)
	}
	for _, r := range id.RTMRHex {
		if r != strings.Repeat("00", 48) {
			t.Fatalf("RTMR: %q", r)
		}
	}
	if vtpmIdentityOf(sim) != nil || vtpmIdentityOf(tdx) != nil || vtpmIdentityOf(nil) != nil {
		t.Fatal("a producer without a vTPM has a vTPM identity")
	}
}
