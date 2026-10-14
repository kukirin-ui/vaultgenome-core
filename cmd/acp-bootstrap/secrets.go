// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// hostSealer is the sealer of this destination's host (ADR 0023): the
// vTPM on a TDX or Azure confidential GPU host (ADR 0022), the chip's
// derived key on SEV-SNP, the simulated TEE's weak key off hardware.
// The closer, when not nil, holds the device the sealer opened.
func hostSealer(cfg TEEConfig) (tee.Sealer, io.Closer, tee.Provider, error) {
	provider, err := tee.ParseProvider(cfg.Provider)
	if err != nil {
		return nil, nil, "", fmt.Errorf("acp-bootstrap: tee.provider: %w", err)
	}
	switch provider {
	case tee.ProviderGCPTDX, tee.ProviderAzureCGPU:
		s, err := tee.NewVTPMSealer(tee.VTPMSealerConfig{TPM2ToolsDir: cfg.TPM2ToolsDir, PCRs: cfg.VTPMSealPCRs})
		if err != nil {
			return nil, nil, "", fmt.Errorf("acp-bootstrap: tee.vtpm_seal_pcrs: %w", err)
		}
		return s, nil, provider, nil
	default:
		producer, err := buildTEEProducer(cfg)
		if err != nil {
			return nil, nil, "", err
		}
		s, closer, err := tee.SealerFor(producer, tee.SealerOptions{SEVGuestDevice: cfg.SEVDevice(), TPM2ToolsDir: cfg.TPM2ToolsDir, VTPMSealPCRs: cfg.VTPMSealPCRs})
		if err != nil {
			return nil, nil, "", fmt.Errorf("acp-bootstrap: %w", err)
		}
		return s, closer, provider, nil
	}
}

// readSecret reads the secret file named by field: bare bytes (exactly
// wantLen of them when wantLen is set, any number otherwise), or a file
// sealed to this host by `acp-bootstrap seal-keys`, opened with the
// host's sealer under the field's name. An empty file is refused.
func readSecret(cfg TEEConfig, path string, wantLen int, field string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: read %s (%q): %w", field, path, err)
	}
	if !tee.IsSealedSecret(raw) {
		if wantLen > 0 && len(raw) != wantLen {
			return nil, fmt.Errorf("acp-bootstrap: %s (%q) must be exactly %d bytes (got %d), or a file sealed by `acp-bootstrap seal-keys`", field, path, wantLen, len(raw))
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("acp-bootstrap: %s (%q) is empty", field, path)
		}
		return raw, nil
	}
	sealer, closer, provider, err := hostSealer(cfg)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: %s (%q) is sealed and this host cannot open it: %w", field, path, err)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	plain, err := tee.OpenSecret(raw, sealer, provider, field)
	if err != nil {
		return nil, fmt.Errorf("acp-bootstrap: %s (%q): %w", field, path, err)
	}
	if (wantLen > 0 && len(plain) != wantLen) || len(plain) == 0 {
		n := len(plain)
		zero(plain)
		return nil, fmt.Errorf("acp-bootstrap: %s (%q): the sealed secret is %d bytes, want %d", field, path, n, wantLen)
	}
	return plain, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
