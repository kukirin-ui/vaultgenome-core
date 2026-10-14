// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// The daemon's key files — the authority's signing seed, the audit seed,
// the session sealing key — are read through here: bare bytes of the
// expected length, or a file `sagvd seal-keys` sealed to this host's TEE
// (ADR 0023), opened with the host's sealer at read time. A sealed file is
// bound to its name: one sealed as the audit seed does not open as the
// authority's.

// hostSealer builds this host's sealer from the TEE config alone, so a
// sealed key file can be opened before the daemon's materials exist. A
// vTPM sealer needs no producer; the others need the host's identity,
// which the producer reads from the chip.
func hostSealer(cfg TEEConfig) (tee.Sealer, io.Closer, tee.Provider, error) {
	provider, err := cfg.ProviderKind()
	if err != nil {
		return nil, nil, "", err
	}
	switch provider {
	case tee.ProviderGCPTDX, tee.ProviderAzureCGPU:
		s, err := tee.NewVTPMSealer(tee.VTPMSealerConfig{TPM2ToolsDir: cfg.TPM2ToolsDir, PCRs: cfg.VTPMSealPCRs})
		if err != nil {
			return nil, nil, "", fmt.Errorf("sagvd: tee.vtpm_seal_pcrs: %w", err)
		}
		return s, nil, provider, nil
	default:
		_, producer, err := buildTEEProducer(cfg)
		if err != nil {
			return nil, nil, "", err
		}
		s, closer, err := tee.SealerFor(producer, tee.SealerOptions{SEVGuestDevice: cfg.SEVDevice(), TPM2ToolsDir: cfg.TPM2ToolsDir, VTPMSealPCRs: cfg.VTPMSealPCRs})
		if err != nil {
			return nil, nil, "", fmt.Errorf("sagvd: %w", err)
		}
		return s, closer, provider, nil
	}
}

// readSecret reads the key file named by field: bare bytes (exactly
// wantLen of them when wantLen is set, any number otherwise) — exactly wantLen bare
// bytes, or a sealed key file opened by this host's TEE.
func readSecret(cfg TEEConfig, path string, wantLen int, field string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sagvd: read %s (%q): %w", field, path, err)
	}
	if !tee.IsSealedSecret(raw) {
		if wantLen > 0 && len(raw) != wantLen {
			return nil, fmt.Errorf("sagvd: %s (%q) must be exactly %d bytes (got %d), or a key file sealed by `sagvd seal-keys`", field, path, wantLen, len(raw))
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("sagvd: %s (%q) is empty", field, path)
		}
		return raw, nil
	}
	sealer, closer, provider, err := hostSealer(cfg)
	if err != nil {
		return nil, fmt.Errorf("sagvd: %s (%q) is sealed and this host cannot open it: %w", field, path, err)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	plain, err := tee.OpenSecret(raw, sealer, provider, field)
	if err != nil {
		return nil, fmt.Errorf("sagvd: %s (%q): %w", field, path, err)
	}
	if (wantLen > 0 && len(plain) != wantLen) || len(plain) == 0 {
		n := len(plain)
		for i := range plain {
			plain[i] = 0
		}
		return nil, fmt.Errorf("sagvd: %s (%q): the sealed key is %d bytes, want %d", field, path, n, wantLen)
	}
	return plain, nil
}
