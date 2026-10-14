// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"fmt"
	"io"
	"os"
)

// SealerOptions is what a host's sealer needs beyond its producer.
type SealerOptions struct {
	// SEVGuestDevice is the sev-guest device a SEV-SNP host derives its
	// sealing key through.
	SEVGuestDevice string
	// TPM2ToolsDir and VTPMSealPCRs configure the vTPM sealer of a TDX or
	// Azure confidential GPU host (ADR 0022); empty means PATH and the
	// default selection.
	TPM2ToolsDir string
	VTPMSealPCRs string
}

// SealerFor returns the sealer of the host the producer attests for, and
// what to close when done with it (nil when nothing was opened).
func SealerFor(p Producer, opts SealerOptions) (Sealer, io.Closer, error) {
	switch t := p.(type) {
	case *Simulated:
		return t, nil, nil
	case *GCPSEVProducer:
		dev, err := os.OpenFile(opts.SEVGuestDevice, os.O_RDWR, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("sealer: open %s (the sev-guest driver must be loaded; the daemon needs access to it): %w", opts.SEVGuestDevice, err)
		}
		return NewGCPSEVSealer(dev, t.Measurement(), t.Policy()), dev, nil
	case *GCPTDXProducer, *AzureCGPUProducer:
		s, err := NewVTPMSealer(VTPMSealerConfig{TPM2ToolsDir: opts.TPM2ToolsDir, PCRs: opts.VTPMSealPCRs})
		if err != nil {
			return nil, nil, err
		}
		return s, nil, nil
	default:
		return nil, nil, fmt.Errorf("sealer: %T has no sealer in this build", p)
	}
}
