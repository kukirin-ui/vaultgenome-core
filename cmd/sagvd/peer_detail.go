// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// peerDetailLogFields says, on the session-opened log line, what the
// verifier saw beyond the measurement: the platform and each GPU with who
// vouched for it, and whether this verifier's own evaluations were
// complete. The full record goes on the TRUST_EVALUATED audit event; the
// log line is the operator's glance. Nothing for a verifier with nothing
// more to say.
func peerDetailLogFields(d *tee.AttestationDetail) []any {
	if d == nil {
		return nil
	}
	fields := []any{"peer_provider", string(d.Provider)}
	if d.Product != "" {
		fields = append(fields, "peer_product", d.Product)
	}
	if d.PCRSelection != "" {
		fields = append(fields, "peer_pcrs", d.PCRSelection)
	}
	if len(d.GPUs) > 0 {
		gpus := make([]string, 0, len(d.GPUs))
		for _, g := range d.GPUs {
			gpus = append(gpus, fmt.Sprintf("%s %s driver %s vbios %s (%s)", g.Key, g.HWModel, g.DriverVersion, g.VBIOSVersion, g.Issuer))
		}
		fields = append(fields, "peer_gpus", strings.Join(gpus, "; "))
	}
	if len(d.Evaluations) > 0 {
		complete := 0
		for _, e := range d.Evaluations {
			if e.Complete() {
				complete++
			}
		}
		fields = append(fields, "peer_gpu_evaluations", fmt.Sprintf("%d/%d complete", complete, len(d.Evaluations)))
	}
	return fields
}
