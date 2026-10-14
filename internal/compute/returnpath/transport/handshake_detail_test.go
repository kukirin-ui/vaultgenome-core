// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package transport

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// detailedVerifier is a verifier that says more than the measurement — as
// the confidential GPU verifier does — wrapped around the simulated one.
type detailedVerifier struct {
	tee.Verifier
	detail *tee.AttestationDetail
}

func (d detailedVerifier) VerifyDetailed(ev tee.Evidence, nonce tee.Nonce) (tee.Measurement, *tee.AttestationDetail, error) {
	m, err := d.Verifier.Verify(ev, nonce)
	if err != nil {
		return nil, nil, err
	}
	return m, d.detail, nil
}

// What the verifier said beyond the measurement reaches the session
// state on the side that verified it, and only there: the server's
// verifier of the client (the worker's GPUs, for sagvd's audit record),
// the client's verifier of the server.
func TestHandshake_PeerDetailReachesTheSessionState(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	worker := &tee.AttestationDetail{Provider: tee.ProviderAzureCGPU, Product: "Genoa",
		GPUs: []tee.GPUVerdict{{Key: "GPU-0", HWModel: "GH100", DriverVersion: "580.95.05", Issuer: "own evaluation"}}}
	c, s, cs, ss := runLoopbackHandshake(t, peers, func(cfg *HandshakeConfig) {
		if cfg.Role == RoleServer {
			cfg.Verifier = detailedVerifier{Verifier: cfg.Verifier, detail: worker}
		}
	})
	defer func() { _ = c.Close(); _ = s.Close() }()

	require.Equal(t, worker, ss.PeerDetail, "the server verified the worker: its detail is in the server's state")
	require.True(t, peers.clientProducer.Measurement().Equal(ss.PeerMeasurement))
	require.Nil(t, cs.PeerDetail, "the client's verifier of the server had nothing beyond the measurement")
	require.True(t, peers.serverProducer.Measurement().Equal(cs.PeerMeasurement))
}

// A plain verifier leaves the detail empty on both sides.
func TestHandshake_NoDetailFromAPlainVerifier(t *testing.T) {
	t.Parallel()
	peers := newPeerTEEs(t)
	c, s, cs, ss := runLoopbackHandshake(t, peers)
	defer func() { _ = c.Close(); _ = s.Close() }()
	require.Nil(t, cs.PeerDetail)
	require.Nil(t, ss.PeerDetail)
}
