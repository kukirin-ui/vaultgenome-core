// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// detailedVerifier says more than the measurement, as the confidential
// GPU verifier does, around the simulated one.
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

// What the destination's verifier said beyond the measurement — the
// chip, the GPUs, this verifier's own evaluation — is on the
// CROSS_CLOUD_ATTESTATION_VERIFIED record the key release rests on.
func TestCoordinateRestore_AttestationRecordCarriesTheVerifiersDetail(t *testing.T) {
	t.Parallel()
	want := &tee.AttestationDetail{Provider: tee.ProviderAzureCGPU, Product: "Genoa", PCRSelection: "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14",
		GPUs:        []tee.GPUVerdict{{Key: "GPU-0", HWModel: "GH100", DriverVersion: "580.95.05", VBIOSVersion: "96.00.9F.00.01", Issuer: "own evaluation"}},
		Evaluations: []tee.GPUEvaluation{{ReportParsed: true, NonceMatch: true, ChainVerified: true, FWIDMatch: true, SignatureVerified: true, HWModel: "GH100", MeasurementsMatch: true}}}
	f := makeFixtureWith(t, func(v tee.Verifier) tee.Verifier { return detailedVerifier{Verifier: v, detail: want} })

	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)
	require.Equal(t, audit_event.KindCrossCloudAttestationVerified, f.auditChain.events[1].Kind)

	var verified attestationVerifiedPayload
	require.NoError(t, json.Unmarshal(f.auditChain.events[1].Payload, &verified))
	require.Equal(t, want, verified.DestinationDetail)
	require.Contains(t, string(f.auditChain.events[1].Payload), `"destination_detail":{"provider":"azure-cgpu","product":"Genoa"`)
	require.Contains(t, string(f.auditChain.events[1].Payload), `"hw_model":"GH100"`)
}

// A verifier with nothing beyond the measurement leaves the field off.
func TestCoordinateRestore_AttestationRecordWithoutDetail(t *testing.T) {
	t.Parallel()
	f := makeFixture(t)
	_, err := f.coord.CoordinateRestore(context.Background(), validRequest(f))
	require.NoError(t, err)
	var verified attestationVerifiedPayload
	require.NoError(t, json.Unmarshal(f.auditChain.events[1].Payload, &verified))
	require.Nil(t, verified.DestinationDetail)
	require.NotContains(t, string(f.auditChain.events[1].Payload), "destination_detail")
}
