// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package receipt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// simulated is a stand-in TEE; each seed is a different key and a
// different workload, so a different measurement.
func simulated(t *testing.T, seed byte) *tee.Simulated {
	t.Helper()
	s, err := tee.NewSimulated([]byte{'w', seed}, bytes.Repeat([]byte{seed}, 32))
	require.NoError(t, err)
	return s
}

func sample(m tee.Measurement) Receipt {
	at := time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)
	return Receipt{
		Schema:                 Schema,
		KeyID:                  "genome-aaaaaaaaaaaa-g1-bbbbbbbbbbbb",
		DecisionID:             "drill-1",
		RequestID:              "req-1",
		TokenID:                "tok-1",
		DestinationKind:        string(tee.ProviderSimulated),
		DestinationMeasurement: hex.EncodeToString(m),
		BundleSHA256:           strings.Repeat("ab", 32),
		Generation:             1,
		ContentKind:            "dir",
		PayloadSHA256:          "sha256:" + strings.Repeat("cd", 32),
		TreeSHA256:             strings.Repeat("ef", 32),
		Files:                  3,
		Bytes:                  81920,
		KeyReceivedAt:          at,
		RestoredAt:             at.Add(1500 * time.Millisecond),
		RestoreSeconds:         1.2,
	}
}

// The destination's TEE signs a receipt; the source verifies it with the
// verifier it trusts for that TEE and learns the measurement.
func TestSignVerify_RoundTrip(t *testing.T) {
	dest := simulated(t, 1)
	signed, err := Sign(sample(dest.Measurement()), dest)
	require.NoError(t, err)

	got, m, err := Verify(signed, tee.NewSimulatedVerifier(dest.PublicKey(), dest.Measurement()))
	require.NoError(t, err)
	require.Equal(t, sample(dest.Measurement()), got)
	require.Equal(t, dest.Measurement(), m)

	// It travels as JSON and verifies on the other side.
	wire, err := json.Marshal(signed)
	require.NoError(t, err)
	var back Signed
	require.NoError(t, json.Unmarshal(wire, &back))
	_, _, err = Verify(back, tee.NewSimulatedVerifier(dest.PublicKey(), dest.Measurement()))
	require.NoError(t, err)
}

// Nothing about a receipt can change after the TEE signed it, and no
// other TEE's signature passes for it.
func TestVerify_RefusesWhatTheDestinationDidNotSign(t *testing.T) {
	dest, other := simulated(t, 1), simulated(t, 2)
	signed, err := Sign(sample(dest.Measurement()), dest)
	require.NoError(t, err)
	verifier := tee.NewSimulatedVerifier(dest.PublicKey(), dest.Measurement())

	edited := signed
	edited.Receipt = bytes.Replace(signed.Receipt, []byte(`"files":3`), []byte(`"files":4`), 1)
	require.NotEqual(t, signed.Receipt, edited.Receipt)
	_, _, err = Verify(edited, verifier)
	require.ErrorContains(t, err, "does not verify")

	forged, err := Sign(sample(dest.Measurement()), other)
	require.NoError(t, err)
	_, _, err = Verify(forged, verifier)
	require.ErrorContains(t, err, "does not verify", "another TEE's evidence")

	// A TEE that signs a receipt naming someone else's measurement.
	lying, err := Sign(sample(dest.Measurement()), other)
	require.NoError(t, err)
	_, _, err = Verify(lying, tee.NewSimulatedVerifier(other.PublicKey(), other.Measurement()))
	require.ErrorContains(t, err, "but its Evidence attests")

	garbage := signed
	garbage.Receipt = []byte(`{"schema":"x"}`)
	garbage.Evidence, err = other.Quote(tee.Nonce(Challenge(garbage.Receipt)))
	require.NoError(t, err)
	_, _, err = Verify(garbage, tee.NewSimulatedVerifier(other.PublicKey(), other.Measurement()))
	require.Error(t, err, "a signed receipt that does not parse")
}

func TestParse_RefusesMalformedReceipts(t *testing.T) {
	m := simulated(t, 1).Measurement()
	good, err := sample(m).Marshal()
	require.NoError(t, err)
	_, err = Parse(good)
	require.NoError(t, err)

	mutate := func(f func(r *Receipt)) []byte {
		r := sample(m)
		f(&r)
		b, err := json.Marshal(r)
		require.NoError(t, err)
		return b
	}
	for name, b := range map[string][]byte{
		"not json":         []byte("{"),
		"unknown field":    bytes.Replace(good, []byte(`{"schema"`), []byte(`{"extra":1,"schema"`), 1),
		"trailing data":    append(append([]byte(nil), good...), []byte(` {}`)...),
		"other schema":     mutate(func(r *Receipt) { r.Schema = "vault-genome/restore-receipt/v0" }),
		"no key id":        mutate(func(r *Receipt) { r.KeyID = "" }),
		"no token":         mutate(func(r *Receipt) { r.TokenID = "" }),
		"short measure":    mutate(func(r *Receipt) { r.DestinationMeasurement = "abcd" }),
		"bundle digest":    mutate(func(r *Receipt) { r.BundleSHA256 = "sha256:" + strings.Repeat("ab", 32) }),
		"payload digest":   mutate(func(r *Receipt) { r.PayloadSHA256 = strings.Repeat("cd", 32) }),
		"tree digest":      mutate(func(r *Receipt) { r.TreeSHA256 = "xyz" }),
		"no files":         mutate(func(r *Receipt) { r.Files = 0 }),
		"negative time":    mutate(func(r *Receipt) { r.RestoreSeconds = -1 }),
		"restored earlier": mutate(func(r *Receipt) { r.RestoredAt = r.KeyReceivedAt.Add(-time.Second) }),
		"no key time":      mutate(func(r *Receipt) { r.KeyReceivedAt = time.Time{} }),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(b)
			require.Error(t, err)
		})
	}

	bad := sample(m)
	bad.Files = 0
	_, err = bad.Marshal()
	require.Error(t, err, "an invalid receipt is never signed")
	_, err = Sign(bad, simulated(t, 1))
	require.Error(t, err)
}

// The challenge binds the exact receipt bytes and nothing else.
func TestChallenge(t *testing.T) {
	a, b := Challenge([]byte("receipt")), Challenge([]byte("receipt "))
	require.Len(t, a, 64)
	require.NotEqual(t, a, b)
	require.Equal(t, a, Challenge([]byte("receipt")))
}

func TestGate(t *testing.T) {
	r := sample(simulated(t, 1).Measurement())
	r.Gate = &Gate{Level: GateEquivalent, Door: "native float", Fixtures: 16, MaxAbsErr: 1.15e-4, MaxRelErr: 1.3e-5, Atol: 1e-2, Rtol: 1e-3, BackendSeconds: 11.2}
	b, err := r.Marshal()
	require.NoError(t, err)
	back, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, r.Gate, back.Gate)

	require.True(t, back.Gate.Meets(GateEquivalent))
	require.False(t, back.Gate.Meets(GateExact))
	require.True(t, (&Gate{Level: GateExact}).Meets(GateExact))
	require.False(t, (&Gate{Level: GateFail}).Meets(GateEquivalent))
	require.False(t, (*Gate)(nil).Meets(GateEquivalent))
	require.False(t, back.Gate.Meets("MAYBE"))

	for name, g := range map[string]Gate{
		"level":    {Level: "PASS", Fixtures: 1},
		"fixtures": {Level: GateExact},
		"negative": {Level: GateExact, Fixtures: 1, MaxAbsErr: -1},
	} {
		t.Run(name, func(t *testing.T) {
			bad := sample(simulated(t, 1).Measurement())
			bad.Gate = &g
			_, err := bad.Marshal()
			require.Error(t, err)
		})
	}
}
