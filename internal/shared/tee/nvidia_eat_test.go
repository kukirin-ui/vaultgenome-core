// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeNRAS signs tokens the way NVIDIA's service does: ES384 under a
// P-384 key published in a JWKS.
type fakeNRAS struct {
	key  *ecdsa.PrivateKey
	kid  string
	jwks []byte
}

func newFakeNRAS(t *testing.T, kid string) *fakeNRAS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	point, err := key.PublicKey.Bytes() // 0x04 || x || y, each 48 bytes
	require.NoError(t, err)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kid": kid, "kty": "EC", "crv": "P-384",
		"x": base64.RawURLEncoding.EncodeToString(point[1:49]),
		"y": base64.RawURLEncoding.EncodeToString(point[49:97]),
	}}})
	return &fakeNRAS{key: key, kid: kid, jwks: jwks}
}

func (f *fakeNRAS) sign(t *testing.T, claims map[string]any, alg string) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": alg, "kid": f.kid, "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	digest := sha512.Sum384([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, digest[:])
	require.NoError(t, err)
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func gpuClaims(nonceHex string, now time.Time) map[string]any {
	return map[string]any{
		"iss": "NRAS", "eat_nonce": nonceHex, "exp": float64(now.Add(time.Hour).Unix()), "hwmodel": "H100 NVL",
		"ueid": "GPU-UUID", "x-nvidia-gpu-driver-version": "595.10.01", "x-nvidia-gpu-vbios-version": "96.00.AB.00.01",
		"measres": "success", "secboot": true, "dbgstat": "disabled",
		"x-nvidia-gpu-attestation-report-nonce-match": true, "x-nvidia-gpu-attestation-report-signature-verified": true,
		"x-nvidia-gpu-attestation-report-parsed": true, "x-nvidia-gpu-arch-check": true,
		"x-nvidia-gpu-driver-rim-measurements-available": true, "x-nvidia-gpu-vbios-rim-measurements-available": true,
		"x-nvidia-gpu-driver-rim-signature-verified": true, "x-nvidia-gpu-vbios-rim-signature-verified": true,
	}
}

func overallClaims(nonceHex string, now time.Time, ok bool) map[string]any {
	return map[string]any{"iss": "NRAS", "x-nvidia-ver": "2.0", "x-nvidia-overall-att-result": ok, "eat_nonce": nonceHex,
		"exp": float64(now.Add(time.Hour).Unix()), "sub": "NVIDIA-PLATFORM-ATTESTATION"}
}

func (f *fakeNRAS) response(t *testing.T, nonceHex string, now time.Time) []byte {
	t.Helper()
	raw, _ := json.Marshal([]any{[]string{"JWT", f.sign(t, overallClaims(nonceHex, now, true), "ES384")},
		map[string]string{"GPU-0": f.sign(t, gpuClaims(nonceHex, now), "ES384")}})
	return raw
}

func TestNRASTokenVerifiesUnderTheJWKSAndTheClaimsPolicy(t *testing.T) {
	now := time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC)
	f := newFakeNRAS(t, "nv-eat-kid-test-1")
	nonce := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	set, err := parseJWKSet(f.jwks)
	require.NoError(t, err)

	tok, err := parseNRASResponse(f.response(t, nonce, now))
	require.NoError(t, err)
	overall, err := verifyES384JWT(tok.Overall, set, now, time.Minute)
	require.NoError(t, err)
	gpu0, err := verifyES384JWT(tok.Detached["GPU-0"], set, now, time.Minute)
	require.NoError(t, err)
	gpus, err := evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpu0}, nonce, GPUClaimsPolicy{})
	require.NoError(t, err)
	require.Len(t, gpus, 1)
	require.Equal(t, "H100 NVL", gpus[0].HWModel)
	require.Equal(t, "595.10.01", gpus[0].DriverVersion)

	// Pins.
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpu0}, nonce, GPUClaimsPolicy{AcceptableHWModels: []string{"H100 NVL"}, AcceptableDriverVersions: []string{"595.10.01"}})
	require.NoError(t, err)
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpu0}, nonce, GPUClaimsPolicy{AcceptableDriverVersions: []string{"550.90.07"}})
	require.ErrorContains(t, err, "driver")

	// Refusals: expiry, another key, a tampered claim, another alg, an unknown kid.
	_, err = verifyES384JWT(tok.Overall, set, now.Add(2*time.Hour), time.Minute)
	require.ErrorContains(t, err, "expired")
	other := newFakeNRAS(t, "nv-eat-kid-test-1")
	_, err = verifyES384JWT(other.sign(t, overallClaims(nonce, now, true), "ES384"), set, now, time.Minute)
	require.ErrorContains(t, err, "does not verify")
	parts := tok.Overall
	edited := parts[:len(parts)-8] + "AAAAAAAA"
	_, err = verifyES384JWT(edited, set, now, time.Minute)
	require.Error(t, err)
	_, err = verifyES384JWT(f.sign(t, overallClaims(nonce, now, true), "ES256"), set, now, time.Minute)
	require.ErrorContains(t, err, "ES384")
	unknown := newFakeNRAS(t, "nv-eat-kid-rotated")
	_, err = verifyES384JWT(unknown.sign(t, overallClaims(nonce, now, true), "ES384"), set, now, time.Minute)
	var unk *errUnknownKID
	require.ErrorAs(t, err, &unk)

	// Claims that do not pass the policy.
	bad := gpuClaims(nonce, now)
	bad["measres"] = "fail"
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": bad}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "measurements did not match")
	bad = gpuClaims(nonce, now)
	bad["dbgstat"] = "enabled"
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": bad}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "debug")
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": bad}, nonce, GPUClaimsPolicy{AllowDebug: true})
	require.NoError(t, err, "an operator may allow a debug GPU knowingly")
	bad = gpuClaims(nonce, now)
	bad["x-nvidia-gpu-attestation-report-nonce-match"] = false
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": bad}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "nonce-match")
	_, err = evaluateGPUClaims(overallClaims(nonce, now, false), map[string]map[string]any{"GPU-0": gpu0}, nonce, GPUClaimsPolicy{})
	require.ErrorContains(t, err, "overall attestation result")
	_, err = evaluateGPUClaims(overall, map[string]map[string]any{"GPU-0": gpu0}, "ffff"+nonce[4:], GPUClaimsPolicy{})
	require.ErrorContains(t, err, "replay")
}

func TestNRASJWKSIsCachedAndRefreshedOnceForAnUnknownKey(t *testing.T) {
	now := time.Date(2026, 9, 16, 14, 0, 0, 0, time.UTC)
	old := newFakeNRAS(t, "kid-old")
	rotated := newFakeNRAS(t, "kid-new")
	fetches := 0
	served := old.jwks
	j := &nrasJWKS{url: "https://nras.example/jwks", dir: t.TempDir(), get: func(string) ([]byte, error) { fetches++; return served, nil }}
	nonce := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

	_, err := j.verify(old.sign(t, overallClaims(nonce, now, true), "ES384"), now, time.Minute)
	require.NoError(t, err)
	require.Equal(t, 1, fetches)
	_, err = j.verify(old.sign(t, overallClaims(nonce, now, true), "ES384"), now, time.Minute)
	require.NoError(t, err)
	require.Equal(t, 1, fetches, "the cached key set serves the second token")

	served = rotated.jwks
	_, err = j.verify(rotated.sign(t, overallClaims(nonce, now, true), "ES384"), now, time.Minute)
	require.NoError(t, err)
	require.Equal(t, 2, fetches, "an unknown kid refreshes the key set once")

	offline := &nrasJWKS{url: "https://nras.example/jwks", dir: t.TempDir(), get: nil}
	_, err = offline.verify(old.sign(t, overallClaims(nonce, now, true), "ES384"), now, time.Minute)
	require.ErrorContains(t, err, "no JWKS cached and no network")

	_, err = parseNRASResponse([]byte(`{"not":"an array"}`))
	require.Error(t, err)
	_, err = parseNRASResponse([]byte(`[["CBOR","x"],{"GPU-0":"y"}]`))
	require.ErrorContains(t, err, "want JWT")
}
