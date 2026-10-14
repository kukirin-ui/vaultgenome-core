// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// NVIDIA's Remote Attestation Service (NRAS) verifies a GPU's attestation
// report — its SPDM measurements against NVIDIA's reference integrity
// manifests for the driver and the VBIOS, its certificate chain to the
// NVIDIA device root, OCSP — and answers with signed Entity Attestation
// Tokens: one overall token and one detached token per GPU, JWTs signed
// ES384 under keys NVIDIA publishes as a JWKS. This verifier checks those
// signatures under the JWKS (fetched once and kept; refreshed when a token
// names a key it does not hold), the tokens' validity window, that the
// nonce NVIDIA saw is the one this verifier expects, that NVIDIA's overall
// result is success, and the per-GPU claims an operator would insist on:
// the report's nonce matched, measurements matched the reference, secure
// boot on, debug off, the driver and VBIOS manifests signed and present,
// the architecture recognised.
//
// What is trusted here is NVIDIA's signature and NVIDIA's evaluation. The
// GPU's own report is in the evidence beside the token for anyone who
// evaluates it independently; this build does not.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultNRASJWKSURL is where NRAS publishes its signing keys.
const DefaultNRASJWKSURL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"

// nrasToken is NRAS's answer: [["JWT", <overall>], {"GPU-0": <detached>, …}].
type nrasToken struct {
	Overall  string
	Detached map[string]string
}

func parseNRASResponse(raw []byte) (*nrasToken, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) != 2 {
		return nil, errors.New("NRAS response is not a two-element array")
	}
	var head []string
	if err := json.Unmarshal(arr[0], &head); err != nil || len(head) != 2 {
		return nil, errors.New("NRAS response: first element is not [type, token]")
	}
	if head[0] != "JWT" {
		return nil, fmt.Errorf("NRAS response: overall token type %q, want JWT", head[0])
	}
	t := &nrasToken{Overall: head[1]}
	if err := json.Unmarshal(arr[1], &t.Detached); err != nil {
		return nil, errors.New("NRAS response: second element is not a map of detached tokens")
	}
	if t.Overall == "" || len(t.Detached) == 0 {
		return nil, errors.New("NRAS response carries no tokens")
	}
	return t, nil
}

// jwkSet is a JSON Web Key Set as NRAS publishes it (EC P-384 keys).
type jwkSet struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	KID string   `json:"kid"`
	KTY string   `json:"kty"`
	CRV string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5C []string `json:"x5c"`
}

func parseJWKSet(raw []byte) (*jwkSet, error) {
	var s jwkSet
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("JWKS: %w", err)
	}
	if len(s.Keys) == 0 {
		return nil, errors.New("JWKS holds no keys")
	}
	return &s, nil
}

func (s *jwkSet) find(kid string) *jsonWebKey {
	for i := range s.Keys {
		if s.Keys[i].KID == kid {
			return &s.Keys[i]
		}
	}
	return nil
}

// ecdsaKey builds the P-384 public key of a JWK from its coordinates,
// and checks it against the leaf certificate in x5c when one is given.
func (k *jsonWebKey) ecdsaKey() (*ecdsa.PublicKey, error) {
	if k.KTY != "EC" || k.CRV != "P-384" {
		return nil, fmt.Errorf("JWK %q is %s/%s, this verifier reads EC/P-384", k.KID, k.KTY, k.CRV)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("JWK %q x: %w", k.KID, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("JWK %q y: %w", k.KID, err)
	}
	if len(x) != 48 || len(y) != 48 {
		return nil, fmt.Errorf("JWK %q: coordinates of %d and %d bytes", k.KID, len(x), len(y))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("JWK %q is not a point on P-384: %w", k.KID, err)
	}
	if len(k.X5C) > 0 {
		der, err := base64.StdEncoding.DecodeString(k.X5C[0])
		if err != nil {
			return nil, fmt.Errorf("JWK %q x5c: %w", k.KID, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("JWK %q x5c: %w", k.KID, err)
		}
		cp, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !cp.Equal(pub) {
			return nil, fmt.Errorf("JWK %q: x5c certificate does not carry the JWK's key", k.KID)
		}
	}
	return pub, nil
}

// jwtParts is a compact JWS split and decoded.
type jwtParts struct {
	Header       map[string]any
	Claims       map[string]any
	SigningInput string
	Signature    []byte
}

func splitJWT(token string) (*jwtParts, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a compact JWS (three parts)")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("token signature: %w", err)
	}
	p := &jwtParts{SigningInput: parts[0] + "." + parts[1], Signature: sig}
	if err := json.Unmarshal(hb, &p.Header); err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	if err := json.Unmarshal(cb, &p.Claims); err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	return p, nil
}

// verifyES384JWT checks a token's signature under the JWKS key its
// header names and its validity window at now; the claims are returned
// only after the signature verified.
func verifyES384JWT(token string, keys *jwkSet, now time.Time, skew time.Duration) (map[string]any, error) {
	p, err := splitJWT(token)
	if err != nil {
		return nil, err
	}
	if alg, _ := p.Header["alg"].(string); alg != "ES384" {
		return nil, fmt.Errorf("token alg %q, this verifier accepts ES384", alg)
	}
	kid, _ := p.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("token names no key (kid)")
	}
	k := keys.find(kid)
	if k == nil {
		return nil, &errUnknownKID{kid: kid}
	}
	pub, err := k.ecdsaKey()
	if err != nil {
		return nil, err
	}
	if len(p.Signature) != 96 {
		return nil, fmt.Errorf("ES384 signature is %d bytes, want 96", len(p.Signature))
	}
	digest := sha512.Sum384([]byte(p.SigningInput))
	r := new(big.Int).SetBytes(p.Signature[:48])
	s := new(big.Int).SetBytes(p.Signature[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, fmt.Errorf("token signature does not verify under key %q", kid)
	}
	if exp, ok := claimTime(p.Claims["exp"]); ok && now.After(exp.Add(skew)) {
		return nil, fmt.Errorf("token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok := claimTime(p.Claims["nbf"]); ok && now.Add(skew).Before(nbf) {
		return nil, fmt.Errorf("token not valid before %s", nbf.UTC().Format(time.RFC3339))
	}
	return p.Claims, nil
}

// errUnknownKID says the JWKS should be refreshed once before giving up.
type errUnknownKID struct{ kid string }

func (e *errUnknownKID) Error() string {
	return fmt.Sprintf("token signed by key %q, not in the JWKS", e.kid)
}

func claimTime(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// nrasJWKS keeps NVIDIA's key set: a file in the cache directory, fetched
// when absent or when a token names a key the file does not hold.
type nrasJWKS struct {
	url string
	dir string
	get func(url string) ([]byte, error)
}

func (j *nrasJWKS) file() string {
	if j.dir == "" {
		return ""
	}
	return filepath.Join(j.dir, "nras-jwks.json")
}

func (j *nrasJWKS) load(refresh bool) (*jwkSet, error) {
	if !refresh {
		if f := j.file(); f != "" {
			if raw, err := os.ReadFile(f); err == nil {
				if set, err := parseJWKSet(raw); err == nil {
					return set, nil
				}
			}
		}
	}
	if j.get == nil {
		return nil, errors.New("no JWKS cached and no network")
	}
	raw, err := j.get(j.url)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	set, err := parseJWKSet(raw)
	if err != nil {
		return nil, err
	}
	if f := j.file(); f != "" {
		_ = writeFileAtomic(f, raw)
	}
	return set, nil
}

// verify checks a token, refreshing the key set once if the token names
// a key the cached set does not hold.
func (j *nrasJWKS) verify(token string, now time.Time, skew time.Duration) (map[string]any, error) {
	set, err := j.load(false)
	if err != nil {
		return nil, err
	}
	claims, err := verifyES384JWT(token, set, now, skew)
	var unknown *errUnknownKID
	if errors.As(err, &unknown) {
		set, err = j.load(true)
		if err != nil {
			return nil, err
		}
		claims, err = verifyES384JWT(token, set, now, skew)
	}
	return claims, err
}

// GPUClaimsPolicy is what an operator insists on in NVIDIA's per-GPU
// claims. The zero value is the strict default.
type GPUClaimsPolicy struct {
	// AllowSecureBootOff, AllowDebug and AllowUnsignedRIM relax the
	// defaults, which require secure boot on, debug off and both the
	// driver and VBIOS reference manifests signed and present.
	AllowSecureBootOff bool
	AllowDebug         bool
	AllowUnsignedRIM   bool
	// AcceptableHWModels, AcceptableDriverVersions and
	// AcceptableVBIOSVersions, when set, pin what the GPU must be.
	AcceptableHWModels       []string
	AcceptableDriverVersions []string
	AcceptableVBIOSVersions  []string
}

// GPUVerdict is what NVIDIA said about one GPU, after this verifier
// checked the token that said it.
type GPUVerdict struct {
	Key           string `json:"key"` // NRAS's key for the device, e.g. GPU-0
	HWModel       string `json:"hw_model,omitempty"`
	DriverVersion string `json:"driver_version,omitempty"`
	VBIOSVersion  string `json:"vbios_version,omitempty"`
	UEID          string `json:"ueid,omitempty"`
	Issuer        string `json:"issuer,omitempty"` // who vouched: NVIDIA's token or "own evaluation"
}

func claimBool(c map[string]any, name string) (bool, bool) {
	v, ok := c[name].(bool)
	return v, ok
}

func claimString(c map[string]any, name string) string {
	s, _ := c[name].(string)
	return s
}

// evaluateGPUClaims applies the policy to verified claims: the overall
// token's result and nonce, then every detached token.
func evaluateGPUClaims(overall map[string]any, detached map[string]map[string]any, expectedNonceHex string, pol GPUClaimsPolicy) ([]GPUVerdict, error) {
	if ok, present := claimBool(overall, "x-nvidia-overall-att-result"); !present || !ok {
		return nil, errors.New("NVIDIA's overall attestation result is not success")
	}
	if got := claimString(overall, "eat_nonce"); !strings.EqualFold(got, expectedNonceHex) {
		return nil, fmt.Errorf("NRAS token nonce %q is not the challenge %q (replay?)", got, expectedNonceHex)
	}
	if len(detached) == 0 {
		return nil, errors.New("NRAS token names no GPU")
	}
	var out []GPUVerdict
	for key, c := range detached {
		must := func(name string) error {
			if v, present := claimBool(c, name); !present || !v {
				return fmt.Errorf("%s: %s is not true", key, name)
			}
			return nil
		}
		for _, name := range []string{
			"x-nvidia-gpu-attestation-report-nonce-match",
			"x-nvidia-gpu-attestation-report-signature-verified",
			"x-nvidia-gpu-attestation-report-parsed",
			"x-nvidia-gpu-arch-check",
			"x-nvidia-gpu-driver-rim-measurements-available",
			"x-nvidia-gpu-vbios-rim-measurements-available",
		} {
			if err := must(name); err != nil {
				return nil, err
			}
		}
		if !pol.AllowUnsignedRIM {
			for _, name := range []string{"x-nvidia-gpu-driver-rim-signature-verified", "x-nvidia-gpu-vbios-rim-signature-verified"} {
				if err := must(name); err != nil {
					return nil, err
				}
			}
		}
		if got := claimString(c, "eat_nonce"); !strings.EqualFold(got, expectedNonceHex) {
			return nil, fmt.Errorf("%s: token nonce %q is not the challenge", key, got)
		}
		if m := claimString(c, "measres"); m != "success" {
			return nil, fmt.Errorf("%s: measurements did not match NVIDIA's reference (measres %q)", key, m)
		}
		if !pol.AllowSecureBootOff {
			if err := must("secboot"); err != nil {
				return nil, fmt.Errorf("%s: secure boot is not on", key)
			}
		}
		if !pol.AllowDebug {
			if d := claimString(c, "dbgstat"); d != "disabled" {
				return nil, fmt.Errorf("%s: GPU debug is %q, not disabled", key, d)
			}
		}
		v := GPUVerdict{Key: key, HWModel: claimString(c, "hwmodel"), DriverVersion: claimString(c, "x-nvidia-gpu-driver-version"),
			VBIOSVersion: claimString(c, "x-nvidia-gpu-vbios-version"), UEID: claimString(c, "ueid"), Issuer: claimString(c, "iss")}
		if len(pol.AcceptableHWModels) > 0 && !containsFold(pol.AcceptableHWModels, v.HWModel) {
			return nil, fmt.Errorf("%s: hardware model %q not in the acceptable set", key, v.HWModel)
		}
		if len(pol.AcceptableDriverVersions) > 0 && !containsFold(pol.AcceptableDriverVersions, v.DriverVersion) {
			return nil, fmt.Errorf("%s: driver %q not in the acceptable set", key, v.DriverVersion)
		}
		if len(pol.AcceptableVBIOSVersions) > 0 && !containsFold(pol.AcceptableVBIOSVersions, v.VBIOSVersion) {
			return nil, fmt.Errorf("%s: VBIOS %q not in the acceptable set", key, v.VBIOSVersion)
		}
		out = append(out, v)
	}
	return out, nil
}

func containsFold(set []string, s string) bool {
	for _, x := range set {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// holdsPins holds a GPU verdict to the policy's model and version pins
// (the claims a report carries; secure boot and debug are NVIDIA-token
// claims and are not asserted by an evaluation of the report alone).
func (pol GPUClaimsPolicy) holdsPins(v GPUVerdict) error {
	if len(pol.AcceptableHWModels) > 0 && !containsFold(pol.AcceptableHWModels, v.HWModel) {
		return fmt.Errorf("hw model %q is not one the policy accepts %v", v.HWModel, pol.AcceptableHWModels)
	}
	if len(pol.AcceptableDriverVersions) > 0 && !containsFold(pol.AcceptableDriverVersions, v.DriverVersion) {
		return fmt.Errorf("driver %q is not one the policy accepts %v", v.DriverVersion, pol.AcceptableDriverVersions)
	}
	if len(pol.AcceptableVBIOSVersions) > 0 && !containsFold(pol.AcceptableVBIOSVersions, v.VBIOSVersion) {
		return fmt.Errorf("VBIOS %q is not one the policy accepts %v", v.VBIOSVersion, pol.AcceptableVBIOSVersions)
	}
	return nil
}
