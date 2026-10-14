// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// fakeVTPM stands in for tpm2-tools over a vTPM: a primary key that is
// the same every time, a policy digest that is a function of the boot's
// PCR state and the selection, sealed objects it hands back only under
// that same policy. It also records every call and every argument the
// sealer passes, which is the contract this file pins.
type fakeVTPM struct {
	t       *testing.T
	boot    string // what the PCRs measure this boot
	secrets map[string][]byte
	calls   []string
	args    map[string][]string
	fail    map[string]error
	stdin   map[string][]byte
}

func newFakeVTPM(t *testing.T) *fakeVTPM {
	t.Helper()
	f := &fakeVTPM{t: t, boot: "boot-1", secrets: map[string][]byte{}, args: map[string][]string{}, fail: map[string]error{}, stdin: map[string][]byte{}}
	oldRun, oldIn := runCommand, runCommandInput
	t.Cleanup(func() { runCommand, runCommandInput = oldRun, oldIn })
	runCommand = func(timeout time.Duration, argv ...string) ([]byte, error) { return f.run(timeout, nil, argv...) }
	runCommandInput = f.run
	return f
}

func (f *fakeVTPM) policy(sel string) []byte {
	d := sha256.Sum256([]byte(f.boot + "|" + sel))
	return d[:]
}

func (f *fakeVTPM) run(_ time.Duration, stdin []byte, argv ...string) ([]byte, error) {
	name := filepath.Base(argv[0])
	f.calls = append(f.calls, name)
	f.args[name] = argv[1:]
	if stdin != nil {
		f.stdin[name] = append([]byte(nil), stdin...)
	}
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	arg := func(flag string) string {
		for i := range argv {
			if argv[i] == flag && i+1 < len(argv) {
				return argv[i+1]
			}
		}
		return ""
	}
	has := func(flag string) bool {
		for _, a := range argv {
			if a == flag {
				return true
			}
		}
		return false
	}
	switch name {
	case "tpm2_createprimary":
		return nil, os.WriteFile(arg("-c"), []byte("primary:owner:ecc:sha256"), 0o600)
	case "tpm2_createpolicy":
		if !has("--policy-pcr") {
			return nil, errors.New("not a PCR policy")
		}
		return nil, os.WriteFile(arg("-L"), f.policy(arg("-l")), 0o600)
	case "tpm2_create":
		if p, _ := os.ReadFile(arg("-C")); string(p) != "primary:owner:ecc:sha256" {
			return nil, errors.New("no primary")
		}
		if arg("-i") != "-" {
			return nil, errors.New("the secret must come on stdin")
		}
		policy, err := os.ReadFile(arg("-L"))
		if err != nil {
			return nil, err
		}
		id := sha256.Sum256(append([]byte("priv|"), stdin...))
		f.secrets[hex.EncodeToString(id[:])] = append([]byte(nil), stdin...)
		if err := os.WriteFile(arg("-u"), policy, 0o600); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(arg("-r"), id[:], 0o600)
	case "tpm2_load":
		if p, _ := os.ReadFile(arg("-C")); string(p) != "primary:owner:ecc:sha256" {
			return nil, errors.New("no primary")
		}
		pub, err := os.ReadFile(arg("-u"))
		if err != nil {
			return nil, err
		}
		priv, err := os.ReadFile(arg("-r"))
		if err != nil {
			return nil, err
		}
		if _, ok := f.secrets[hex.EncodeToString(priv)]; !ok {
			return nil, errors.New("integrity check failed: not an object of this TPM")
		}
		return nil, os.WriteFile(arg("-c"), append(append([]byte(nil), pub...), priv...), 0o600)
	case "tpm2_unseal":
		ctx, err := os.ReadFile(arg("-c"))
		if err != nil {
			return nil, err
		}
		pub, priv := ctx[:32], ctx[32:]
		sel := strings.TrimPrefix(arg("-p"), "pcr:")
		if !bytes.Equal(pub, f.policy(sel)) {
			return nil, errors.New("policy check failed (TPM_RC_POLICY_FAIL)")
		}
		return f.secrets[hex.EncodeToString(priv)], nil
	}
	return nil, os.ErrNotExist
}

func TestVTPMSealerRoundTripsAndBindsTheBoot(t *testing.T) {
	f := newFakeVTPM(t)
	s, err := NewVTPMSealer(VTPMSealerConfig{TPM2ToolsDir: "/opt/tpm2"})
	require.NoError(t, err)
	require.Equal(t, DefaultVTPMSealPCRs, s.PCRs())
	pt, aad := []byte("the escrow private key"), []byte("vault-genome sealed-escrow-key v1")

	sealed, err := s.Seal(pt, aad)
	require.NoError(t, err)
	require.Equal(t, []string{"tpm2_createprimary", "tpm2_createpolicy", "tpm2_create"}, f.calls)
	require.Equal(t, "/opt/tpm2/tpm2_createprimary", "/opt/tpm2/"+f.calls[0], "the tools come from the configured directory")
	var blob vtpmSealedBlob
	require.NoError(t, json.Unmarshal(sealed, &blob))
	require.Equal(t, VTPMSealedSchema, blob.Schema)
	require.Equal(t, DefaultVTPMSealPCRs, blob.PCRs)
	require.NotEmpty(t, blob.Public)
	require.NotEmpty(t, blob.Private)
	require.NotContains(t, string(sealed), string(pt))
	require.Len(t, f.stdin["tpm2_create"], 32, "the AES key went to tpm2_create on stdin")
	require.NotContains(t, string(sealed), hex.EncodeToString(f.stdin["tpm2_create"]), "the key is not in the blob")
	// The exact tool contract.
	require.Equal(t, []string{"-C", "o", "-g", "sha256", "-G", "ecc"}, f.args["tpm2_createprimary"][:6], "the owner hierarchy's primary, ECC, sha256")
	require.Equal(t, []string{"--policy-pcr", "-l", DefaultVTPMSealPCRs}, f.args["tpm2_createpolicy"][:3])
	create := strings.Join(f.args["tpm2_create"], " ")
	require.Contains(t, create, "-a "+vtpmSealedObjectAttributes, "policy-only: no userwithauth")
	require.Contains(t, create, "-i -", "the secret on stdin, never a file")

	f.calls = nil
	got, err := s.Unseal(sealed, aad)
	require.NoError(t, err)
	require.Equal(t, pt, got)
	require.Equal(t, []string{"tpm2_createprimary", "tpm2_load", "tpm2_unseal"}, f.calls)
	require.Equal(t, "pcr:"+DefaultVTPMSealPCRs, f.args["tpm2_unseal"][3], "unsealed under a PCR policy session for the blob's selection")

	// Another AAD: the AEAD refuses.
	_, err = s.Unseal(sealed, []byte("another key's AAD"))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	// A touched ciphertext: refused.
	blob.Box[len(blob.Box)-1] ^= 0x01
	touched, err := json.Marshal(blob)
	require.NoError(t, err)
	_, err = s.Unseal(touched, aad)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	// Another boot: the vTPM's policy fails and it refuses to unseal.
	f.boot = "boot-2: a new kernel"
	_, err = s.Unseal(sealed, aad)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, "refused to unseal under this boot's PCRs")
	f.boot = "boot-1"

	// A fresh key and object per seal.
	again, err := s.Seal(pt, aad)
	require.NoError(t, err)
	require.False(t, bytes.Equal(sealed, again))
}

func TestVTPMSealerRefusesWhatItCannotOpen(t *testing.T) {
	f := newFakeVTPM(t)
	s, err := NewVTPMSealer(VTPMSealerConfig{PCRs: "sha256:0,1,2,3,4,5,6,7"})
	require.NoError(t, err)
	aad := []byte("aad")
	sealed, err := s.Seal([]byte("secret"), aad)
	require.NoError(t, err)

	for name, blob := range map[string][]byte{
		"not json":       []byte("not a blob"),
		"unknown field":  []byte(`{"schema":"` + VTPMSealedSchema + `","pcrs":"sha256:0,1,2,3,4,5,6,7","public":"AA==","private":"AA==","box":"AA==","extra":1}`),
		"other schema":   []byte(`{"schema":"vault-genome/vtpm-sealed/v0","pcrs":"sha256:0,1,2,3,4,5,6,7","public":"AA==","private":"AA==","box":"AA=="}`),
		"other PCRs":     []byte(`{"schema":"` + VTPMSealedSchema + `","pcrs":"sha256:0","public":"AA==","private":"AA==","box":"AA=="}`),
		"missing object": []byte(`{"schema":"` + VTPMSealedSchema + `","pcrs":"sha256:0,1,2,3,4,5,6,7","public":"","private":"AA==","box":"AA=="}`),
	} {
		t.Run(name, func(t *testing.T) {
			calls := len(f.calls)
			_, err := s.Unseal(blob, aad)
			require.Error(t, err)
			require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err), "%v", err)
			require.Len(t, f.calls, calls, "a malformed blob never reaches the TPM")
		})
	}

	// An object of another TPM does not load.
	var blob vtpmSealedBlob
	require.NoError(t, json.Unmarshal(sealed, &blob))
	blob.Private = bytes.Repeat([]byte{7}, 32)
	foreign, err := json.Marshal(blob)
	require.NoError(t, err)
	_, err = s.Unseal(foreign, aad)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))
	require.ErrorContains(t, err, "did not load")

	// A tool that fails is named, and a short key is refused.
	f.fail["tpm2_createprimary"] = errors.New("tpm2_createprimary: no TPM at /dev/tpmrm0")
	_, err = s.Seal([]byte("x"), aad)
	require.ErrorContains(t, err, "primary key")
	require.ErrorContains(t, err, "tpm2_createprimary")
	delete(f.fail, "tpm2_createprimary")
	f.fail["tpm2_createpolicy"] = errors.New("boom")
	_, err = s.Seal([]byte("x"), aad)
	require.ErrorContains(t, err, "PCR policy")
	delete(f.fail, "tpm2_createpolicy")
	f.fail["tpm2_create"] = errors.New("boom")
	_, err = s.Seal([]byte("x"), aad)
	require.ErrorContains(t, err, "seal the key")
}

func TestNewVTPMSealerValidatesTheSelection(t *testing.T) {
	t.Parallel()
	s, err := NewVTPMSealer(VTPMSealerConfig{})
	require.NoError(t, err)
	require.Equal(t, DefaultVTPMSealPCRs, s.PCRs())
	for _, bad := range []string{"sha1:0,1", "sha256:", "0,1,2", "sha256:0,24", "sha256:0,x", "sha256:0,0", "sha384:0"} {
		_, err := NewVTPMSealer(VTPMSealerConfig{PCRs: bad})
		require.Error(t, err, bad)
		require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	}
	require.NoError(t, ValidatePCRSelection("sha256:0,1,2,3,4,5,6,7"))
	require.NoError(t, ValidatePCRSelection("sha256:7"))
}

// The contract every sealer in this package keeps.
func TestContract_VTPM_Sealer(t *testing.T) {
	newFakeVTPM(t)
	s, err := NewVTPMSealer(VTPMSealerConfig{})
	require.NoError(t, err)
	var _ Sealer = s
	sealed, err := s.Seal([]byte("plaintext"), []byte("aad"))
	require.NoError(t, err)
	got, err := s.Unseal(sealed, []byte("aad"))
	require.NoError(t, err)
	require.Equal(t, []byte("plaintext"), got)
}
