// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// The vTPM sealer. A TDX Trust Domain and an Azure confidential GPU VM
// give the guest no sealing key of their own (SEV-SNP's derived key has no
// counterpart there), but both give it a virtual TPM, and the TPM's
// business is exactly this: to hold a secret that only a machine in a
// known state can have back.
//
// Seal makes a fresh AES-256 key, hands it to the vTPM as a sealed object
// under the owner hierarchy's primary key with a policy that only this
// boot's PCR values satisfy, and encrypts the plaintext under that key
// (AES-256-GCM, with the caller's AAD). The blob carries the sealed
// object's public and private parts, the PCR selection and the
// ciphertext; the AES key is never written to disk (tpm2_create reads it
// from stdin) and is zeroed once used. Unseal loads the object and asks
// the vTPM for the key under a PCR policy session: on another boot — a
// changed kernel or firmware, another machine, a cleared TPM — the policy
// fails and the vTPM refuses, and so does the AEAD if anything else was
// touched.
//
// The tools are tpm2-tools (tpm2_createprimary, tpm2_createpolicy,
// tpm2_create, tpm2_load, tpm2_unseal), run as processes like the
// azure-cgpu producer's quote; no TPM library enters the build. The
// primary key is deterministic for the hierarchy's seed, so the same
// object loads after a reboot as long as the owner hierarchy is not
// cleared. The PCR selection is the operator's: by default the fifteen
// PCRs the azure-cgpu registry pin covers (sha256:0-14), so the escrow key
// opens only on the boot the operator pinned.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// VTPMSealedSchema names the sealed blob's shape.
const VTPMSealedSchema = "vault-genome/vtpm-sealed/v1"

// DefaultVTPMSealPCRs is the PCR selection a sealed key is bound to when
// the operator names none: the same PCRs the azure-cgpu quote covers.
const DefaultVTPMSealPCRs = DefaultTPMQuotePCRs

// vtpmSealedObjectAttributes leaves the sealed object usable under its
// policy only (no userwithauth: a password never opens it), pinned to
// this TPM and parent, and outside the dictionary-attack lockout so a
// failed policy on another boot cannot lock the object.
const vtpmSealedObjectAttributes = "fixedtpm|fixedparent|noda"

// runCommandInput runs a tool with stdin, as runCommand does without.
var runCommandInput = func(timeout time.Duration, stdin []byte, argv ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is the operator's configuration
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(stdin), &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// VTPMSealerConfig configures a VTPMSealer.
type VTPMSealerConfig struct {
	// TPM2ToolsDir is where the tpm2_* tools live; empty means PATH.
	TPM2ToolsDir string
	// PCRs is the selection the sealed key is bound to ("sha256:0,1,...");
	// empty means DefaultVTPMSealPCRs.
	PCRs string
	// Timeout bounds each tool invocation; zero means one minute.
	Timeout time.Duration
}

// VTPMSealer seals to the guest's vTPM. See the file comment.
type VTPMSealer struct {
	cfg VTPMSealerConfig
}

// NewVTPMSealer checks the PCR selection and returns the sealer. Nothing
// is run against the TPM until Seal or Unseal.
func NewVTPMSealer(cfg VTPMSealerConfig) (*VTPMSealer, error) {
	if cfg.PCRs == "" {
		cfg.PCRs = DefaultVTPMSealPCRs
	}
	if err := ValidatePCRSelection(cfg.PCRs); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "vtpm-sealer: "+err.Error(), nil)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = time.Minute
	}
	return &VTPMSealer{cfg: cfg}, nil
}

// ValidatePCRSelection accepts "sha256:<n>[,<n>...]" with every n in
// 0..23, the form tpm2-tools take and the only bank this sealer binds.
func ValidatePCRSelection(sel string) error {
	bank, list, ok := strings.Cut(sel, ":")
	if !ok || bank != "sha256" || list == "" {
		return fmt.Errorf("PCR selection %q: want sha256:<n>[,<n>] with n in 0-23", sel)
	}
	seen := map[int]bool{}
	for _, f := range strings.Split(list, ",") {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || n > 23 {
			return fmt.Errorf("PCR selection %q: %q is not a PCR index (0-23)", sel, f)
		}
		if seen[n] {
			return fmt.Errorf("PCR selection %q: PCR %d listed twice", sel, n)
		}
		seen[n] = true
	}
	return nil
}

// PCRs is the selection this sealer binds to.
func (s *VTPMSealer) PCRs() string { return s.cfg.PCRs }

func (s *VTPMSealer) tool(name string) string {
	if s.cfg.TPM2ToolsDir == "" {
		return name
	}
	return filepath.Join(s.cfg.TPM2ToolsDir, name)
}

// vtpmSealedBlob is the sealed form: what the TPM needs to give the key
// back, and what the key protects.
type vtpmSealedBlob struct {
	Schema  string `json:"schema"`
	PCRs    string `json:"pcrs"`
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	Box     []byte `json:"box"`
}

// primary makes the owner hierarchy's primary key in dir and returns its
// context file. Deterministic for the hierarchy's seed and this template.
func (s *VTPMSealer) primary(dir string) (string, error) {
	ctx := filepath.Join(dir, "primary.ctx")
	if _, err := runCommand(s.cfg.Timeout, s.tool("tpm2_createprimary"), "-C", "o", "-g", "sha256", "-G", "ecc", "-c", ctx, "-Q"); err != nil {
		return "", fmt.Errorf("vtpm-sealer: primary key: %w", err)
	}
	return ctx, nil
}

// Seal implements Sealer.
func (s *VTPMSealer) Seal(plaintext, aad []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "vg-vtpm-seal-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	primary, err := s.primary(dir)
	if err != nil {
		return nil, err
	}
	policy := filepath.Join(dir, "pcr.policy")
	if _, err := runCommand(s.cfg.Timeout, s.tool("tpm2_createpolicy"), "--policy-pcr", "-l", s.cfg.PCRs, "-L", policy, "-Q"); err != nil {
		return nil, fmt.Errorf("vtpm-sealer: PCR policy for %s: %w", s.cfg.PCRs, err)
	}
	key := make([]byte, crypto.AES256KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	defer zeroize(key)
	pub, priv := filepath.Join(dir, "seal.pub"), filepath.Join(dir, "seal.priv")
	if _, err := runCommandInput(s.cfg.Timeout, key, s.tool("tpm2_create"), "-C", primary, "-L", policy, "-a", vtpmSealedObjectAttributes,
		"-i", "-", "-u", pub, "-r", priv, "-Q"); err != nil {
		return nil, fmt.Errorf("vtpm-sealer: seal the key to the vTPM: %w", err)
	}
	pubB, err := os.ReadFile(pub)
	if err != nil {
		return nil, err
	}
	privB, err := os.ReadFile(priv)
	if err != nil {
		return nil, err
	}
	if len(pubB) == 0 || len(privB) == 0 {
		return nil, errors.New("vtpm-sealer: tpm2_create wrote an empty sealed object")
	}
	box, err := sevAEADSeal(key, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("vtpm-sealer: AEAD seal: %w", err)
	}
	return json.Marshal(vtpmSealedBlob{Schema: VTPMSealedSchema, PCRs: s.cfg.PCRs, Public: pubB, Private: privB, Box: box})
}

// Unseal implements Sealer.
func (s *VTPMSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	var b vtpmSealedBlob
	dec := json.NewDecoder(bytes.NewReader(sealed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "vtpm-sealer: not a sealed blob", err)
	}
	switch {
	case b.Schema != VTPMSealedSchema:
		return nil, shared_errors.Structural(shared_errors.CodeSchemaVersionUnsupported, fmt.Sprintf("vtpm-sealer: blob schema %q, want %q", b.Schema, VTPMSealedSchema), nil)
	case b.PCRs != s.cfg.PCRs:
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, fmt.Sprintf("vtpm-sealer: the blob is bound to PCRs %q, this sealer binds %q", b.PCRs, s.cfg.PCRs), nil)
	case len(b.Public) == 0 || len(b.Private) == 0 || len(b.Box) == 0:
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "vtpm-sealer: blob lacks the sealed object or the ciphertext", nil)
	}
	dir, err := os.MkdirTemp("", "vg-vtpm-unseal-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	primary, err := s.primary(dir)
	if err != nil {
		return nil, err
	}
	pub, priv, ctx := filepath.Join(dir, "seal.pub"), filepath.Join(dir, "seal.priv"), filepath.Join(dir, "seal.ctx")
	if err := os.WriteFile(pub, b.Public, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(priv, b.Private, 0o600); err != nil {
		return nil, err
	}
	if _, err := runCommand(s.cfg.Timeout, s.tool("tpm2_load"), "-C", primary, "-u", pub, "-r", priv, "-c", ctx, "-Q"); err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("vtpm-sealer: the vTPM did not load the sealed object: %v (another TPM, or a cleared owner hierarchy?)", err), err)
	}
	key, err := runCommand(s.cfg.Timeout, s.tool("tpm2_unseal"), "-c", ctx, "-p", "pcr:"+b.PCRs)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("vtpm-sealer: the vTPM refused to unseal under this boot's PCRs %s: %v (another boot, another machine?)", b.PCRs, err), err)
	}
	defer zeroize(key)
	if len(key) != crypto.AES256KeySize {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid,
			fmt.Sprintf("vtpm-sealer: the vTPM returned %d bytes, want %d", len(key), crypto.AES256KeySize), nil)
	}
	plaintext, err := sevAEADOpen(key, b.Box, aad)
	if err != nil {
		return nil, shared_errors.Integrity(shared_errors.CodeSignatureInvalid, fmt.Sprintf("vtpm-sealer: AEAD open: %v", err), err)
	}
	return plaintext, nil
}
