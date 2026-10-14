// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package continuity_proof

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this bundle under
// p.SigningKeyID, bound to keys.PurposeSigningAuthority.
//
// Intentionally does NOT call Validate() up front — Signature is the
// field this call is about to produce, and Validate requires it
// non-empty. Callers MUST run Validate (or Verify) afterward to confirm
// the bundle is internally consistent.
//
// The inner AGDs and scorecard and WitnessReceipt MUST already be
// signed before SignWith is called; the outer authority signature
// binds an ASSERTION of internal consistency, not the inner keys
// themselves.
func (p *ContinuityProof) SignWith(signer keys.Signer) error {
	if p == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: nil receiver",
			nil,
		)
	}
	if p.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: signing_key_id required before sign",
			nil,
		)
	}
	cp := *p
	cp.Signature = nil
	cp.AncestorChain = append(cp.AncestorChain[:0:0], p.AncestorChain...)
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"continuity_proof: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(p.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	p.Signature = sig
	return nil
}

// VerifySignature checks ONLY the bundle's own authority signature
// against canonical cover-bytes. For the full end-to-end gate
// (structural + inner AGDs + scorecard + witness receipt + this
// signature), use Verify.
func (p *ContinuityProof) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"continuity_proof: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := p.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(p.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, p.Signature)
}
