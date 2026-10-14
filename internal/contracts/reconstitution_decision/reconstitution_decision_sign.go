// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstitution_decision

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this ReconstitutionDecision
// under r.SigningKeyID, bound to keys.PurposeSigningAuthority. The key
// is the receive-side signing-authority key; it is operationally
// distinct from the Vault's. Cross-checking the two ledgers is exactly
// the operation that makes the receive-side admission story falsifiable.
func (r *ReconstitutionDecision) SignWith(signer keys.Signer) error {
	if r == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"reconstitution_decision: nil receiver",
			nil,
		)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"reconstitution_decision: signing_key_id required before sign",
			nil,
		)
	}
	cp := *r
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"reconstitution_decision: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(r.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	r.Signature = sig
	return nil
}

// VerifySignature resolves r.SigningKeyID under
// keys.PurposeSigningAuthority and checks the stored signature.
func (r *ReconstitutionDecision) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"reconstitution_decision: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := r.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(r.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, r.Signature)
}
