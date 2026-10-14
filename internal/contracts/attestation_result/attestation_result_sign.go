// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package attestation_result

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this AttestationResult under
// a.SigningKeyID, binding to keys.PurposeSigningAuthority. The produced
// signature is assigned to a.Signature. See session_object.SignWith for
// the rationale on why Validate() is not called here.
func (a *AttestationResult) SignWith(signer keys.Signer) error {
	if a == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"attestation_result: nil receiver",
			nil,
		)
	}
	if a.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"attestation_result: signing_key_id required before sign",
			nil,
		)
	}
	cp := *a
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"attestation_result: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(a.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	a.Signature = sig
	return nil
}

// VerifySignature resolves a.SigningKeyID under
// keys.PurposeSigningAuthority and verifies the stored signature against
// canonical cover-bytes.
func (a *AttestationResult) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"attestation_result: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := a.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(a.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, a.Signature)
}
