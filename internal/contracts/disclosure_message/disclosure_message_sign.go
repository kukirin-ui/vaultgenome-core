// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this DisclosureMessage under
// d.SigningKeyID, bound to keys.PurposeSigningAuthority. See
// session_object.SignWith for rationale on the skipped Validate().
func (d *DisclosureMessage) SignWith(signer keys.Signer) error {
	if d == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure_message: nil receiver",
			nil,
		)
	}
	if d.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure_message: signing_key_id required before sign",
			nil,
		)
	}
	cp := *d
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"disclosure_message: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(d.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	d.Signature = sig
	return nil
}

// VerifySignature resolves d.SigningKeyID under
// keys.PurposeSigningAuthority and checks the stored signature.
func (d *DisclosureMessage) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure_message: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := d.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(d.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, d.Signature)
}
