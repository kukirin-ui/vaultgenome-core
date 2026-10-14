// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package key_release_token

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this token under
// t.SigningKeyID, bound to keys.PurposeSigningAuthority.
func (t *KeyReleaseToken) SignWith(signer keys.Signer) error {
	if t == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: nil receiver",
			nil,
		)
	}
	if t.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: signing_key_id required before sign",
			nil,
		)
	}
	cp := *t
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"key_release_token: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(t.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	t.Signature = sig
	return nil
}

// VerifySignature resolves t.SigningKeyID under
// keys.PurposeSigningAuthority and checks the stored signature.
func (t *KeyReleaseToken) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"key_release_token: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := t.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(t.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, t.Signature)
}
