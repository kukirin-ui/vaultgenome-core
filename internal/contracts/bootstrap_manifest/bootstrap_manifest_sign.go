// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_manifest

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this BootstrapManifest
// under b.SigningKeyID, bound to keys.PurposeSigningAuthority. The
// receive-side environment runs its own signing-authority key separate
// from the Vault's; the manifest is an assertion by the receiver,
// countersigned-out-of-band against the release-side manifest by the
// orchestrator.
func (b *BootstrapManifest) SignWith(signer keys.Signer) error {
	if b == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap_manifest: nil receiver",
			nil,
		)
	}
	if b.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap_manifest: signing_key_id required before sign",
			nil,
		)
	}
	cp := *b
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"bootstrap_manifest: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(b.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	b.Signature = sig
	return nil
}

// VerifySignature resolves b.SigningKeyID under
// keys.PurposeSigningAuthority and checks the stored signature.
func (b *BootstrapManifest) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"bootstrap_manifest: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := b.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(b.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, b.Signature)
}
