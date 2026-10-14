// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package cross_cloud_handshake_request

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this request under
// r.SigningKeyID, bound to keys.PurposeSigningAuthority — the same
// purpose used for ReleaseDecision and other release-side authority
// artifacts. This guarantees that a single compromised signing key
// cannot be re-purposed across signing roles.
func (r *CrossCloudHandshakeRequest) SignWith(signer keys.Signer) error {
	if r == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: nil receiver",
			nil,
		)
	}
	if r.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: signing_key_id required before sign",
			nil,
		)
	}
	cp := *r
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"cross_cloud_handshake_request: canonical encode failed",
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
// keys.PurposeSigningAuthority and checks the stored signature
// against the canonical cover-bytes.
func (r *CrossCloudHandshakeRequest) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"cross_cloud_handshake_request: key resolver required to verify the signature",
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
