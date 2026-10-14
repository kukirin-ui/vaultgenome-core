// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconstruction_job_manifest

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith signs the canonical cover-bytes of this manifest under
// m.SigningKeyID, bound to keys.PurposeSigningAuthority. The SHA-256 of
// these cover-bytes is what op.manifest_integrity re-verifies on the
// external-compute side.
func (m *ReconstructionJobManifest) SignWith(signer keys.Signer) error {
	if m == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"reconstruction_job_manifest: nil receiver",
			nil,
		)
	}
	if m.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"reconstruction_job_manifest: signing_key_id required before sign",
			nil,
		)
	}
	cp := *m
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"reconstruction_job_manifest: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(m.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	m.Signature = sig
	return nil
}

// VerifySignature resolves m.SigningKeyID under
// keys.PurposeSigningAuthority and checks the stored signature.
func (m *ReconstructionJobManifest) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"reconstruction_job_manifest: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := m.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(m.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, m.Signature)
}
