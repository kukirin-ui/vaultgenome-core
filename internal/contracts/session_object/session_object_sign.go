// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_object

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith computes the canonical cover-bytes of this SessionObject (with
// Signature zeroed) and asks signer to produce an Ed25519 signature under
// the key identified by s.SigningKeyID and bound to
// keys.PurposeSigningAuthority. On success the resulting signature is
// assigned to s.Signature.
//
// SignWith intentionally does NOT call the full Validate(): Signature is
// what the method is about to produce, so requiring it present up front
// would be a chicken-and-egg. All non-signature fields are the caller's
// responsibility — a subsequent Validate() after SignWith is the standard
// sanity-check pattern.
func (s *SessionObject) SignWith(signer keys.Signer) error {
	if s == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"session_object: nil receiver",
			nil,
		)
	}
	if s.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"session_object: signing_key_id required before sign",
			nil,
		)
	}
	cp := *s
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"session_object: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(s.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	s.Signature = sig
	return nil
}

// VerifySignature resolves s.SigningKeyID under
// keys.PurposeSigningAuthority through the given resolver and checks the
// stored Ed25519 signature against the canonical cover-bytes. A failed
// verification returns an Integrity-classified error; an unknown or
// purpose-mismatched key returns the error classification of the resolver.
func (s *SessionObject) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"session_object: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := s.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(s.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, s.Signature)
}
