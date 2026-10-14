// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package genome_descriptor

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith computes the canonical cover-bytes of this GenomeDescriptor
// (with Signature zeroed, GenomeID retained) and asks signer to produce
// an Ed25519 signature under the key identified by g.SigningKeyID and
// bound to keys.PurposeSigningAuthority. On success the resulting
// signature is assigned to g.Signature.
//
// Expected sequence for a producer:
//
//  1. populate every field except GenomeID and Signature,
//  2. g.GenomeID, _ = g.DeriveID(),           // content-address
//  3. g.SignWith(signer),                     // sign
//  4. g.Validate(),                           // self-consistency check
//
// SignWith intentionally does NOT call Validate() up front: the Signature
// field is what the method is about to produce, and Validate requires it
// non-empty. Callers MUST Validate() afterward — the post-sign Validate
// is what verifies the content-addressing invariant (R-14).
func (g *GenomeDescriptor) SignWith(signer keys.Signer) error {
	if g == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: nil receiver",
			nil,
		)
	}
	if g.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: signing_key_id required before sign",
			nil,
		)
	}
	if g.GenomeID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: genome_id must be derived before sign",
			nil,
		)
	}
	cp := *g
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"genome_descriptor: canonical encode failed",
			err,
		)
	}
	sig, err := signer.Sign(g.SigningKeyID, keys.PurposeSigningAuthority, cb)
	if err != nil {
		return err
	}
	g.Signature = sig
	return nil
}

// VerifySignature performs the full integrity sequence:
//
//  1. Validate (which includes the R-14 content-addressing check),
//  2. resolve g.SigningKeyID under keys.PurposeSigningAuthority,
//  3. crypto.Verify the Ed25519 signature over CanonicalBytes().
//
// A failed verification returns an Integrity-classified error. An unknown
// or purpose-mismatched key returns the error classification of the
// resolver (Authority on unknown, Integrity on cross-purpose lookup).
func (g *GenomeDescriptor) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"genome_descriptor: key resolver required to verify the signature",
			nil,
		)
	}
	if err := g.Validate(); err != nil {
		return err
	}
	cb, err := g.CanonicalBytes()
	if err != nil {
		return err
	}
	vk, err := resolver.Resolve(g.SigningKeyID, keys.PurposeSigningAuthority)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, cb, g.Signature)
}
