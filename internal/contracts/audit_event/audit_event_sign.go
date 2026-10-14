// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_event

import (
	"bytes"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// SignWith is the two-stage sealing routine for AuditEvent:
//
//  1. Compute canonical cover-bytes (Hash and Signature zeroed).
//  2. Set e.Hash = SHA-256(cover-bytes).
//  3. Set e.Signature = Sign(e.Hash) under keys.PurposeSigningAudit.
//
// The signature covers Hash — not the whole event. This lets chain
// verifiers re-compute each event's Hash and then do a single Ed25519
// verify per entry, amortizing the cost of auditing long chains.
//
// The audit-signing purpose is deliberately distinct from authority
// signing so that compromising the authority key does not automatically
// forge audit continuity.
func (e *AuditEvent) SignWith(signer keys.Signer) error {
	if e == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"audit_event: nil receiver",
			nil,
		)
	}
	if e.SigningKeyID.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"audit_event: signing_key_id required before sign",
			nil,
		)
	}
	cp := *e
	cp.Hash = nil
	cp.Signature = nil
	cb, err := crypto.CanonicalJSON(&cp)
	if err != nil {
		return shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"audit_event: canonical encode failed",
			err,
		)
	}
	h := crypto.SHA256(cb)
	e.Hash = append([]byte(nil), h[:]...)
	sig, err := signer.Sign(e.SigningKeyID, keys.PurposeSigningAudit, e.Hash)
	if err != nil {
		return err
	}
	e.Signature = sig
	return nil
}

// VerifySignature checks two independent integrity claims on the event:
//
//   - Hash correctly summarizes the canonical bytes of the event
//     (i.e. no field was mutated after Hash was taken).
//   - Signature is a valid Ed25519 signature over Hash under the key
//     identified by SigningKeyID and bound to PurposeSigningAudit.
//
// Either failure is returned as an Integrity-classified error.
func (e *AuditEvent) VerifySignature(resolver keys.Resolver) error {
	if resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"audit_event: key resolver required to verify the signature",
			nil,
		)
	}
	cb, err := e.CanonicalBytes()
	if err != nil {
		return err
	}
	h := crypto.SHA256(cb)
	if !bytes.Equal(h[:], e.Hash) {
		return shared_errors.Integrity(
			shared_errors.CodeSignatureInvalid,
			"audit_event: hash does not match canonical bytes",
			nil,
		)
	}
	vk, err := resolver.Resolve(e.SigningKeyID, keys.PurposeSigningAudit)
	if err != nil {
		return err
	}
	return crypto.Verify(vk.PublicKey, e.Hash, e.Signature)
}
