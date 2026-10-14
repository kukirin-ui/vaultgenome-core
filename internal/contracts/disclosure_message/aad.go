// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_message

import (
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// RecipientAAD is the associated-data struct bound into every
// DisclosureMessage's AES-256-GCM seal. Its canonical-JSON bytes are the
// AAD argument to Seal on the release side and to Open on the receive
// side.
//
// Why it lives in the contract package, not in /vault/disclosure/
//
// Doctrine invariant #1 ("Vault is authority") forbids non-vault
// packages from importing release-side authority code. The receive-side
// reassembler must, however, be able to reconstruct the exact bytes
// that were fed to the sealer — so either the receiver has to reach
// into /vault/disclosure/ (forbidden), or the AAD shape must live
// somewhere both sides can import.
//
// The DisclosureMessage envelope is already the cross-boundary
// contract. Extracting the AAD struct into the same package expresses
// the doctrinal truth: the AAD shape is a wire-protocol fact, not a
// release-authority decision.
//
// # Wire stability
//
// The field set and JSON names are FIXED. Any change is a breaking
// doctrinal bump — every sealed DisclosureMessage ever issued would
// fail Open otherwise. This struct does NOT carry a SchemaVersion
// because every byte of the envelope that feeds it also cross-binds
// via the authority signature; a sealer-only adversary cannot break
// this without also breaking Ed25519.
type RecipientAAD struct {
	SessionID      ids.SessionID     `json:"session_id"`
	ComponentID    ids.ComponentID   `json:"component_id"`
	SequenceIndex  uint32            `json:"sequence_index"`
	PolicyVersion  ids.PolicyVersion `json:"policy_version"`
	RecipientKeyID ids.KeyID         `json:"recipient_key_id"`
}

// BuildRecipientAAD returns the canonical-JSON bytes of a RecipientAAD
// populated from the five AAD-bound envelope fields. The result is
// passed as the AAD argument to keys.Sealer.Seal on the release side
// and to keys.Sealer.Open on the receive side.
//
// The release side (/vault/disclosure/) and the receive side
// (/reassembly/) MUST produce byte-identical outputs for the same
// inputs. That invariant is the entire point of sharing this helper —
// if the two sides drift, every Open call returns "decryption failed"
// with no diagnostic hint as to why.
func BuildRecipientAAD(
	session ids.SessionID,
	component ids.ComponentID,
	seqIndex uint32,
	policy ids.PolicyVersion,
	recipient ids.KeyID,
) ([]byte, error) {
	aad := RecipientAAD{
		SessionID:      session,
		ComponentID:    component,
		SequenceIndex:  seqIndex,
		PolicyVersion:  policy,
		RecipientKeyID: recipient,
	}
	out, err := crypto.CanonicalJSON(&aad)
	if err != nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"disclosure_message: AAD encode failed",
			err,
		)
	}
	return out, nil
}

// BuildRecipientAADForMessage is the receive-side convenience form:
// given a DisclosureMessage, it reconstructs the AAD bytes used to
// seal the envelope's payload. This is the form callers in
// /internal/reassembly/ will use.
//
// The caller is responsible for having verified the envelope's
// authority signature before invoking Open; a forged envelope that
// happens to produce a well-formed AAD would still fail GCM
// integrity, but relying on that alone conflates two layers of
// defence.
func BuildRecipientAADForMessage(d *DisclosureMessage) ([]byte, error) {
	if d == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"disclosure_message: nil receiver for AAD reconstruction",
			nil,
		)
	}
	return BuildRecipientAAD(
		d.SessionID,
		d.ComponentID,
		d.SequenceIndex,
		d.PolicyVersion,
		d.RecipientKeyID,
	)
}
