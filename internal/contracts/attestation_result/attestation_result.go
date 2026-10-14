// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package attestation_result defines the AttestationResult canonical
// contract — the outcome of Trust Admission.
//
// # Doctrinal role
//
// Trust is a gate, not a log. An AttestationResult with Outcome != allow
// short-circuits the pipeline. The operational validation sub-check
// op.attestation_valid consumes this object's signature and outcome;
// op.attestation_ttl consumes IssuedAt + TTL.
//
// Canonical term: "Trust Admission outcome" — docs/doctrine/terminology.md §2.
package attestation_result

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1

	// DefaultTTL is the MVP default attestation time-to-live. Policy may
	// narrow this but never widen it beyond the vault's configured ceiling.
	DefaultTTL = 5 * time.Minute
)

// Outcome enumerates the admissible verdicts of Trust Admission.
type Outcome string

const (
	OutcomeAllow    Outcome = "allow"
	OutcomeDeny     Outcome = "deny"
	OutcomeRestrict Outcome = "restrict"
)

// AttestationResult represents the outcome of Trust Admission for one
// RecoveryRequest.
type AttestationResult struct {
	SchemaVersion uint16            `json:"schema_version"`
	AttestationID ids.AttestationID `json:"attestation_id"`
	RequestID     ids.RequestID     `json:"request_id"`

	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason,omitempty"`

	IssuedAt time.Time     `json:"issued_at"`
	TTL      time.Duration `json:"ttl"`

	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}
