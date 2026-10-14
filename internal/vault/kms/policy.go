// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"bytes"
	"fmt"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// PolicyVerdict is the result of consulting a KeyReleasePolicy. The
// Coordinator emits the embedded Reason verbatim into the audit
// payload so auditors can replay policy decisions years later.
type PolicyVerdict struct {
	Authorized bool
	Reason     string
}

// KeyReleasePolicy is the gate function that decides whether wrapped
// DEKs may be dispatched to a verified destination measurement.
//
// The Coordinator calls AuthorizeKeyRelease AFTER the destination's
// attestation has been cryptographically verified — i.e., the
// measurement passed in is ground truth, not a claim. The policy's
// job is purely to compare that measurement against operator-supplied
// rules: allow-list, vendor-specific, attribute-based, etc.
//
// The policy MUST be deterministic given the same inputs and
// operator-loaded ruleset. Non-determinism would break audit
// reproducibility (auditors replaying past decisions would get
// different outcomes).
type KeyReleasePolicy interface {
	// AuthorizeKeyRelease evaluates the policy for a given
	// destination measurement, source decision, and key set.
	AuthorizeKeyRelease(
		destinationKind tee.Provider,
		destinationMeasurement []byte,
		decisionID ids.DecisionID,
		keyIDs []ids.KeyID,
	) (PolicyVerdict, error)

	// PolicyVersion returns a stable identifier for the policy
	// state at evaluation time. Operators bump this when ruleset
	// changes ship; auditors use it to correlate audit records to
	// historical policy snapshots.
	PolicyVersion() string
}

// AllowListPolicy is the MVP KeyReleasePolicy implementation: a
// simple (Provider, Measurement) allow-list loaded from operator
// configuration. Authorisation is granted iff the destination
// measurement appears in the allow-list under its declared TEE kind.
//
// Production deployments will replace this with attribute-based
// policy (e.g., "any AWS Nitro measurement signed by a customer's
// Vault Genome operator key after 2026-06-01"), but Phase 4 ships
// with allow-list semantics because they are the simplest
// auditable policy.
type AllowListPolicy struct {
	version string
	allowed map[tee.Provider][][]byte // Provider → list of measurements (32, 48 or 64 bytes)
}

// NewAllowListPolicy constructs a policy from a version string and a
// map of Provider → measurement slices. The version string is
// recorded in the audit payload of every KindKeyReleaseAuthorized
// event the Coordinator emits while this policy is active.
//
// Each measurement entry must be a whole measurement — 32, 48 or 64
// bytes, as tee.MeasurementFromBytes accepts (ADR 0007) — so real
// SEV-SNP and Nitro measurements (48 bytes) are pinned in full.
func NewAllowListPolicy(version string, allowed map[tee.Provider][][]byte) (*AllowListPolicy, error) {
	if version == "" {
		return nil, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"kms.NewAllowListPolicy: version required",
			nil,
		)
	}
	out := make(map[tee.Provider][][]byte, len(allowed))
	for kind, list := range allowed {
		if kind == "" {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"kms.NewAllowListPolicy: empty Provider key",
				nil,
			)
		}
		dup := make([][]byte, 0, len(list))
		for i, m := range list {
			cp, err := tee.MeasurementFromBytes(m)
			if err != nil {
				return nil, shared_errors.Structural(
					shared_errors.CodeFieldValueInvalid,
					fmt.Sprintf("kms.NewAllowListPolicy: %s[%d] measurement must be 32, 48 or 64 bytes; got %d", kind, i, len(m)),
					err,
				)
			}
			dup = append(dup, cp)
		}
		out[kind] = dup
	}
	return &AllowListPolicy{version: version, allowed: out}, nil
}

// AuthorizeKeyRelease returns Authorized=true iff the destination's
// measurement appears in the allow-list under its declared TEE kind.
// The decisionID and keyIDs are not consulted by this policy but are
// validated as non-zero (un-attributable releases are rejected on
// principle).
func (p *AllowListPolicy) AuthorizeKeyRelease(
	destinationKind tee.Provider,
	destinationMeasurement []byte,
	decisionID ids.DecisionID,
	keyIDs []ids.KeyID,
) (PolicyVerdict, error) {
	if destinationKind == "" {
		return PolicyVerdict{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"kms.AllowListPolicy: destination_tee_kind required",
			nil,
		)
	}
	if _, err := tee.MeasurementFromBytes(destinationMeasurement); err != nil {
		return PolicyVerdict{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.AllowListPolicy: destination_measurement must be 32, 48 or 64 bytes; got %d", len(destinationMeasurement)),
			err,
		)
	}
	if decisionID.IsZero() {
		return PolicyVerdict{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"kms.AllowListPolicy: decision_id required",
			nil,
		)
	}
	if len(keyIDs) == 0 {
		return PolicyVerdict{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"kms.AllowListPolicy: key_ids must contain at least one key",
			nil,
		)
	}
	list, ok := p.allowed[destinationKind]
	if !ok || len(list) == 0 {
		return PolicyVerdict{
			Authorized: false,
			Reason:     fmt.Sprintf("no allow-list entries for destination kind %q", destinationKind),
		}, nil
	}
	for _, m := range list {
		if bytes.Equal(m, destinationMeasurement) {
			return PolicyVerdict{
				Authorized: true,
				Reason:     fmt.Sprintf("allow-list match for %q", destinationKind),
			}, nil
		}
	}
	return PolicyVerdict{
		Authorized: false,
		Reason:     fmt.Sprintf("destination measurement not in allow-list for %q", destinationKind),
	}, nil
}

// PolicyVersion returns the operator-supplied version string passed
// to NewAllowListPolicy.
func (p *AllowListPolicy) PolicyVersion() string {
	if p == nil {
		return ""
	}
	return p.version
}
