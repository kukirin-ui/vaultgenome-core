// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"fmt"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// Gate narrows a release policy to the policy's standby: a failover
// release goes to the destination the operator named, or nowhere, even
// when the allow-list would admit others. Compose it inside the operator
// stop list (revocation.NewGate(failover.NewGate(allowList, p), stop)), so
// a stop still refuses first and the stop serial stays last in the
// recorded policy version.
type Gate struct {
	inner kms.KeyReleasePolicy
	p     Policy
}

// NewGate wraps inner with the policy's standby.
func NewGate(inner kms.KeyReleasePolicy, p Policy) *Gate { return &Gate{inner: inner, p: p} }

// AuthorizeKeyRelease implements kms.KeyReleasePolicy.
func (g *Gate) AuthorizeKeyRelease(kind tee.Provider, measurement []byte, decision ids.DecisionID, keyIDs []ids.KeyID) (kms.PolicyVerdict, error) {
	if !g.p.Allows(kind, measurement) {
		return kms.PolicyVerdict{Authorized: false, Reason: fmt.Sprintf(
			"failover policy serial %d releases only to its standby (%s, measurement %v); %s %x is not it",
			g.p.Serial, g.p.Standby.Kind, g.p.Standby.Measurements, kind, measurement)}, nil
	}
	return g.inner.AuthorizeKeyRelease(kind, measurement, decision, keyIDs)
}

// PolicyVersion implements kms.KeyReleasePolicy: the inner version and the
// failover policy's serial.
func (g *Gate) PolicyVersion() string {
	return fmt.Sprintf("%s;failover=%d", g.inner.PolicyVersion(), g.p.Serial)
}
