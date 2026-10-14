// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package keys

import (
	"fmt"
	"strings"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Multi-tenant key derivation.
//
// Phase-2 readiness work for the case where a single sagvd instance
// serves more than one customer. Each tenant gets its own logically-
// isolated set of sealing and signing keys, derived from the vault's
// master keys via RFC 5869 HKDF.
//
// Doctrinal properties:
//
//  1. Determinism. The derivation is a pure function of
//     (master kid, master material, tenant id, purpose). Recovery
//     procedures (`acpctl recover`) can recompute the exact key any
//     time without persisted state — the master is enough.
//
//  2. Cryptographic isolation. An attacker who holds tenant A's
//     derived key cannot recover the master nor any other tenant's
//     derived key. This is the standard HKDF-Expand security claim
//     (RFC 5869 §3.3).
//
//  3. Domain separation. The HKDF salt is a fixed bytestring distinct
//     from any other derivation in the codebase, so an attacker who
//     observed both a tenant key and a Return-Path session key can
//     distinguish them but cannot relate them.
//
//  4. Purpose binding. The HKDF info parameter binds the purpose
//     (sealing vs signing-authority vs signing-audit) into the
//     derivation. Cross-purpose key abuse remains impossible even if
//     a derived key leaks.
//
// Out of scope here:
//
//   - Per-tenant rotation policy (operator-side; this package merely
//     provides idempotent derivation given a stable master)
//   - Per-tenant audit-log scoping (handled by the audit_event contract
//     once tenant_id is added there in a follow-up)
//   - Multi-tenant capacity limits (operational concern; the keystore
//     scales linearly with tenant count, ~96 bytes per derived key)

// TenantID is the canonical identifier for a tenant. The byte form
// flows into HKDF info so two tenants whose IDs differ get distinct
// keys regardless of how similar their human-readable names look.
//
// IDs are case-sensitive and must match the regular expression
// /^[A-Za-z0-9_-]{1,64}$/. We deliberately exclude '/' so the
// derived KID layout
// (`<master_kid>/tenant/<tenant_id>/<purpose>`) remains
// unambiguously parseable, and exclude '.' so future hierarchical
// schemes have a free separator.
type TenantID string

// IsValid reports whether t is well-formed per the regex above.
// Empty IDs are NOT valid — callers MUST set a tenant ID explicitly,
// even for single-tenant deployments (use "default" by convention).
func (t TenantID) IsValid() bool {
	if len(t) == 0 || len(t) > 64 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		ok := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// String returns the underlying ID; provided so the type satisfies
// fmt.Stringer for log redaction.
func (t TenantID) String() string { return string(t) }

// tenantDeriveSalt is the HKDF salt used by every tenant derivation
// in this codebase. It is a fixed domain-separation label; rotating
// it would invalidate every tenant's existing key, which is why it
// carries a version suffix — future versions move to v2 only via an
// ADR amendment.
var tenantDeriveSalt = []byte("vault-genome.tenant-derive.v1")

// TenantKeyID returns the canonical KeyID for a tenant-derived key.
// The format is intentionally human-readable so an operator scanning
// audit logs can attribute events to the tenant + purpose without a
// lookup table:
//
//	<master_kid>/tenant/<tenant_id>/<purpose>
//
// e.g.: `session-sealing-2026-q1/tenant/acme-bank/sealing`.
//
// Returns a Structural error for invalid tenant IDs or non-derivable
// purposes (the derivation only supports PurposeSealing,
// PurposeSigningAuthority, PurposeSigningAudit, PurposeSigningWitness;
// PurposeUnknown is rejected).
func TenantKeyID(masterKID ids.KeyID, tenant TenantID, purpose Purpose) (ids.KeyID, error) {
	if masterKID.IsZero() {
		return "", shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"keys: master KeyID required for tenant derivation",
			nil,
		)
	}
	if !tenant.IsValid() {
		return "", shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("keys: tenant ID %q is not well-formed", tenant),
			nil,
		)
	}
	if purpose == PurposeUnknown {
		return "", shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: purpose required for tenant derivation",
			nil,
		)
	}
	return ids.KeyID(fmt.Sprintf("%s/tenant/%s/%s",
		string(masterKID), string(tenant), purpose.String())), nil
}

// ParseTenantKeyID is the inverse of TenantKeyID. It returns the
// (master_kid, tenant, purpose) triple if kid is in tenant-derived
// format, or ok=false otherwise.
func ParseTenantKeyID(kid ids.KeyID) (master ids.KeyID, tenant TenantID, purpose Purpose, ok bool) {
	parts := strings.Split(string(kid), "/")
	if len(parts) != 4 || parts[1] != "tenant" {
		return "", "", PurposeUnknown, false
	}
	master = ids.KeyID(parts[0])
	tenant = TenantID(parts[2])
	purpose = parsePurpose(parts[3])
	if master.IsZero() || !tenant.IsValid() || purpose == PurposeUnknown {
		return "", "", PurposeUnknown, false
	}
	return master, tenant, purpose, true
}

func parsePurpose(s string) Purpose {
	switch s {
	case "signing_authority":
		return PurposeSigningAuthority
	case "signing_audit":
		return PurposeSigningAudit
	case "signing_witness":
		return PurposeSigningWitness
	case "sealing":
		return PurposeSealing
	default:
		return PurposeUnknown
	}
}

// tenantDeriveInfo builds the HKDF info parameter for a tenant
// derivation. The info encodes (tenant, NUL, purpose) with NUL as a
// non-reserved separator that cannot appear in a TenantID per its
// validation regex; this makes the encoding canonical so two
// distinct (tenant, purpose) pairs cannot collide.
func tenantDeriveInfo(tenant TenantID, purpose Purpose) []byte {
	out := make([]byte, 0, len(tenant)+1+len(purpose.String()))
	out = append(out, []byte(tenant)...)
	out = append(out, 0x00)
	out = append(out, []byte(purpose.String())...)
	return out
}

// DeriveTenantSealing derives a per-tenant AES-256 sealing key from
// the master kid's stored material via HKDF, registers it under the
// canonical tenant KID, and returns the new KID.
//
// The master kid MUST already be registered as a sealing key. The
// derivation is idempotent: calling it twice with the same arguments
// is rejected by the underlying RegisterSealing's duplicate-kid
// guard. Callers who need "register if missing" semantics should use
// EnsureTenantSealing.
func (s *InMemoryStore) DeriveTenantSealing(masterKID ids.KeyID, tenant TenantID) (ids.KeyID, error) {
	derivedKID, err := TenantKeyID(masterKID, tenant, PurposeSealing)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	master, ok := s.sealing[masterKID]
	s.mu.RUnlock()
	if !ok {
		return "", shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			fmt.Sprintf("keys: master sealing kid %q not registered", masterKID),
			nil,
		)
	}

	info := tenantDeriveInfo(tenant, PurposeSealing)
	derived, err := crypto.HKDFSHA256(tenantDeriveSalt, master.Material, info, crypto.AES256KeySize)
	if err != nil {
		return "", err
	}
	if err := s.RegisterSealing(derivedKID, derived); err != nil {
		// zeroize the freshly-derived material so it doesn't linger
		// in our defensive copy buffer beyond this scope.
		for i := range derived {
			derived[i] = 0
		}
		return "", err
	}
	for i := range derived {
		derived[i] = 0
	}
	return derivedKID, nil
}

// EnsureTenantSealing is the idempotent variant of
// DeriveTenantSealing: returns the existing tenant KID if already
// registered, derives + registers if not. Useful in HTTP request
// paths where the per-request setup must succeed regardless of prior
// state.
func (s *InMemoryStore) EnsureTenantSealing(masterKID ids.KeyID, tenant TenantID) (ids.KeyID, error) {
	derivedKID, err := TenantKeyID(masterKID, tenant, PurposeSealing)
	if err != nil {
		return "", err
	}
	s.mu.RLock()
	_, exists := s.sealing[derivedKID]
	s.mu.RUnlock()
	if exists {
		return derivedKID, nil
	}
	return s.DeriveTenantSealing(masterKID, tenant)
}

// DeriveTenantSigning derives a per-tenant Ed25519 signing key from
// a master signing key's seed-equivalent (the first 32 bytes of the
// private key, which IS the seed for Ed25519). Registers it under
// the canonical tenant KID and returns the resulting VerifyingKey.
//
// purpose must be one of the signing purposes
// (PurposeSigningAuthority, PurposeSigningAudit, PurposeSigningWitness).
func (s *InMemoryStore) DeriveTenantSigning(masterKID ids.KeyID, tenant TenantID, purpose Purpose) (VerifyingKey, error) {
	if purpose != PurposeSigningAuthority &&
		purpose != PurposeSigningAudit &&
		purpose != PurposeSigningWitness {
		return VerifyingKey{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"keys: tenant signing derivation requires a signing purpose",
			nil,
		)
	}
	derivedKID, err := TenantKeyID(masterKID, tenant, purpose)
	if err != nil {
		return VerifyingKey{}, err
	}

	s.mu.RLock()
	master, ok := s.signing[masterKID]
	s.mu.RUnlock()
	if !ok {
		return VerifyingKey{}, shared_errors.Authority(
			shared_errors.CodeRequiredFieldMissing,
			fmt.Sprintf("keys: master signing kid %q not registered", masterKID),
			nil,
		)
	}
	// Ed25519 private keys are 64 bytes (32-byte seed || 32-byte
	// public). The seed is the IKM for HKDF — using the full private
	// key would needlessly mix the public half into the input, which
	// changes nothing (HMAC's pseudorandomness floor is the same)
	// but obscures the construction.
	masterSeed := master.Priv[:crypto.Ed25519SeedSize]

	info := tenantDeriveInfo(tenant, purpose)
	derivedSeed, err := crypto.HKDFSHA256(tenantDeriveSalt, masterSeed, info, crypto.Ed25519SeedSize)
	if err != nil {
		return VerifyingKey{}, err
	}
	defer func() {
		for i := range derivedSeed {
			derivedSeed[i] = 0
		}
	}()
	return s.RegisterSigningFromSeed(derivedKID, purpose, derivedSeed)
}

// EnsureTenantSigning — idempotent variant of DeriveTenantSigning.
func (s *InMemoryStore) EnsureTenantSigning(masterKID ids.KeyID, tenant TenantID, purpose Purpose) (VerifyingKey, error) {
	derivedKID, err := TenantKeyID(masterKID, tenant, purpose)
	if err != nil {
		return VerifyingKey{}, err
	}
	s.mu.RLock()
	existing, ok := s.signing[derivedKID]
	s.mu.RUnlock()
	if ok {
		return existing.VerifyingKey, nil
	}
	return s.DeriveTenantSigning(masterKID, tenant, purpose)
}
