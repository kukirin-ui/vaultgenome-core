// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"fmt"
	"sort"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// Registry holds Verifiers for multiple TEE Provider families
// simultaneously. It is the entry point used by cross-cloud authorities
// (release-side KMS Coordinator, destination CrossCloudReceiver) that
// must verify Evidence produced by multiple source TEE vendors during
// the same handshake — for example, a release authority running on
// GCP SEV-SNP that must accept and verify Evidence from AWS Nitro,
// Azure SGX, and Intel SGX DCAP destinations.
//
// # Doctrinal role
//
// The frozen R-10 surface (Producer, Verifier, Sealer in tee.go and the
// per-provider BuildVerifier dispatch in factory.go) is unmodified. The
// Registry is a thin orchestration layer that holds *several* Verifier
// instances and dispatches resolutions by Provider. Each Verifier is
// constructed via the existing factory.go BuildVerifier function, so
// new providers added to the factory automatically become available
// here once the operator includes them in the RegistrySpec list.
//
// # Concurrency
//
// Registry is read-only after construction (NewRegistry returns a
// fully-populated *Registry). All Resolve / Providers calls are lock-
// free and safe for concurrent use. Callers who need to add or remove
// entries at runtime must replace the entire registry pointer
// atomically — the registry itself does not support mutation.
//
// # Failure semantics
//
// NewRegistry returns Structural errors when:
//   - The same Provider is registered more than once (operator config bug).
//   - Any provided VerifierSpec fails to construct via BuildVerifier
//     (e.g., missing AttestorPubKey, hardware-backed verifier on a host
//     without the necessary library).
//
// Resolve returns a Structural error if the Provider is not registered.
// The diagnostic includes the set of registered Providers for
// operator clarity.
//
// See ADR 0006 §"Verifier Registry" for the Phase 4 design rationale.
type Registry struct {
	verifiers map[Provider]Verifier
}

// RegistrySpec pairs a Provider with the VerifierSpec needed to
// construct it. A registry-builder iterates over a slice of these to
// populate the Registry at daemon startup.
type RegistrySpec struct {
	Provider Provider
	Spec     VerifierSpec
}

// NewRegistry constructs a Registry from a slice of RegistrySpec
// entries. Each entry is dispatched through the frozen BuildVerifier
// factory (factory.go), so the Registry inherits any future Provider
// additions without modification here.
//
// Duplicate Providers in the input slice are rejected with a
// Structural error — the daemon must not silently shadow one verifier
// with another, since that would mask attestation policy bugs.
//
// Construction is synchronous; if a hardware-backed verifier requires
// driver-level setup, BuildVerifier surfaces that as a Structural
// error here. Callers that want to start with a partial registry
// should filter the spec list before calling NewRegistry.
func NewRegistry(specs []RegistrySpec) (*Registry, error) {
	verifiers := make(map[Provider]Verifier, len(specs))
	for _, rs := range specs {
		if rs.Provider == "" {
			return nil, shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"tee.NewRegistry: RegistrySpec.Provider is empty",
				nil,
			)
		}
		if _, dup := verifiers[rs.Provider]; dup {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("tee.NewRegistry: duplicate provider %q in registry spec", rs.Provider),
				nil,
			)
		}
		// The Spec.Provider field must agree with the outer rs.Provider —
		// otherwise the registry indexes one Provider but the verifier
		// was built for another, which would silently mis-dispatch.
		if rs.Spec.Provider != rs.Provider {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf(
					"tee.NewRegistry: RegistrySpec.Provider %q does not match VerifierSpec.Provider %q",
					rs.Provider, rs.Spec.Provider,
				),
				nil,
			)
		}
		v, err := BuildVerifier(rs.Spec)
		if err != nil {
			return nil, shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("tee.NewRegistry: BuildVerifier failed for provider %q: %s", rs.Provider, err.Error()),
				err,
			)
		}
		verifiers[rs.Provider] = v
	}
	return &Registry{verifiers: verifiers}, nil
}

// NewRegistryOf holds verifiers built elsewhere — instrumented ones, or a
// test's — keyed by the provider each verifies for.
func NewRegistryOf(verifiers map[Provider]Verifier) *Registry {
	m := make(map[Provider]Verifier, len(verifiers))
	for p, v := range verifiers {
		m[p] = v
	}
	return &Registry{verifiers: m}
}

// Resolve returns the Verifier registered for the given Provider, or
// a Structural error if the Provider is unknown. The error diagnostic
// lists the registered Providers so operators can spot configuration
// gaps quickly.
//
// Resolve is the entry point invoked by the KMS Coordinator after a
// CrossCloudHandshakeRequest is sent and the destination's Evidence
// arrives — the Coordinator looks up the verifier for the destination's
// declared TEE kind and validates the Evidence under that.
func (r *Registry) Resolve(p Provider) (Verifier, error) {
	if r == nil || r.verifiers == nil {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"tee.Registry.Resolve: registry is nil",
			nil,
		)
	}
	v, ok := r.verifiers[p]
	if !ok {
		return nil, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("tee.Registry.Resolve: provider %q not registered (available: %v)", p, r.providersUnsorted()),
			nil,
		)
	}
	return v, nil
}

// Providers returns the set of Providers registered, sorted in stable
// alphabetical order. Useful for daemon health checks, CLI listings,
// and audit-event payload construction.
func (r *Registry) Providers() []Provider {
	if r == nil || r.verifiers == nil {
		return nil
	}
	out := r.providersUnsorted()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Has reports whether the given Provider is registered.
func (r *Registry) Has(p Provider) bool {
	if r == nil || r.verifiers == nil {
		return false
	}
	_, ok := r.verifiers[p]
	return ok
}

// Len reports the number of providers registered.
func (r *Registry) Len() int {
	if r == nil || r.verifiers == nil {
		return 0
	}
	return len(r.verifiers)
}

func (r *Registry) providersUnsorted() []Provider {
	out := make([]Provider, 0, len(r.verifiers))
	for p := range r.verifiers {
		out = append(out, p)
	}
	return out
}
