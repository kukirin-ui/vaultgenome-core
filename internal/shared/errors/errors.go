// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors

import (
	stderrors "errors"
	"fmt"
)

// Category names the doctrinal classification of an error. Classification
// drives which AuditEvent kind is emitted and whether Incident Termination
// must run.
type Category uint8

const (
	// CategoryUnknown is reserved for errors that have not yet been
	// classified. Code MUST NOT emit unclassified errors to callers; use
	// As/Is helpers to classify before returning.
	CategoryUnknown Category = 0

	// CategoryStructural — malformed contract, wrong schema version,
	// missing required field. Not a security event.
	CategoryStructural Category = 1

	// CategoryAuthority — authority denied a request. A deny/restrict
	// AttestationResult, a revoked session, a policy miss. Recoverable;
	// caller surfaces to user with the Reason code.
	CategoryAuthority Category = 2

	// CategoryOperational — an operational validation sub-check failed
	// (attestation TTL, manifest integrity, policy alignment, etc.).
	// Triggers OverallVerdict=fail regardless of other dimensions.
	CategoryOperational Category = 3

	// CategoryIntegrity — cryptographic or audit-chain integrity
	// violation. Signature fails, hash mismatch, chain gap detected. This
	// is always a critical signal.
	CategoryIntegrity Category = 4

	// CategoryIncident — tamper or adversarial-condition signal.
	// Triggers Incident Termination in /internal/vault/incident.
	CategoryIncident Category = 5
)

// String returns a stable, lowercase identifier for the category.
func (c Category) String() string {
	switch c {
	case CategoryStructural:
		return "structural"
	case CategoryAuthority:
		return "authority"
	case CategoryOperational:
		return "operational"
	case CategoryIntegrity:
		return "integrity"
	case CategoryIncident:
		return "incident"
	default:
		return "unknown"
	}
}

// Error is the common interface of every classified error in this package.
// It exposes the category and a stable machine-readable code alongside the
// human-readable message.
type Error interface {
	error
	Category() Category
	Code() string
	Unwrap() error
}

// classifiedError is the concrete implementation. It is unexported so all
// construction goes through the category-specific constructors.
type classifiedError struct {
	cat   Category
	code  string
	msg   string
	cause error
}

func (e *classifiedError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s[%s]: %s: %v", e.cat, e.code, e.msg, e.cause)
	}
	return fmt.Sprintf("%s[%s]: %s", e.cat, e.code, e.msg)
}

func (e *classifiedError) Category() Category { return e.cat }
func (e *classifiedError) Code() string       { return e.code }
func (e *classifiedError) Unwrap() error      { return e.cause }

// Structural constructs a structural error.
func Structural(code, msg string, cause error) Error {
	return &classifiedError{cat: CategoryStructural, code: code, msg: msg, cause: cause}
}

// Authority constructs an authority error.
func Authority(code, msg string, cause error) Error {
	return &classifiedError{cat: CategoryAuthority, code: code, msg: msg, cause: cause}
}

// Operational constructs an operational error.
func Operational(code, msg string, cause error) Error {
	return &classifiedError{cat: CategoryOperational, code: code, msg: msg, cause: cause}
}

// Integrity constructs an integrity error. These are always critical.
func Integrity(code, msg string, cause error) Error {
	return &classifiedError{cat: CategoryIntegrity, code: code, msg: msg, cause: cause}
}

// Incident constructs an incident error. Callers that receive an Incident
// error MUST surface it to /internal/vault/incident for termination
// handling.
func Incident(code, msg string, cause error) Error {
	return &classifiedError{cat: CategoryIncident, code: code, msg: msg, cause: cause}
}

// ---- classification helpers -------------------------------------------------

// CategoryOf returns the Category of err if it is a classified Error,
// otherwise CategoryUnknown. The intended use is:
//
//	switch errors.CategoryOf(err) {
//	case errors.CategoryIncident:
//	    // wire to incident.Handle()
//	case errors.CategoryIntegrity:
//	    // emit INCIDENT_DETECTED audit event (yes — integrity is critical)
//	    // ...
//	}
func CategoryOf(err error) Category {
	var e Error
	if stderrors.As(err, &e) {
		return e.Category()
	}
	return CategoryUnknown
}

// Is reports whether err has the given category in its cause chain.
func Is(err error, cat Category) bool {
	var e Error
	if stderrors.As(err, &e) {
		return e.Category() == cat
	}
	return false
}

// CodeOf returns the stable code of err, or the empty string if err is
// not classified.
func CodeOf(err error) string {
	var e Error
	if stderrors.As(err, &e) {
		return e.Code()
	}
	return ""
}

// ---- stable code constants --------------------------------------------------

// Code constants are NOT exhaustive — packages define their own codes in
// their own namespace — but the following are shared across the platform.
const (
	CodeSchemaVersionUnsupported = "schema_version_unsupported"
	CodeRequiredFieldMissing     = "required_field_missing"
	CodeFieldValueInvalid        = "field_value_invalid"
	CodeCrossFieldInconsistent   = "cross_field_inconsistent"

	CodeSessionExpired       = "session_expired"
	CodeSessionInvalidated   = "session_invalidated"
	CodeAttestationExpired   = "attestation_expired"
	CodeAttestationDenied    = "attestation_denied"
	CodePolicyDrifted        = "policy_drifted"
	CodeManifestHashMismatch = "manifest_hash_mismatch"

	CodeSignatureInvalid  = "signature_invalid"
	CodeChainHashMismatch = "chain_hash_mismatch"
	CodeChainGapDetected  = "chain_gap_detected"

	CodeTamperSignal         = "tamper_signal"
	CodeZeroizationTriggered = "zeroization_triggered"

	// CodeIssuerFinalized indicates a release-side issuer
	// (e.g. disclosure.StagedIssuer) refused an operation because
	// Finalize has already been called on it. Operational category.
	CodeIssuerFinalized = "issuer_finalized"

	// CodeResourceExhausted indicates an operation could not proceed
	// because the underlying resource it depended on is no longer
	// available — an audit store closed by Close(), a channel shut
	// down, a file handle returned to the pool. Operational category.
	//
	// Used by /internal/audit/store for Append/Load/Len after Close,
	// and by the compute worker when a cancelled context arrives at
	// the Reconstructor. Callers may distinguish the two cases by
	// inspecting errors.Is for the sentinel the producing package
	// documents (e.g. store.ErrStoreClosed).
	CodeResourceExhausted = "resource_exhausted"
)
