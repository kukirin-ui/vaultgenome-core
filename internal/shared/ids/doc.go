// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package ids defines the typed identifier aliases used across the
// canonical contracts. They are string-based typed aliases so the Go type
// system catches wrong-id-in-wrong-slot bugs at compile time. A SessionID
// cannot be assigned to a ManifestID slot by accident.
//
// # Doctrinal role
//
// Every continuity-relevant artifact is correlated by ID. Mixing IDs
// across slots has real consequences: an operational-validation sub-check
// relies on a ManifestID matching the one the session's disclosure record
// names. A typo that silently widens to a plain string would be a
// dangerous defect; typed IDs shift the error from runtime to compile
// time.
//
// All typed IDs in this package share the same underlying representation
// (string) but are NOT mutually assignable. Conversions require explicit
// casts and a rationale comment (see /doc/dependencies for the rule on
// explicit casts).
//
// Format of ID values is NOT constrained here. Contracts may impose
// further format rules (UUIDv7, lowercase hex, etc.) in their Validate()
// methods. The ids package only provides typing.
package ids
