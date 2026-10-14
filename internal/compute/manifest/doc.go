// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package manifest parses and validates incoming ReconstructionJobManifest
// objects on the worker side. This is distinct from the vault-side
// issuance path (that lives in /internal/vault/orchestration).
//
// # Doctrinal role
//
// The worker must refuse manifests whose signature does not verify, whose
// deadline has passed, whose DisclosureIDs do not match what was received
// over the wire, or whose SchemaVersion it cannot interpret. A refusal
// is NOT a CandidateOutput; it is an explicit error that the Return Path
// relays back to the vault so the vault can record an operational fault.
//
// Stage B: empty package, doctrinal purpose only.
package manifest
