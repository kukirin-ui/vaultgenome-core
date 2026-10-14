// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package intake is the entry point for RecoveryRequest objects into the
// vault — stage 1 of the nine-stage flow. It performs the first shape and
// identity checks and hands admitted requests to /internal/vault/trust for
// authority evaluation.
//
// # Doctrinal role
//
// Intake is not authority. It decides only whether a request is well-
// formed enough to present to trust. It may reject on structural grounds
// (malformed, duplicate) but never on continuity-policy grounds — that is
// trust's job. The vault daemon records REQUEST_RECEIVED for every request
// intake admits, before the request is queued (ADR 0015).
package intake
