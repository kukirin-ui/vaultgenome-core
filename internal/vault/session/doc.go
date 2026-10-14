// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package session implements TrustedSession lifecycle management — issuance,
// lookup, renewal (if policy permits), and invalidation.
//
// # Doctrinal role
//
// Sessions are mandatory. No AI Genome component is touched without a
// valid SessionObject. The session is the correlation anchor across
// disclosure, manifest issuance, candidate return, validation, release,
// and audit. Every downstream contract carries the SessionID.
//
// On any IncidentEvent of severity >= warn bound to a session, the
// session is invalidated atomically.
//
// Stage B: empty package, doctrinal purpose only.
package session
