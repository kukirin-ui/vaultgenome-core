// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package trust implements Trust Admission — stage 2 of the nine-stage
// flow: the authority decision that either issues an AttestationResult with
// Outcome=allow, permitting the flow to proceed to session issuance, or
// with deny, blocking it.
//
// # Doctrinal role
//
// Trust is a gate, not a log. It is the enforcement point of the policy
// envelope named by the RecoveryRequest. It consumes the request's policy
// profile and the attested compute peer — the party whose TEE Evidence the
// vault verified on the Return Path handshake and that would receive the
// disclosures — consults the operator's stop list (ADR 0010), and produces
// a signed AttestationResult. The vault daemon records TRUST_EVALUATED for
// every decision before acting on it (ADR 0015).
package trust
