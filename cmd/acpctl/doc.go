// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package main (cmd/acpctl) is the administrative command-line interface for
// operators of the AI Continuity Platform.
//
// # Doctrinal role
//
// acpctl is a client to the sagvd authority, never a replacement for it. It
// issues read-only queries for operational status (session states, audit
// records, incident events) and submits governance requests that the vault
// independently authorizes. acpctl cannot short-circuit any authority path.
//
// # Commands
//
//   - status, audit query|verify, lineage: read an audit log; verify replays
//     every hash and signature from the first event.
//   - genome seal|open|verify|inspect|chain|lineage|gate: seal a model or a
//     directory into a bundle (its key to --key-out, or escrowed with
//     --escrow-to), restore it all or nothing, check it.
//   - stop keygen|issue|verify: the operator's signed stop list (ADR 0010).
//   - escrow keygen|recovery-keygen|recover: the operator's side of escrow
//     custody (ADR 0016) — keygen writes a plaintext escrow key, for the
//     simulated TEE only; a hardware release host makes its own sealed key
//     with `sagvd escrow-provision`, wrapped to the recovery key
//     recovery-keygen makes, and recover opens that envelope off the host
//     for `sagvd escrow-provision -stdin` on a new one.
//   - sentinel keygen|identity|seal-key|watch: on the primary, keep a running model's
//     state sealed generation by generation, attest every record with the
//     primary's TEE (--tee, ADR 0017), report when a tripwire fires
//     (ADR 0012); identity prints what the operator pins.
//   - failover issue|verify: the operator's signed failover policy — the
//     sentinel's key, the primary's TEE, the one standby, the triggers, the
//     grace on `stopped`, the quarantine, the required gate.
//   - recover: unseal a VG-VAULT-01 envelope with the TEE backend it names.
package main
