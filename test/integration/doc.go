// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package integration holds black-box tests that build the real sagvd,
// acp-compute and deploy/compose/keygen binaries, run them as separate
// processes over loopback, and drive them only through their public
// surfaces: the operator REST API, the mTLS Return Path, and the
// health/metrics endpoints.
//
// The tests carry the "integration" build tag because they compile
// binaries and spawn processes; run them with
//
//	make test-integration
//
// which is vault-gate sub-check 06. In-process end-to-end tests that do
// not need separate processes live in internal/integration and run with
// the unit suite.
package integration
