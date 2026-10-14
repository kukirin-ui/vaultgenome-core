// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud_test

import "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"

// shaTest32 returns the project-canonical SHA-256 digest. Kept in
// its own _test.go file so the heavy imports in http_handler_test.go
// stay focused on the HTTP round-trip surface.
func shaTest32(b []byte) [32]byte {
	return crypto.SHA256(b)
}
