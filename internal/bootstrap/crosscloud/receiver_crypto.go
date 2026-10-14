// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package crosscloud

import "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"

// sha256OfBytes returns the SHA-256 digest of b. Indirection through a
// dedicated helper isolates the stdlib hashing dependency in one
// file, which simplifies the audit trail when Phase 5 swaps in a
// hardware-backed digest engine.
func sha256OfBytes(b []byte) [32]byte {
	return crypto.SHA256(b)
}
