// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package tee

import (
	"errors"
	"os"
)

// sevGuestDerivedKeyIoctl needs the Linux sev-guest driver.
func sevGuestDerivedKeyIoctl(_ *os.File, _ sevDerivedKeyRequest) ([]byte, error) {
	return nil, errors.New("SEV-SNP derived keys come from /dev/sev-guest, a Linux device; this build runs elsewhere")
}
