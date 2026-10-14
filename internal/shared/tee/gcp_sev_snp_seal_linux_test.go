// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package tee

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// The ioctl number is _IOWR('S', 0x1, struct snp_guest_request_ioctl),
// with the struct 32 bytes: recomputed here so a typo cannot ship.
func TestSNPGetDerivedKeyIoctlNumber(t *testing.T) {
	const (
		iocWrite = 1
		iocRead  = 2
	)
	size := unsafe.Sizeof(snpGuestRequestIoctl{})
	require.Equal(t, uintptr(32), size)
	require.Equal(t, uintptr(32), unsafe.Sizeof(snpDerivedKeyReq{}))
	require.Equal(t, uintptr(64), unsafe.Sizeof(snpDerivedKeyResp{}))
	want := uint32((iocRead|iocWrite)<<30) | uint32(size)<<16 | uint32('S')<<8 | 0x1
	require.Equal(t, uint32(snpGetDerivedKey), want)
}
