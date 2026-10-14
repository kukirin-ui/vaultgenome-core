// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package tee

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// snpGetDerivedKey is SNP_GET_DERIVED_KEY from include/uapi/linux/sev-guest.h:
// _IOWR('S', 0x1, struct snp_guest_request_ioctl) — direction read and
// write (3) in bits 30–31, the 32-byte argument size in bits 16–29, the
// type 'S' (0x53) in bits 8–15 and the number 1 in bits 0–7.
const snpGetDerivedKey = 0xc0205301

// snpGuestRequestIoctl is struct snp_guest_request_ioctl: 32 bytes on
// x86-64, the two buffers passed by address.
type snpGuestRequestIoctl struct {
	MsgVersion uint8
	_          [7]byte
	ReqData    uint64
	RespData   uint64
	// ExitInfo2 carries the firmware error in its low 32 bits and the
	// hypervisor's in its high 32 bits when the request fails.
	ExitInfo2 uint64
}

// snpDerivedKeyReq is struct snp_derived_key_req (MSG_KEY_REQ).
type snpDerivedKeyReq struct {
	RootKeySelect    uint32
	Rsvd             uint32
	GuestFieldSelect uint64
	VMPL             uint32
	GuestSVN         uint32
	TCBVersion       uint64
}

// snpDerivedKeyResp is struct snp_derived_key_resp: the 64-byte
// MSG_KEY_RSP payload.
type snpDerivedKeyResp struct {
	Data [64]byte
}

// sevGuestDerivedKeyIoctl issues SNP_GET_DERIVED_KEY on device.
func sevGuestDerivedKeyIoctl(device *os.File, r sevDerivedKeyRequest) ([]byte, error) {
	req := &snpDerivedKeyReq{RootKeySelect: r.RootKeySelect, GuestFieldSelect: r.GuestFieldSelect, VMPL: r.VMPL, GuestSVN: r.GuestSVN, TCBVersion: r.TCBVersion}
	resp := &snpDerivedKeyResp{}
	// The kernel reads the request and writes the response through the
	// addresses in arg while the syscall runs: pin both so the collector
	// cannot move them in the meantime.
	var pin runtime.Pinner
	pin.Pin(req)
	pin.Pin(resp)
	defer pin.Unpin()
	arg := &snpGuestRequestIoctl{
		MsgVersion: 1,
		ReqData:    uint64(uintptr(unsafe.Pointer(req))),
		RespData:   uint64(uintptr(unsafe.Pointer(resp))),
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), snpGetDerivedKey, uintptr(unsafe.Pointer(arg)))
	runtime.KeepAlive(req)
	runtime.KeepAlive(resp)
	if errno != 0 {
		return nil, fmt.Errorf("SNP_GET_DERIVED_KEY on %s: %v (firmware error %#x, hypervisor error %#x)",
			device.Name(), errno, uint32(arg.ExitInfo2), uint32(arg.ExitInfo2>>32))
	}
	key, err := sevDerivedKeyFromResponse(resp.Data[:])
	zeroize(resp.Data[:])
	return key, err
}
