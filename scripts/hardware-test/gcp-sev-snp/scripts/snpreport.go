// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// snpreport.go — request a real SEV-SNP attestation report from
// /dev/sev-guest via direct ioctl, write the raw 1184-byte report to a
// file. Independent of snpguest/Rust toolchain — pure Go stdlib + a
// few syscalls. Captures the artefact Vault Genome's hardware
// validation workflow needs as a chip-rooted proof point.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Linux uapi mirrors of <linux/sev-guest.h>.
type snpReportReq struct {
	UserData [64]byte
	VMPL     uint32
	Rsvd     [28]byte
}

type snpReportResp struct {
	Data [4000]byte
}

type snpGuestReqIoctl struct {
	MsgVersion uint8
	_pad       [7]byte
	ReqData    uint64
	RespData   uint64
	FwErr      uint64
}

// SNP_GET_REPORT = _IOWR('S', 0x0, sizeof(snpGuestReqIoctl))
//
//	= (3<<30) | (32<<16) | (0x53<<8) | 0
//	= 0xC0205300
const SNP_GET_REPORT = 0xC0205300

func main() {
	out := "snp-attestation-report.bin"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	f, err := os.OpenFile("/dev/sev-guest", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open /dev/sev-guest:", err)
		os.Exit(1)
	}
	defer f.Close()

	var req snpReportReq
	if _, err := rand.Read(req.UserData[:]); err != nil {
		fmt.Fprintln(os.Stderr, "rand:", err)
		os.Exit(1)
	}

	var resp snpReportResp

	ioctl := snpGuestReqIoctl{
		MsgVersion: 1,
		ReqData:    uint64(uintptr(unsafe.Pointer(&req))),
		RespData:   uint64(uintptr(unsafe.Pointer(&resp))),
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		SNP_GET_REPORT,
		uintptr(unsafe.Pointer(&ioctl)),
	)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "ioctl SNP_GET_REPORT: %v (fw_err=0x%x)\n", errno, ioctl.FwErr)
		os.Exit(1)
	}

	report := resp.Data[:1184]
	if err := os.WriteFile(out, report, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	fmt.Printf("✓ SEV-SNP attestation report captured\n")
	fmt.Printf("  output:    %s\n", out)
	fmt.Printf("  size:      %d bytes\n", len(report))
	fmt.Printf("  user_data: %s...\n", hex.EncodeToString(req.UserData[:32]))
	fmt.Printf("  fw_err:    0x%x\n", ioctl.FwErr)
}
