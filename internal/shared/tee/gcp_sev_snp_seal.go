// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Sealing on AMD SEV-SNP. The guest asks the firmware, through
// /dev/sev-guest (SNP_GET_DERIVED_KEY), for a key derived from the chip's
// VCEK root and the guest's own launch measurement and policy; the
// hypervisor forwards the request and cannot read it. The sealer expands
// that 32-byte root into an AES-256-GCM key with a label of its own, so a
// blob it seals is opened only by this code, on this chip, at this
// measurement and policy. A different VM image, a debuggable guest, or
// another chip derives a different key, and the AEAD fails to open.
//
// The key is not written anywhere: it is derived for every Seal and
// Unseal and zeroed after. The kernel ABI is in
// include/uapi/linux/sev-guest.h; the message layout is MSG_KEY_REQ /
// MSG_KEY_RSP of the SEV-SNP firmware ABI.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
)

// sevSealingLabel binds the AEAD key to this use of the derived key.
const sevSealingLabel = "vault-genome/sev-snp-sealing/v1"

// GUEST_FIELD_SELECT bits of MSG_KEY_REQ: which guest fields the firmware
// mixes into the derived key.
const (
	sevFieldGuestPolicy = 1 << 0
	sevFieldImageID     = 1 << 1
	sevFieldFamilyID    = 1 << 2
	sevFieldMeasurement = 1 << 3
	sevFieldGuestSVN    = 1 << 4
	sevFieldTCBVersion  = 1 << 5
)

// sevDerivedKeyBytes is the length of the key MSG_KEY_RSP carries.
const sevDerivedKeyBytes = 32

// sevDerivedKeyRequest is what the sealer asks the firmware for.
type sevDerivedKeyRequest struct {
	// RootKeySelect: 0 derives from the VCEK (chip and firmware TCB),
	// 1 from the VMRK the hypervisor set at launch.
	RootKeySelect    uint32
	GuestFieldSelect uint64
	// VMPL is the privilege level the key is for; it must not be below
	// the requester's own.
	VMPL       uint32
	GuestSVN   uint32
	TCBVersion uint64
}

// sevGuestDerivedKey asks the firmware for the derived key. Linux only;
// tests substitute a fake guest.
var sevGuestDerivedKey = func(device *os.File, req sevDerivedKeyRequest) ([]byte, error) {
	return sevGuestDerivedKeyIoctl(device, req)
}

// sevSealingRequest is the request every sealer makes: the VCEK root, the
// launch measurement and the guest policy mixed in, VMPL 0. Neither the
// guest SVN nor the TCB version is mixed in, so a firmware update on the
// same chip still opens what was sealed before it.
func sevSealingRequest() sevDerivedKeyRequest {
	return sevDerivedKeyRequest{RootKeySelect: 0, GuestFieldSelect: sevFieldGuestPolicy | sevFieldMeasurement, VMPL: 0}
}

// realSEVSNPDerivedKey derives the sealer's AES-256 key: the firmware's
// derived key, expanded with the sealing label, the measurement and the
// policy the sealer was built with.
func realSEVSNPDerivedKey(device *os.File, measure Measurement, policy uint64) ([]byte, error) {
	if device == nil {
		return nil, errors.New("no /dev/sev-guest handle")
	}
	if len(measure) != 48 {
		return nil, fmt.Errorf("measurement must be the 48-byte SEV-SNP launch measurement, got %d bytes", len(measure))
	}
	root, err := sevGuestDerivedKey(device, sevSealingRequest())
	if err != nil {
		return nil, err
	}
	defer zeroize(root)
	if len(root) != sevDerivedKeyBytes {
		return nil, fmt.Errorf("derived key is %d bytes, want %d", len(root), sevDerivedKeyBytes)
	}
	info := make([]byte, 0, len(sevSealingLabel)+1+len(measure)+8)
	info = append(info, sevSealingLabel...)
	info = append(info, 0)
	info = append(info, measure...)
	info = binary.LittleEndian.AppendUint64(info, policy)
	return crypto.HKDFSHA256(nil, root, info, crypto.AES256KeySize)
}

// sevDerivedKeyFromResponse reads MSG_KEY_RSP: STATUS (4 bytes, little
// endian), reserved, then the 32-byte DERIVED_KEY at offset 0x20.
func sevDerivedKeyFromResponse(data []byte) ([]byte, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("derived-key response is %d bytes, want 64", len(data))
	}
	if status := binary.LittleEndian.Uint32(data[:4]); status != 0 {
		return nil, fmt.Errorf("firmware refused the derived-key request: status %#x", status)
	}
	key := append([]byte(nil), data[32:64]...)
	if Measurement(key).IsZero() {
		return nil, errors.New("firmware returned an all-zero derived key")
	}
	return key, nil
}

// realSEVAEADSeal is AES-256-GCM: a fresh 12-byte nonce, then the
// ciphertext and tag.
func realSEVAEADSeal(key, plaintext, aad []byte) ([]byte, error) {
	nonce, ct, err := crypto.Seal(key, plaintext, aad, nil)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// realSEVAEADOpen reverses realSEVAEADSeal.
func realSEVAEADOpen(key, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < crypto.GCMNonceSize+crypto.GCMTagSize {
		return nil, errors.New("sealed blob too short")
	}
	return crypto.Open(key, sealed[:crypto.GCMNonceSize], sealed[crypto.GCMNonceSize:], aad)
}

func init() {
	sevSNPDerivedKey = realSEVSNPDerivedKey
	sevAEADSeal = realSEVAEADSeal
	sevAEADOpen = realSEVAEADOpen
}
