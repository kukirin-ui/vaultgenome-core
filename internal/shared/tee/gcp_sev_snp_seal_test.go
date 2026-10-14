// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// fakeSEVGuest stands in for the firmware: the derived key is a function
// of the chip secret and the fields the request selects, exactly as the
// PSP would derive it — the same request on the same chip gives the same
// key, and a different guest (measurement, policy) or chip gives another.
type fakeSEVGuest struct {
	chip        []byte
	measurement [48]byte
	policy      uint64
	calls       int
	fail        error
}

func (g *fakeSEVGuest) derive(_ *os.File, req sevDerivedKeyRequest) ([]byte, error) {
	g.calls++
	if g.fail != nil {
		return nil, g.fail
	}
	h := sha256.New()
	h.Write(g.chip)
	_ = binary.Write(h, binary.LittleEndian, req.RootKeySelect)
	_ = binary.Write(h, binary.LittleEndian, req.GuestFieldSelect)
	_ = binary.Write(h, binary.LittleEndian, req.VMPL)
	if req.GuestFieldSelect&sevFieldMeasurement != 0 {
		h.Write(g.measurement[:])
	}
	if req.GuestFieldSelect&sevFieldGuestPolicy != 0 {
		_ = binary.Write(h, binary.LittleEndian, g.policy)
	}
	return h.Sum(nil), nil
}

// installFakeGuest routes the sealer's firmware request to g for the test.
func installFakeGuest(t *testing.T, g *fakeSEVGuest) {
	t.Helper()
	prev := sevGuestDerivedKey
	sevGuestDerivedKey = g.derive
	t.Cleanup(func() { sevGuestDerivedKey = prev })
}

// sealerDevice is any open file: the fake guest never reads it, and the
// real ioctl path is exercised on hardware.
func sealerDevice(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "sev-guest"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func testGuest() *fakeSEVGuest {
	g := &fakeSEVGuest{chip: bytes.Repeat([]byte{0xC1}, 32), policy: 0x30000}
	for i := range g.measurement {
		g.measurement[i] = byte(i)
	}
	return g
}

func TestSEVSealerRoundTripsAndBindsAAD(t *testing.T) {
	g := testGuest()
	installFakeGuest(t, g)
	s := NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy)
	pt, aad := []byte("escrow private key bytes"), []byte("vault-genome sealed-escrow-key v1")
	sealed, err := s.Seal(pt, aad)
	require.NoError(t, err)
	require.Len(t, sealed, 12+len(pt)+16)
	require.NotContains(t, string(sealed), string(pt))

	// The same chip and guest, in a fresh sealer (a restart), opens it.
	again := NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy)
	got, err := again.Unseal(sealed, aad)
	require.NoError(t, err)
	require.Equal(t, pt, got)

	_, err = again.Unseal(sealed, []byte("other aad"))
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)/2] ^= 1
	_, err = again.Unseal(tampered, aad)
	require.Error(t, err)

	_, err = again.Unseal(sealed[:20], aad)
	require.Error(t, err)

	other, err := s.Seal(pt, aad)
	require.NoError(t, err)
	require.False(t, bytes.Equal(sealed, other), "a fresh nonce per seal")
	require.Equal(t, 6, g.calls, "the key is derived for every call and never kept")
}

// A blob sealed on one guest does not open on another chip, at another
// measurement or under another policy: the firmware derives a different
// root, and the sealer's own expansion differs too.
func TestSEVSealerIsBoundToChipMeasurementAndPolicy(t *testing.T) {
	g := testGuest()
	installFakeGuest(t, g)
	s := NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy)
	sealed, err := s.Seal([]byte("secret"), []byte("aad"))
	require.NoError(t, err)

	otherChip := testGuest()
	otherChip.chip = bytes.Repeat([]byte{0xC2}, 32)
	installFakeGuest(t, otherChip)
	_, err = NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy).Unseal(sealed, []byte("aad"))
	require.Error(t, err, "another chip")

	otherImage := testGuest()
	otherImage.measurement[0] ^= 0xFF
	installFakeGuest(t, otherImage)
	_, err = NewGCPSEVSealer(sealerDevice(t), otherImage.measurement[:], g.policy).Unseal(sealed, []byte("aad"))
	require.Error(t, err, "another VM image")

	debuggable := testGuest()
	debuggable.policy |= sevPolicyDebug
	installFakeGuest(t, debuggable)
	_, err = NewGCPSEVSealer(sealerDevice(t), g.measurement[:], debuggable.policy).Unseal(sealed, []byte("aad"))
	require.Error(t, err, "a debuggable guest")

	// A sealer whose belief about the guest differs from the firmware's
	// derives a different expansion even on the same chip.
	installFakeGuest(t, g)
	_, err = NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy+1).Unseal(sealed, []byte("aad"))
	require.Error(t, err)
}

func TestSEVSealerRequestSelectsMeasurementAndPolicyOnly(t *testing.T) {
	req := sealingRequestSeen(t)
	require.Equal(t, uint32(0), req.RootKeySelect, "the VCEK root")
	require.Equal(t, uint64(sevFieldGuestPolicy|sevFieldMeasurement), req.GuestFieldSelect)
	require.Zero(t, req.GuestFieldSelect&sevFieldTCBVersion, "a firmware update must not lock the sealed data out")
	require.Zero(t, req.GuestFieldSelect&sevFieldGuestSVN)
	require.Equal(t, uint32(0), req.VMPL)
}

func sealingRequestSeen(t *testing.T) sevDerivedKeyRequest {
	t.Helper()
	var seen sevDerivedKeyRequest
	prev := sevGuestDerivedKey
	sevGuestDerivedKey = func(_ *os.File, req sevDerivedKeyRequest) ([]byte, error) {
		seen = req
		return bytes.Repeat([]byte{7}, 32), nil
	}
	t.Cleanup(func() { sevGuestDerivedKey = prev })
	g := testGuest()
	_, err := NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy).Seal([]byte("x"), nil)
	require.NoError(t, err)
	return seen
}

func TestSEVSealerRefusesWhatItCannotSeal(t *testing.T) {
	g := testGuest()
	installFakeGuest(t, g)
	_, err := NewGCPSEVSealer(nil, g.measurement[:], g.policy).Seal([]byte("x"), nil)
	require.ErrorContains(t, err, "no /dev/sev-guest")
	_, err = NewGCPSEVSealer(sealerDevice(t), Measurement(bytes.Repeat([]byte{1}, 32)), g.policy).Seal([]byte("x"), nil)
	require.ErrorContains(t, err, "48-byte")

	g.fail = errors.New("SNP_GET_DERIVED_KEY: input/output error (firmware error 0x16, hypervisor error 0x0)")
	_, err = NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy).Seal([]byte("x"), nil)
	require.ErrorContains(t, err, "firmware error 0x16")
	_, err = NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy).Unseal(bytes.Repeat([]byte{1}, 40), nil)
	require.ErrorContains(t, err, "derive key")
}

func TestSEVDerivedKeyResponse(t *testing.T) {
	var resp [64]byte
	for i := 32; i < 64; i++ {
		resp[i] = byte(i)
	}
	key, err := sevDerivedKeyFromResponse(resp[:])
	require.NoError(t, err)
	require.Equal(t, resp[32:64], key)

	binary.LittleEndian.PutUint32(resp[:4], 0x16)
	_, err = sevDerivedKeyFromResponse(resp[:])
	require.ErrorContains(t, err, "status 0x16")

	_, err = sevDerivedKeyFromResponse(make([]byte, 64))
	require.ErrorContains(t, err, "all-zero")
	_, err = sevDerivedKeyFromResponse(resp[:40])
	require.ErrorContains(t, err, "40 bytes")
}

// Without a guest to ask, the sealer says so rather than sealing under a
// key that is not the chip's.
func TestSEVSealerWithoutAGuestFails(t *testing.T) {
	if _, err := os.Stat("/dev/sev-guest"); err == nil {
		t.Skip("a real /dev/sev-guest is present")
	}
	g := testGuest()
	_, err := NewGCPSEVSealer(sealerDevice(t), g.measurement[:], g.policy).Seal([]byte("x"), nil)
	require.Error(t, err)
}
