// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// sentinelSeedName is the name the sentinel's seed is sealed under
// (ADR 0023): a file sealed as anything else does not open as it.
const sentinelSeedName = "sentinel.seed"

// sentinelSealKeyCmd is `acpctl sentinel seal-key`: the sentinel's seed
// file sealed in place to the primary's TEE (ADR 0023) — the chip's
// derived key on SEV-SNP, the simulated TEE's weak key off hardware — so
// the file the sentinel runs from is no seed on any other machine. The
// seed is opened once from the sealed form before the file is replaced,
// atomically, mode 0600. A file already sealed is proven to open here and
// left as it is.
func sentinelSealKeyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sentinel seal-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "The sentinel's seed file to seal in place (acpctl sentinel keygen)")
	tf := addTEEFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl sentinel seal-key --key SEED --tee gcp-sev-snp|simulated [--sev-guest-device DEV] [--tee-seed SEED --workload-descriptor D]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" || *tf.kind == "" {
		fmt.Fprintln(stderr, "acpctl sentinel seal-key: --key and --tee are required")
		return 2
	}
	provider, producer, err := tf.producer()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: %v\n", err)
		return 1
	}
	raw, err := readPrivateFile(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: --key: %v\n", err)
		return 2
	}
	out := struct {
		TEE            string `json:"tee"`
		MeasurementHex string `json:"measurement_hex"`
		Key            string `json:"key"`
		Sealed         bool   `json:"sealed"`
		AlreadySealed  bool   `json:"already_sealed,omitempty"`
	}{TEE: string(provider), MeasurementHex: hex.EncodeToString(producer.Measurement()), Key: *keyPath}
	if tee.IsSealedSecret(raw) {
		key, err := readSentinelSeed(*keyPath, tf, provider, producer)
		if err != nil {
			fmt.Fprintf(stderr, "acpctl sentinel seal-key: %s is sealed, and this host cannot open it: %v\n", *keyPath, err)
			return 1
		}
		zero(key)
		out.AlreadySealed = true
		printJSON(stdout, out)
		return 0
	}
	if len(raw) != ed25519.SeedSize {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: %s holds %d bytes, not a %d-byte seed\n", *keyPath, len(raw), ed25519.SeedSize)
		return 2
	}
	defer zero(raw)
	sealer, closer, err := tee.SealerFor(producer, tee.SealerOptions{SEVGuestDevice: *tf.sevDevice})
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: %v\n", err)
		return 1
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	blob, err := tee.SealSecret(raw, sealer, provider, producer.Measurement(), sentinelSeedName)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: %v\n", err)
		return 1
	}
	back, err := tee.OpenSecret(blob, sealer, provider, sentinelSeedName)
	if err == nil && !bytes.Equal(back, raw) {
		err = errors.New("the sealed seed did not open to the same bytes")
	}
	zero(back)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: the sealed file was not written: it does not open on this host: %v\n", err)
		return 1
	}
	if err := replaceFile(*keyPath, blob); err != nil {
		fmt.Fprintf(stderr, "acpctl sentinel seal-key: %v\n", err)
		return 1
	}
	out.Sealed = true
	printJSON(stdout, out)
	return 0
}

// readSentinelSeed reads the sentinel's seed file: 32 bare bytes, or a
// file sealed by `acpctl sentinel seal-key`, opened with the primary's
// TEE named by --tee — so a seed sealed on the pinned chip is no seed
// anywhere else. A file other users can read is refused either way.
func readSentinelSeed(path string, tf teeFlags, provider tee.Provider, producer tee.Producer) (ed25519.PrivateKey, error) {
	raw, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if !tee.IsSealedSecret(raw) {
		if len(raw) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s holds %d bytes, not a %d-byte seed", path, len(raw), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if producer == nil {
		return nil, fmt.Errorf("%s is sealed to the primary's TEE (acpctl sentinel seal-key); pass --tee to open it", path)
	}
	sealer, closer, err := tee.SealerFor(producer, tee.SealerOptions{SEVGuestDevice: *tf.sevDevice})
	if err != nil {
		return nil, fmt.Errorf("%s is sealed, and this host cannot open it: %w", path, err)
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	plain, err := tee.OpenSecret(raw, sealer, provider, sentinelSeedName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer zero(plain)
	if len(plain) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: the sealed seed is %d bytes, want %d", path, len(plain), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(plain), nil
}

// readPrivateFile reads a file, refusing one other users can read.
func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other users (mode %04o); chmod 600 it", path, perm)
	}
	return os.ReadFile(path)
}

// replaceFile writes data beside path, mode 0600, and renames it over
// path: the old bytes are never half-replaced.
func replaceFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	err = f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(data)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func printJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
