// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package receipt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// A saved receipt loads back whole — the same bytes and evidence, the
// same parsed receipt — and still verifies; the save leaves no temporary
// file beside it.
func TestSaveLoad_RoundTrip(t *testing.T) {
	dest := simulated(t, 1)
	signed, err := Sign(sample(dest.Measurement()), dest)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "restore.receipt.json")
	require.NoError(t, Save(path, signed))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left beside the receipt")
	require.Equal(t, "restore.receipt.json", entries[0].Name())

	loaded, r, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, signed, loaded)
	require.Equal(t, sample(dest.Measurement()), r)
	_, _, err = Verify(loaded, tee.NewSimulatedVerifier(dest.PublicKey(), dest.Measurement()))
	require.NoError(t, err)

	// Saving again over the same path replaces it whole.
	other := simulated(t, 2)
	again, err := Sign(sample(other.Measurement()), other)
	require.NoError(t, err)
	require.NoError(t, Save(path, again))
	loaded, _, err = Load(path)
	require.NoError(t, err)
	require.Equal(t, again, loaded)
}

// Save refuses a destination it cannot write to atomically — a directory
// that does not exist, or a path that is a directory — and cleans up its
// temporary file when the final rename fails.
func TestSave_RefusesWhereItCannotWrite(t *testing.T) {
	dest := simulated(t, 1)
	signed, err := Sign(sample(dest.Measurement()), dest)
	require.NoError(t, err)

	err = Save(filepath.Join(t.TempDir(), "absent", "r.json"), signed)
	require.ErrorContains(t, err, "receipt: save:")

	dir := t.TempDir()
	taken := filepath.Join(dir, "taken")
	require.NoError(t, os.Mkdir(taken, 0o755))
	err = Save(taken, signed)
	require.ErrorContains(t, err, "receipt: save:")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "the temporary file is removed after a failed rename")
}

// Load reports a missing file, a file that is not a saved receipt, and a
// saved receipt whose receipt bytes do not parse, each naming the path.
func TestLoad_RefusesWhatIsNotASavedReceipt(t *testing.T) {
	dir := t.TempDir()
	notJSON := filepath.Join(dir, "not.json")
	require.NoError(t, os.WriteFile(notJSON, []byte("not json"), 0o644))
	badReceipt := filepath.Join(dir, "bad.json")
	raw, err := json.Marshal(Signed{Receipt: []byte(`{"schema":"x"}`), Evidence: []byte{1}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(badReceipt, raw, 0o644))

	cases := map[string]struct {
		path string
		want string
	}{
		"missing file":               {filepath.Join(dir, "absent.json"), "receipt: load:"},
		"not json":                   {notJSON, "receipt: load " + notJSON},
		"receipt bytes do not parse": {badReceipt, "receipt: load " + badReceipt},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, r, err := Load(tc.path)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, Signed{}, s)
			require.Equal(t, Receipt{}, r)
		})
	}
}

// refusingProducer is a TEE whose quote fails, the way a producer does
// when its attestation device is unavailable.
type refusingProducer struct{ tee.Producer }

func (refusingProducer) Quote(tee.Nonce) (tee.Evidence, error) {
	return nil, errors.New("attestation device unavailable")
}

// Sign surfaces a TEE that will not quote, and a receipt that does not
// validate is refused before the TEE is asked at all.
func TestSign_RefusesWithoutAQuote(t *testing.T) {
	dest := simulated(t, 1)
	_, err := Sign(sample(dest.Measurement()), refusingProducer{dest})
	require.ErrorContains(t, err, "receipt: quote: attestation device unavailable")

	bad := sample(dest.Measurement())
	bad.Schema = "x"
	_, err = Sign(bad, refusingProducer{dest})
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), "quote"), "an invalid receipt is refused before the quote: %v", err)
}
