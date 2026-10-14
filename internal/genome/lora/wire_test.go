// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package lora

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/validation/equivalence"
)

func f64(vals ...float64) string {
	b := make([]byte, 8*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint64(b[8*i:], math.Float64bits(v))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// sealedTo returns a genome whose fixtures digest is the digest of raw,
// so a hand-written fixtures document passes the match check.
func sealedTo(raw []byte) Genome {
	sum := sha256.Sum256(raw)
	var g Genome
	g.Fixtures.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
	return g
}

// Wire tensors decode f64 as well as f32, accept a scalar with an empty
// shape and no bytes, and refuse a negative dimension or bytes that do
// not fill the shape.
func TestParseFixtures_DecodesWireTensors(t *testing.T) {
	raw := []byte(`{"schema":"` + FixturesSchema + `","fixtures":[
		{"id":"d","expected":{"dtype":"f64","shape":[2],"raw_b64":"` + f64(1.5, -2) + `"}},
		{"id":"s","expected":{"dtype":"f32","shape":[],"raw_b64":""}}]}`)
	fx, prompts, err := ParseFixtures(sealedTo(raw), raw)
	require.NoError(t, err)
	require.Empty(t, prompts)
	require.Len(t, fx, 2)
	require.Equal(t, equivalence.F64, fx[0].Expected.DType)
	require.Equal(t, []int{2}, fx[0].Expected.Shape)
	require.Equal(t, math.Float64bits(-2), binary.LittleEndian.Uint64(fx[0].Expected.Raw[8:]))
	require.Equal(t, equivalence.F32, fx[1].Expected.DType)
	require.Empty(t, fx[1].Expected.Shape)
	require.Empty(t, fx[1].Expected.Raw)

	cases := map[string]struct {
		tensor string
		want   string
	}{
		"negative dimension": {`{"dtype":"f32","shape":[-1],"raw_b64":""}`, "negative dimension"},
		"scalar with bytes":  {`{"dtype":"f32","shape":[],"raw_b64":"` + f32(1) + `"}`, "do not fill shape"},
		"f64 short of bytes": {`{"dtype":"f64","shape":[2],"raw_b64":"` + f32(1, 2) + `"}`, "do not fill shape"},
		"unknown dtype":      {`{"dtype":"i8","shape":[1],"raw_b64":"AA=="}`, `dtype "i8"`},
		"not base64":         {`{"dtype":"f32","shape":[1],"raw_b64":"***"}`, "illegal base64"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"schema":"` + FixturesSchema + `","fixtures":[{"id":"x","expected":` + tc.tensor + `}]}`)
			_, _, err := ParseFixtures(sealedTo(raw), raw)
			require.ErrorContains(t, err, "lora: fixture x: ")
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// The integer references are refused when the document is not JSON or
// carries another schema, and reading them from a genome whose fixtures
// file is gone fails on the file.
func TestIntegerFixtures_RefusesUnreadableDocuments(t *testing.T) {
	notJSON := []byte(`{"schema":`)
	_, err := ParseIntegerFixtures(sealedTo(notJSON), notJSON)
	require.ErrorContains(t, err, "lora: fixtures: ")

	otherSchema := []byte(`{"schema":"vault-genome/other/v9","fixtures":[]}`)
	_, err = ParseIntegerFixtures(sealedTo(otherSchema), otherSchema)
	require.ErrorContains(t, err, `lora: fixtures schema "vault-genome/other/v9", want "`+FixturesSchema+`"`)

	dir := writeGenome(t, integerFixtures(), describeInteger)
	g, err := Load(dir)
	require.NoError(t, err)
	g.Fixtures.File = "gone.json"
	_, err = IntegerFixtures(dir, g)
	require.True(t, os.IsNotExist(err), "missing fixtures file: %v", err)
}

// RecipeDtype reads the recipe's dtype and falls back to float32 for a
// genome that predates the field.
func TestRecipeDtype_DefaultsToFloat32(t *testing.T) {
	var g Genome
	require.Equal(t, "float32", g.RecipeDtype())
	g.Recipe.Dtype = "bfloat16"
	require.Equal(t, "bfloat16", g.RecipeDtype())
}
