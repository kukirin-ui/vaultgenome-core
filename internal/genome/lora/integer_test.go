// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package lora

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// integerFixtures is twoFixtures with the integer door's references, as
// the worker writes them beside the float ones.
func integerFixtures() map[string]any {
	fx := twoFixtures()
	list := fx["fixtures"].([]map[string]any)
	list[0]["expected_integer"] = map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32(1.375, -2.125)}
	list[1]["expected_integer"] = map[string]any{"dtype": "f32", "shape": []int{2}, "raw_b64": f32(0.25, 3.0625)}
	fx["integer"] = map[string]any{"scheme": IntegerDoorScheme, "fidelity": map[string]any{"fixtures": 2, "top1_same": 2, "max_abs_err": 0.125}}
	return fx
}

func describeInteger(g map[string]any) {
	g["fixtures"].(map[string]any)["integer"] = map[string]any{
		"scheme": IntegerDoorScheme, "fidelity": map[string]any{"fixtures": 2, "top1_same": 2, "max_abs_err": 0.125, "max_rel_err": 0.09},
	}
}

func TestIntegerFixtures_AreReadBesideTheFloatOnes(t *testing.T) {
	dir := writeGenome(t, integerFixtures(), describeInteger)
	g, err := Load(dir)
	require.NoError(t, err)
	require.NotNil(t, g.Fixtures.Integer)
	require.Equal(t, IntegerDoorScheme, g.Fixtures.Integer.Scheme)
	require.Equal(t, 2, g.Fixtures.Integer.Fidelity.Top1Same)
	require.Equal(t, 0.125, g.Fixtures.Integer.Fidelity.MaxAbsErr)

	fx, err := Fixtures(dir, g)
	require.NoError(t, err)
	ifx, err := IntegerFixtures(dir, g)
	require.NoError(t, err)
	require.Len(t, ifx, 2)
	require.Equal(t, IDs(fx), IDs(ifx), "the same fixtures, in order")
	require.True(t, ifx[0].Critical)
	require.NotEqual(t, fx[0].Expected.Raw, ifx[0].Expected.Raw, "the integer door's own arithmetic, not the float reference")
	require.Equal(t, fx[0].Expected.Shape, ifx[0].Expected.Shape)
}

func TestIntegerFixtures_NilForAGenomeWithoutThem(t *testing.T) {
	dir := writeGenome(t, twoFixtures(), nil)
	g, err := Load(dir)
	require.NoError(t, err)
	require.Nil(t, g.Fixtures.Integer)
	ifx, err := IntegerFixtures(dir, g)
	require.NoError(t, err)
	require.Nil(t, ifx)
}

func TestIntegerFixtures_RefusesHalfDescribedReferences(t *testing.T) {
	t.Run("references genome.json does not describe", func(t *testing.T) {
		dir := writeGenome(t, integerFixtures(), nil)
		g, err := Load(dir)
		require.NoError(t, err)
		_, err = IntegerFixtures(dir, g)
		require.ErrorContains(t, err, "does not describe")
	})
	t.Run("a description without references", func(t *testing.T) {
		dir := writeGenome(t, twoFixtures(), describeInteger)
		g, err := Load(dir)
		require.NoError(t, err)
		_, err = IntegerFixtures(dir, g)
		require.ErrorContains(t, err, "0 of 2 fixtures")
	})
	t.Run("a reference on one fixture only", func(t *testing.T) {
		fx := integerFixtures()
		delete(fx["fixtures"].([]map[string]any)[1], "expected_integer")
		dir := writeGenome(t, fx, describeInteger)
		g, err := Load(dir)
		require.NoError(t, err)
		_, err = IntegerFixtures(dir, g)
		require.ErrorContains(t, err, "1 of 2 fixtures")
	})
	t.Run("a scheme this build does not know", func(t *testing.T) {
		dir := writeGenome(t, integerFixtures(), func(g map[string]any) {
			describeInteger(g)
			g["fixtures"].(map[string]any)["integer"].(map[string]any)["scheme"] = "vg-integer-door/v9"
		})
		g, err := Load(dir)
		require.NoError(t, err)
		_, err = IntegerFixtures(dir, g)
		require.ErrorContains(t, err, "vg-integer-door/v9")
	})
	t.Run("a reference that does not fill its shape", func(t *testing.T) {
		fx := integerFixtures()
		fx["fixtures"].([]map[string]any)[0]["expected_integer"] = map[string]any{"dtype": "f32", "shape": []int{3}, "raw_b64": f32(1, 2)}
		dir := writeGenome(t, fx, describeInteger)
		g, err := Load(dir)
		require.NoError(t, err)
		_, err = IntegerFixtures(dir, g)
		require.ErrorContains(t, err, "do not fill shape")
	})
	t.Run("fixtures edited after sealing", func(t *testing.T) {
		dir := writeGenome(t, integerFixtures(), describeInteger)
		g, err := Load(dir)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "fixtures.json"), []byte(`{"schema":"vault-genome/lora-fixtures/v1","fixtures":[]}`), 0o644))
		_, err = IntegerFixtures(dir, g)
		require.ErrorContains(t, err, "do not match")
	})
}
