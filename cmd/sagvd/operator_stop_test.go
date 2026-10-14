// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/vault/revocation"
)

// The operator's stop list is read and verified once before the daemon
// starts, then again at every trust admission; a newer list takes effect
// at once, an older one put back is refused, and a list that cannot be
// read stops admissions rather than letting them through.
func TestNewOperatorStopSource(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	cfg := OperatorStopConfig{KeyID: "operator-test", PublicKeyPath: writeFile(t, dir, "operator.pub", pub), ListPath: filepath.Join(dir, "stop.json")}

	_, _, err = newOperatorStopSource(cfg)
	require.ErrorContains(t, err, "sagvd: operator_stop", "no list on disk: the daemon does not start")

	writeStopList(t, cfg.ListPath, priv, revocation.List{Serial: 3})
	src, serial, err := newOperatorStopSource(cfg)
	require.NoError(t, err)
	require.Equal(t, uint64(3), serial)
	list, err := src()
	require.NoError(t, err)
	require.Equal(t, uint64(3), list.Serial)
	require.False(t, list.StopAll)

	writeStopList(t, cfg.ListPath, priv, revocation.List{Serial: 4, StopAll: true, Reason: "incident 12"})
	list, err = src()
	require.NoError(t, err)
	require.Equal(t, uint64(4), list.Serial)
	require.True(t, list.StopAll, "the new list is in force at the next admission")

	writeStopList(t, cfg.ListPath, priv, revocation.List{Serial: 3})
	_, err = src()
	require.ErrorContains(t, err, "rollback refused")

	writeStopList(t, cfg.ListPath, priv, revocation.List{Serial: 4})
	list, err = src()
	require.NoError(t, err, "the serial already consulted is accepted again")
	require.Equal(t, uint64(4), list.Serial)

	require.NoError(t, os.Remove(cfg.ListPath))
	_, err = src()
	require.ErrorContains(t, err, "without a valid list nothing is released")
}
