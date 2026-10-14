// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The usage text names every command main dispatches, so an operator who
// reads it finds each one. printUsage writes to the process's stdout, so
// the test lends it a pipe; it runs alone, never in parallel.
func TestPrintUsage_NamesEveryCommand(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	saved := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = saved })

	done := make(chan struct{})
	var out bytes.Buffer
	go func() {
		defer close(done)
		_, _ = io.Copy(&out, r)
	}()
	printUsage()
	os.Stdout = saved
	require.NoError(t, w.Close())
	<-done
	require.NoError(t, r.Close())

	text := out.String()
	require.True(t, strings.HasPrefix(text, "acpctl — AI Continuity Platform administrative CLI\n"))
	for _, cmd := range []string{"version", "help", "recover", "status", "audit query", "audit verify", "lineage",
		"genome seal", "genome open", "genome verify", "genome inspect", "genome chain",
		"stop keygen", "stop issue", "stop verify",
		"escrow keygen", "escrow recovery-keygen", "escrow recover",
		"sentinel keygen", "sentinel identity", "sentinel seal-key", "sentinel watch",
		"failover issue", "failover verify"} {
		require.Regexp(t, `(?m)^  `+cmd+` +\S`, text, "command %q is listed with a description", cmd)
	}
	require.True(t, strings.HasSuffix(text, "Run `acpctl <command> --help` for per-subcommand flags.\n"))
}
