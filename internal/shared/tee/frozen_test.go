// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFrozen_InterfaceSurface is the R-10 interface-freeze guard.
//
// Doctrine. docs/doctrine/open-decisions-resolved.md R-10 stipulates that the TEE
// abstraction's interface surface is frozen for V1: the MVP simulated
// backend and the V2 real-hardware backend share the SAME Producer /
// Verifier / Sealer shapes. An accidental method addition or renaming
// turns a "surgical swap-in" (the V2 backend's single constructor
// replaces the simulator) into a cross-package rewrite.
//
// Strategy. Parse the /internal/shared/tee package source, enumerate
// the exported identifiers declared in tee.go (the interface file,
// excluding simulated.go and doc.go), and compare them byte-for-byte
// with a hard-coded allowlist. If the lists differ — either direction
// — the test fails with a diagnostic pointing to the doctrine section
// a contributor has to re-read before landing the change.
//
// The lists include interface names, struct/type names, consts, and
// functions. They do NOT include:
//
//   - anything in simulated.go (that is the backend, free to change),
//   - anything in doc.go (documentation only),
//   - methods on interfaces (captured by InterfaceMethods below
//     instead, which is ordered so method renames are also caught).
func TestFrozen_InterfaceSurface(t *testing.T) {
	t.Parallel()

	// The frozen R-10 surface. Every exported identifier in tee.go must
	// appear here; nothing here may be removed without amending this
	// test and docs/doctrine/bootstrap-contracts.md §15.
	wantIdentifiers := []string{
		"Evidence",
		"Measurement",
		"MeasurementFromBytes",
		"MeasurementOf",
		"Nonce",
		"NonceMinBytes",
		"Producer",
		"Sealer",
		"Verifier",
	}

	// The frozen interface method sets. Order matters only within a
	// given interface (for consistent diagnostics); we sort both sides
	// before comparing.
	wantMethods := map[string][]string{
		"Producer": {"Measurement", "Quote"},
		"Verifier": {"Verify"},
		"Sealer":   {"Seal", "Unseal"},
	}

	pkgDir := locateTeePkgDir(t)
	teeGo := filepath.Join(pkgDir, "tee.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, teeGo, nil, parser.SkipObjectResolution)
	require.NoError(t, err, "parse tee.go")

	var gotIdentifiers []string
	gotMethods := map[string][]string{}

	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if !s.Name.IsExported() {
						continue
					}
					gotIdentifiers = append(gotIdentifiers, s.Name.Name)
					if iface, ok := s.Type.(*ast.InterfaceType); ok {
						for _, m := range iface.Methods.List {
							for _, name := range m.Names {
								if name.IsExported() {
									gotMethods[s.Name.Name] =
										append(gotMethods[s.Name.Name], name.Name)
								}
							}
						}
					}
				case *ast.ValueSpec:
					for _, name := range s.Names {
						if name.IsExported() {
							gotIdentifiers = append(gotIdentifiers, name.Name)
						}
					}
				}
			}
		case *ast.FuncDecl:
			// Only top-level functions (no receiver) are part of the
			// package's exported surface that this test locks. Methods
			// on concrete types live in simulated.go.
			if d.Recv == nil && d.Name.IsExported() {
				gotIdentifiers = append(gotIdentifiers, d.Name.Name)
			}
		}
	}

	sort.Strings(gotIdentifiers)
	sort.Strings(wantIdentifiers)
	require.Equal(t, wantIdentifiers, gotIdentifiers,
		"R-10 frozen identifier surface drifted. "+
			"Add/remove in this list only alongside an amendment to "+
			"docs/doctrine/bootstrap-contracts.md §15 (iteration 5).")

	// Normalize method lists for comparison.
	for iface := range wantMethods {
		sort.Strings(wantMethods[iface])
	}
	for iface := range gotMethods {
		sort.Strings(gotMethods[iface])
	}
	require.Equal(t, wantMethods, gotMethods,
		"R-10 frozen interface method set drifted. "+
			"A V2 backend must drop into the exact shape V1 defines; "+
			"method changes require amending docs/doctrine/bootstrap-contracts.md §15.")
}

// locateTeePkgDir returns the absolute path to the /internal/shared/tee
// package source, resolved from the current test's working directory.
// Factored out so the helper can be reused if another freeze test lands
// in this package (e.g., a sealed-blob format freeze).
func locateTeePkgDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	// When `go test ./internal/shared/tee/...` runs, cwd IS the package
	// dir. Defensive: if not, walk upward to find tee.go.
	if _, err := os.Stat(filepath.Join(cwd, "tee.go")); err == nil {
		return cwd
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "internal", "shared", "tee", "tee.go")
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Dir(candidate)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate /internal/shared/tee from %s", cwd)
	return ""
}
