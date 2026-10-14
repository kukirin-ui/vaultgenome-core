// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker_test

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

// TestFrozen_ReconstructorInterface is the R-11 interface-freeze guard
// for /internal/compute/worker.
//
// Doctrine. docs/doctrine/open-decisions-resolved.md R-11 stipulates that the
// generative reconstruction mechanism is a placeholder only for V1; the
// V2 production backend replaces the implementation behind the
// Reconstructor interface, and the interface itself does not change.
// A surgical V2 swap is only possible if the shape of the interface
// and of its neighbour types (ComponentMaterial) is locked.
//
// Strategy. Parse reconstruction.go and enumerate:
//
//   - exported type names (interface, struct, alias),
//   - exported constant and variable names declared in the file,
//   - exported top-level function names (no receiver),
//   - method sets of exported interfaces.
//
// The enumerated shape is compared against a hard-coded expectation.
// If a contributor adds a new exported identifier to this file — or a
// method to Reconstructor — the test fails with a diagnostic that
// points at docs/doctrine/bootstrap-contracts.md §15, which must be
// amended before the change is allowed to land.
func TestFrozen_ReconstructorInterface(t *testing.T) {
	t.Parallel()

	wantIdentifiers := []string{
		"ComponentMaterial",
		"DeterministicReconstructor",
		"NewDeterministicReconstructor",
		"Reconstructor",
	}

	// The frozen interface method set. Ordering is stabilised by
	// sorting both sides before comparison.
	wantMethods := map[string][]string{
		"Reconstructor": {"Reconstruct"},
	}

	pkgDir := locateWorkerPkgDir(t)
	recon := filepath.Join(pkgDir, "reconstruction.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, recon, nil, parser.SkipObjectResolution)
	require.NoError(t, err, "parse reconstruction.go")

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
					// Skip blank-identifier compile-time assertions
					// like `var _ Reconstructor = (*Foo)(nil)`.
					for _, name := range s.Names {
						if name.Name == "_" {
							continue
						}
						if name.IsExported() {
							gotIdentifiers = append(gotIdentifiers, name.Name)
						}
					}
				}
			}
		case *ast.FuncDecl:
			if d.Recv != nil {
				continue // methods belong to their receiver type
			}
			if d.Name.IsExported() {
				gotIdentifiers = append(gotIdentifiers, d.Name.Name)
			}
		}
	}

	sort.Strings(gotIdentifiers)
	sort.Strings(wantIdentifiers)
	require.Equal(t, wantIdentifiers, gotIdentifiers,
		"R-11 frozen identifier surface drifted. "+
			"Add/remove in this list only alongside an amendment to "+
			"docs/doctrine/bootstrap-contracts.md §15 (iteration 5).")

	for iface := range wantMethods {
		sort.Strings(wantMethods[iface])
	}
	for iface := range gotMethods {
		sort.Strings(gotMethods[iface])
	}
	require.Equal(t, wantMethods, gotMethods,
		"R-11 frozen interface method set drifted. "+
			"A V2 generative backend must drop into the exact shape V1 "+
			"defines; method changes require amending "+
			"docs/doctrine/bootstrap-contracts.md §15.")
}

func locateWorkerPkgDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	if _, err := os.Stat(filepath.Join(cwd, "reconstruction.go")); err == nil {
		return cwd
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "internal", "compute", "worker", "reconstruction.go")
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Dir(candidate)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate /internal/compute/worker from %s", cwd)
	return ""
}
