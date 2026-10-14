// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package doctrine

// Stale-branch regression harness for doctrine policy scripts.
//
// Purpose. The doctrine test suite (TestInvariant_01 … TestInvariant_11)
// proves that the *current* tree upholds every architectural invariant.
// This file proves something different and complementary: that the
// doctrine policy SCRIPTS actually *catch* a regression.
//
// The failure mode this file defends against is "silent drift" — a
// developer branches off a tree in which an invariant has not yet been
// added or has been weakened, does work that trips a newer invariant,
// then rebases. If the doctrine script were over-permissive (for
// example because a regex was wrong, or because the tree-walker missed
// a file type, or because an excludes-list was too generous), the
// rebased branch could land without its violation ever being named.
//
// This harness forces the inverse: for each policy script we care
// about, we synthesise a tiny "stale" tree that KNOWS it violates the
// invariant, run the script against that tree, and assert that the
// script returns a non-zero exit and names the violation. We also run
// the script against a clean synthetic tree and assert green, so the
// "true negative" direction is exercised too.
//
// Scripts covered in this file:
//
//   - scripts/terminology_check.sh
//       positive: a .go file using a deprecated term from
//       docs/doctrine/terminology.md §4 trips the check.
//       negative: a clean .go file does not trip it.
//
//   - scripts/license_header_check.sh
//       positive: a .go file missing the SPDX header trips the check.
//       negative: a .go file carrying the header does not trip it.
//
// Out of scope here. dep-allowlist and dep-depth depend on `go mod
// graph`, which in turn depends on a compilable synthetic module; that
// is a heavier harness and belongs in its own file. This file sticks to
// scripts whose inputs are plain files on disk.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test_Regression_TerminologyScriptCatchesStaleTerm creates a temp tree
// containing a single .go file that uses the deprecated project name
// "genome_vault" in prose, invokes the terminology check script against
// that tree, and asserts that the script exits non-zero and names the
// offending pattern.
func Test_Regression_TerminologyScriptCatchesStaleTerm(t *testing.T) {
	t.Parallel()
	modRoot := locateModuleRoot(t)
	script := filepath.Join(modRoot, "scripts", "terminology_check.sh")

	staleTree := t.TempDir()
	// Drop a .go file carrying a deprecated project name. "genome_vault"
	// is on the §4 list because it is a former name of the project; the
	// rename to "VaultGenome" / "genome" must stay complete (see §2 of
	// docs/doctrine/terminology.md).
	stalePath := filepath.Join(staleTree, "stale.go")
	staleContent := `// SPDX-License-Identifier: AGPL-3.0-or-later
package stale

// The genome_vault module used to live here.
// This comment is DELIBERATELY WRONG for the regression harness — it
// uses the deprecated project name "genome_vault" which is banned by
// docs/doctrine/terminology.md §4.
`
	if err := os.WriteFile(stalePath, []byte(staleContent), 0o644); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	out, err := runScript(t, script, staleTree)
	if err == nil {
		t.Fatalf("terminology_check.sh returned green on a stale tree — regression harness failed\noutput:\n%s", out)
	}
	if !strings.Contains(out, "terminology_check: FAIL") {
		t.Fatalf("terminology_check.sh failed but did not emit the 'FAIL' verdict line\noutput:\n%s", out)
	}
	if !strings.Contains(out, "genome_vault") {
		t.Fatalf("terminology_check.sh failed but did not name the offending term\noutput:\n%s", out)
	}
}

// Test_Regression_TerminologyScriptPassesCleanTree creates a temp tree
// containing a single .go file with only canonical terms and asserts
// that the terminology script returns green. This defends against a
// "false positive" regression where an over-broad pattern would trip
// the check even in a clean tree.
func Test_Regression_TerminologyScriptPassesCleanTree(t *testing.T) {
	t.Parallel()
	modRoot := locateModuleRoot(t)
	script := filepath.Join(modRoot, "scripts", "terminology_check.sh")

	cleanTree := t.TempDir()
	cleanPath := filepath.Join(cleanTree, "clean.go")
	cleanContent := `// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
package clean

// The Vault mints a SessionObject and drives Staged Disclosure through
// StagedSequencer. The ReleaseDecision binds the AuditEventID of the
// authorising audit event. Every term here is canonical per
// docs/doctrine/terminology.md.
`
	if err := os.WriteFile(cleanPath, []byte(cleanContent), 0o644); err != nil {
		t.Fatalf("write clean file: %v", err)
	}

	out, err := runScript(t, script, cleanTree)
	if err != nil {
		t.Fatalf("terminology_check.sh returned non-zero on a clean tree — regression harness failed\noutput:\n%s\nerr: %v", out, err)
	}
	if !strings.Contains(out, "terminology_check: PASS") {
		t.Fatalf("terminology_check.sh returned zero but did not emit the 'PASS' verdict line\noutput:\n%s", out)
	}
}

// Test_Regression_LicenseHeaderScriptCatchesMissingHeader creates a
// temp tree containing a single .go file without the SPDX header,
// invokes the license header check script, and asserts that it exits
// non-zero and names the offending file path.
func Test_Regression_LicenseHeaderScriptCatchesMissingHeader(t *testing.T) {
	t.Parallel()
	modRoot := locateModuleRoot(t)
	script := filepath.Join(modRoot, "scripts", "license_header_check.sh")

	staleTree := t.TempDir()
	stalePath := filepath.Join(staleTree, "stale.go")
	// DELIBERATELY OMITS the SPDX header that every .go file must carry
	// per docs/doctrine/ci-security-policy.md §7.
	staleContent := `package stale

// No SPDX header above. This file is DELIBERATELY WRONG for the
// regression harness.

func HelloDoctrine() string { return "doctrine" }
`
	if err := os.WriteFile(stalePath, []byte(staleContent), 0o644); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	out, err := runScript(t, script, staleTree)
	if err == nil {
		t.Fatalf("license_header_check.sh returned green on a tree with a missing header — regression harness failed\noutput:\n%s", out)
	}
	if !strings.Contains(out, "license_header_check: FAIL") {
		t.Fatalf("license_header_check.sh failed but did not emit the 'FAIL' verdict line\noutput:\n%s", out)
	}
	if !strings.Contains(out, "stale.go") {
		t.Fatalf("license_header_check.sh failed but did not name the offending file\noutput:\n%s", out)
	}
}

// Test_Regression_LicenseHeaderScriptPassesCleanTree creates a temp
// tree containing a single correctly-headered .go file and asserts
// that the license header script returns green.
func Test_Regression_LicenseHeaderScriptPassesCleanTree(t *testing.T) {
	t.Parallel()
	modRoot := locateModuleRoot(t)
	script := filepath.Join(modRoot, "scripts", "license_header_check.sh")

	cleanTree := t.TempDir()
	cleanPath := filepath.Join(cleanTree, "clean.go")
	cleanContent := `// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package clean

func HelloDoctrine() string { return "doctrine" }
`
	if err := os.WriteFile(cleanPath, []byte(cleanContent), 0o644); err != nil {
		t.Fatalf("write clean file: %v", err)
	}

	out, err := runScript(t, script, cleanTree)
	if err != nil {
		t.Fatalf("license_header_check.sh returned non-zero on a clean tree — regression harness failed\noutput:\n%s\nerr: %v", out, err)
	}
	if !strings.Contains(out, "license_header_check: PASS") {
		t.Fatalf("license_header_check.sh returned zero but did not emit the 'PASS' verdict line\noutput:\n%s", out)
	}
}

// Test_Regression_TerminologyScriptCatchesEachPattern walks every
// deprecated-term pattern enumerated in docs/doctrine/terminology.md §4
// (as mirrored in terminology_check.sh) and asserts that a minimal
// file carrying that term trips the script. This defends against
// someone silently dropping a pattern from the script's PATTERNS array.
func Test_Regression_TerminologyScriptCatchesEachPattern(t *testing.T) {
	t.Parallel()
	modRoot := locateModuleRoot(t)
	script := filepath.Join(modRoot, "scripts", "terminology_check.sh")

	// Probes. Each probe is a minimal sentence that exercises one §4
	// pattern. The set MUST stay in sync with terminology_check.sh
	// PATTERNS. If a pattern is removed from the script, the
	// corresponding probe here must also be removed — but only after
	// docs/doctrine/terminology.md has been amended to drop that term
	// from the deprecation list.
	probes := []struct {
		name    string
		content string
	}{
		{"NSV", "// the NSV component is deprecated"},
		{"neural_seed", "// see the neural_seed reference"},
		{"NeuralSeedVault", "// NeuralSeedVault is the old name"},
		{"neural_seed_vault", "// the neural_seed_vault module"},
		{"genome_vault", "// the genome_vault service"},
		// The vocabulary terms of terminology.md §5 (restore/restoration/
		// backup/"decrypt and load"/"model file"/"weights file") are
		// advisory house style, not gated — see §5 — so they are not
		// probed here. Only the §4 project-name bans are enforced.
	}

	for _, probe := range probes {
		probe := probe
		t.Run(probe.name, func(t *testing.T) {
			tree := t.TempDir()
			path := filepath.Join(tree, "probe.go")
			contents := "// SPDX-License-Identifier: AGPL-3.0-or-later\npackage probe\n\n" + probe.content + "\n"
			if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
				t.Fatalf("write probe file: %v", err)
			}
			out, err := runScript(t, script, tree)
			if err == nil {
				t.Fatalf("pattern %q did not trip terminology_check.sh\noutput:\n%s", probe.name, out)
			}
			if !strings.Contains(out, "terminology_check: FAIL") {
				t.Fatalf("pattern %q tripped non-zero exit but no FAIL verdict line\noutput:\n%s", probe.name, out)
			}
		})
	}
}
