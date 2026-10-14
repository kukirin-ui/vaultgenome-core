// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package buildinfo

import (
	"runtime/debug"
	"testing"
)

func info(mainVersion string, settings map[string]string) *debug.BuildInfo {
	bi := &debug.BuildInfo{}
	bi.Main.Version = mainVersion
	for k, v := range settings {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	return bi
}

func TestResolveFrom(t *testing.T) {
	const sha = "14067f755402abcd"

	cases := []struct {
		name               string
		stampedV, stampedC string
		info               *debug.BuildInfo
		wantV, wantC       string
	}{
		{
			name:     "stamped values always win",
			stampedV: "v0.3.1", stampedC: "e835288",
			info:  info("v9.9.9", map[string]string{"vcs.revision": sha}),
			wantV: "v0.3.1", wantC: "e835288",
		},
		{
			name:     "go install of a tag: version and revision are recovered",
			stampedV: placeholderVersion, stampedC: placeholderCommit,
			info:  info("v0.3.2", map[string]string{"vcs.revision": sha}),
			wantV: "v0.3.2", wantC: "14067f755402",
		},
		{
			name:     "a dirty tree is marked, not hidden",
			stampedV: placeholderVersion, stampedC: placeholderCommit,
			info:  info("(devel)", map[string]string{"vcs.revision": sha, "vcs.modified": "true"}),
			wantV: placeholderVersion, wantC: "14067f755402-dirty",
		},
		{
			name:     "a pseudo-version is not surfaced as a release",
			stampedV: placeholderVersion, stampedC: placeholderCommit,
			info:  info("v0.3.2-0.20260917192257-14067f755402", map[string]string{"vcs.revision": sha}),
			wantV: placeholderVersion, wantC: "14067f755402",
		},
		{
			name:     "no VCS in the build context (the Docker case): placeholders survive",
			stampedV: placeholderVersion, stampedC: placeholderCommit,
			info:  info("(devel)", nil),
			wantV: placeholderVersion, wantC: placeholderCommit,
		},
		{
			name:     "a short revision is not truncated",
			stampedV: placeholderVersion, stampedC: placeholderCommit,
			info:  info("(devel)", map[string]string{"vcs.revision": "abc123"}),
			wantV: placeholderVersion, wantC: "abc123",
		},
		{
			name:     "empty stamps behave like placeholders",
			stampedV: "", stampedC: "",
			info:  info("v1.0.0", map[string]string{"vcs.revision": sha}),
			wantV: "v1.0.0", wantC: "14067f755402",
		},
		{
			name:     "nil build info changes nothing",
			stampedV: placeholderVersion, stampedC: placeholderCommit,
			info:  nil,
			wantV: placeholderVersion, wantC: placeholderCommit,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, cm := resolveFrom(c.stampedV, c.stampedC, c.info)
			if v != c.wantV || cm != c.wantC {
				t.Fatalf("resolveFrom() = (%q, %q), want (%q, %q)", v, cm, c.wantV, c.wantC)
			}
		})
	}
}

func TestIsReleaseVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.3.2":                               true,
		"v1.0.0":                               true,
		"v10.20.30":                            true,
		"":                                     false,
		"v":                                    false,
		"(devel)":                              false,
		"0.3.2":                                false,
		"v0.3.2-0.20260917192257-14067f755402": false,
		"v2.0.0+incompatible":                  false,
	} {
		if got := isReleaseVersion(v); got != want {
			t.Errorf("isReleaseVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

// Resolve reads this test binary's own build info; it must never panic and
// never return an empty string, whatever the environment it runs in.
func TestResolve_OnThisBinary(t *testing.T) {
	v, c := Resolve(placeholderVersion, placeholderCommit)
	if v == "" || c == "" {
		t.Fatalf("Resolve returned an empty field: (%q, %q)", v, c)
	}
	if v == "(devel)" {
		t.Fatalf("(devel) must never be surfaced as a version")
	}
}
