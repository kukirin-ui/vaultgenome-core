// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package buildinfo answers "which build is this?" for a binary that was not
// built by this repository's Makefile.
//
// The Makefile stamps -X main.version / -X main.commit, so `make build` and the
// release workflow produce binaries that know what they are. One path a reader
// is explicitly invited to take does not go through the Makefile:
//
//	go install github.com/vault-genome/vaultgenome-core/cmd/acpctl@v0.3.2
//
// That printed "acpctl 0.0.0-dev (commit none)", an unhelpful answer from a
// project whose claim is that you can tell what you are running. Go records the
// module version and the VCS revision in the binary itself, so when the ldflags
// are absent we read those instead.
//
// The image built from this repository's Dockerfile is a third case: its build
// context excludes .git, so Go can embed no revision there. That one is solved
// in the Dockerfile, by passing VERSION and COMMIT as build arguments.
package buildinfo

import "runtime/debug"

const (
	placeholderVersion = "0.0.0-dev"
	placeholderCommit  = "none"

	// revisionDisplayLen matches the short SHA the Makefile stamps.
	revisionDisplayLen = 12
)

// Resolve returns the version and commit a binary should print, reading this
// binary's own embedded build information.
func Resolve(stampedVersion, stampedCommit string) (version, commit string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return stampedVersion, stampedCommit
	}
	return resolveFrom(stampedVersion, stampedCommit, info)
}

// resolveFrom is Resolve's decision, separated from the global read so that
// every branch can be exercised with a constructed *debug.BuildInfo.
// Values stamped by the Makefile always win.
func resolveFrom(stampedVersion, stampedCommit string, info *debug.BuildInfo) (version, commit string) {
	version, commit = stampedVersion, stampedCommit
	if info == nil {
		return version, commit
	}

	if version == "" || version == placeholderVersion {
		// Adopt only a real tagged module version. Go otherwise reports
		// "(devel)" for a working-tree build, or a pseudo-version such as
		// v0.3.2-0.20260917192257-14067f755402 for a commit after the last tag;
		// neither tells a reader more than the placeholder, and surfacing a
		// pseudo-version would change what `make build` has always printed.
		if v := info.Main.Version; isReleaseVersion(v) {
			version = v
		}
	}

	if commit == "" || commit == placeholderCommit {
		if rev := revisionOf(info); rev != "" {
			commit = rev
		}
	}

	return version, commit
}

// revisionOf returns the VCS revision Go embedded, shortened, and marked when
// the working tree was dirty at build time. It returns "" when the binary
// carries no revision, which is the case whenever .git was outside the build
// context.
func revisionOf(info *debug.BuildInfo) string {
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return ""
	}
	if len(revision) > revisionDisplayLen {
		revision = revision[:revisionDisplayLen]
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return revision
}

// isReleaseVersion reports whether v is a plain tagged version like "v0.3.2"
// rather than "(devel)", a pseudo-version, or build metadata such as
// "+incompatible".
func isReleaseVersion(v string) bool {
	if len(v) < 2 || v[0] != 'v' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] == '-' || v[i] == '+' {
			return false
		}
	}
	return true
}
