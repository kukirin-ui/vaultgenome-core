// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// A job's error view carries the classification of what failed it, and
// nothing when nothing did.
func TestNewJobError(t *testing.T) {
	require.Equal(t, JobError{}, newJobError(nil))
	got := newJobError(shared_errors.Operational(CodeReleaseRefused, "release refused: validation FAIL", nil))
	require.Equal(t, JobError{Category: "operational", Code: CodeReleaseRefused, Message: "operational[release_refused]: release refused: validation FAIL"}, got)
}
