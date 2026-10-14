// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// AMD KDS answers bursts with HTTP 429. The verifier waits it out a few
// times (honouring Retry-After) and then fails closed.
func TestHTTPGet_WaitsOutKDSRateLimiting(t *testing.T) {
	withRealSEVParse(t) // serialises with tests that swap package vars
	var waits []time.Duration
	origSleep := kdsSleep
	kdsSleep = func(d time.Duration) { waits = append(waits, d) }
	t.Cleanup(func() { kdsSleep = origSleep })

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("vcek-der"))
	}))
	defer srv.Close()

	body, err := httpGet(srv.URL)
	require.NoError(t, err)
	require.Equal(t, "vcek-der", string(body))
	require.Equal(t, []time.Duration{3 * time.Second, 3 * time.Second}, waits)

	// Still limited after every attempt: fail closed, naming the status.
	waits = nil
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer limited.Close()
	_, err = httpGet(limited.URL)
	require.ErrorContains(t, err, "HTTP 429")
	require.Len(t, waits, kdsAttempts-1)

	// Other failures are not retried.
	waits = nil
	missing := httptest.NewServer(http.NotFoundHandler())
	defer missing.Close()
	_, err = httpGet(missing.URL)
	require.ErrorContains(t, err, "HTTP 404")
	require.Empty(t, waits)
}

func TestKDSBackoff(t *testing.T) {
	t.Parallel()
	require.Equal(t, 2*time.Second, kdsBackoff(1, ""))
	require.Equal(t, 4*time.Second, kdsBackoff(2, "soon"))
	require.Equal(t, 7*time.Second, kdsBackoff(1, "7"))
	require.Equal(t, kdsMaxWait, kdsBackoff(1, "3600"))
	require.Equal(t, kdsMaxWait, kdsBackoff(10, ""))
}

// A one-shot verifier (a fresh process per restore) asks KDS once per chip
// and TCB; later runs read the certificate back from VCEKCacheDir.
func TestFetchVCEK_DiskCacheSparesKDS(t *testing.T) {
	withRealSEVParse(t)
	var fetches atomic.Int32
	orig := amdKDSGetVCEK
	amdKDSGetVCEK = func(string, [64]byte, uint64) ([]byte, error) {
		fetches.Add(1)
		return []byte("vcek-der-bytes"), nil
	}
	t.Cleanup(func() { amdKDSGetVCEK = orig })

	dir := filepath.Join(t.TempDir(), "vcek")
	chip := [64]byte{0xAB, 0xCD}
	newVerifier := func() *GCPSEVVerifier {
		v, err := NewGCPSEVVerifier(nil, make(Measurement, 48), GCPSEVVerifierConfig{VCEKCacheDir: dir})
		require.NoError(t, err)
		return v
	}

	got, err := newVerifier().fetchVCEK(chip, 42)
	require.NoError(t, err)
	require.Equal(t, "vcek-der-bytes", string(got))
	require.EqualValues(t, 1, fetches.Load())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "one certificate file, no temporary leftovers")

	got, err = newVerifier().fetchVCEK(chip, 42) // "the next process"
	require.NoError(t, err)
	require.Equal(t, "vcek-der-bytes", string(got))
	require.EqualValues(t, 1, fetches.Load(), "the cached certificate was used")

	_, err = newVerifier().fetchVCEK(chip, 43) // another TCB is another certificate
	require.NoError(t, err)
	require.EqualValues(t, 2, fetches.Load())
}
