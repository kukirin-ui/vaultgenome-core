// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	shared_crypto "github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// fakeConfigfs behaves like the kernel's configfs-tsm for one provider:
// mkdir creates an entry with provider and generation attributes, every
// attribute write bumps generation, and reading outblob returns a report
// built from the entry's inblob.
type fakeConfigfs struct {
	mu         sync.Mutex
	provider   string
	makeReport func(inblob []byte) []byte
	interfere  int // bump generation behind the caller's back on this many outblob reads
	mkdirErr   error

	entries   map[string]*fakeEntry
	created   []string
	removed   []string
	privlevel string
}

type fakeEntry struct {
	generation uint64
	inblob     []byte
}

func newFakeConfigfs(provider string, makeReport func([]byte) []byte) *fakeConfigfs {
	return &fakeConfigfs{provider: provider, makeReport: makeReport, entries: map[string]*fakeEntry{}}
}

func (f *fakeConfigfs) Mkdir(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mkdirErr != nil {
		return f.mkdirErr
	}
	if _, ok := f.entries[path]; ok {
		return os.ErrExist
	}
	f.entries[path] = &fakeEntry{}
	f.created = append(f.created, path)
	return nil
}

func (f *fakeConfigfs) Remove(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, path)
	f.removed = append(f.removed, path)
	return nil
}

func (f *fakeConfigfs) entry(path string) (*fakeEntry, string, error) {
	e, ok := f.entries[filepath.Dir(path)]
	if !ok {
		return nil, "", os.ErrNotExist
	}
	return e, filepath.Base(path), nil
}

func (f *fakeConfigfs) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, attr, err := f.entry(path)
	if err != nil {
		return nil, err
	}
	switch attr {
	case "provider":
		return []byte(f.provider + "\n"), nil
	case "generation":
		return []byte(fmt.Sprintf("%d\n", e.generation)), nil
	case "outblob":
		if f.interfere > 0 {
			f.interfere--
			e.generation++ // another writer touched the entry
		}
		return f.makeReport(e.inblob), nil
	}
	return nil, os.ErrNotExist
}

func (f *fakeConfigfs) WriteFile(path string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, attr, err := f.entry(path)
	if err != nil {
		return err
	}
	switch attr {
	case "inblob":
		e.inblob = append([]byte(nil), data...)
	case "privlevel":
		f.privlevel = string(data)
	default:
		return os.ErrPermission
	}
	e.generation++
	return nil
}

func (f *fakeConfigfs) allRemoved(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Empty(t, f.entries, "report entries left behind: %v", f.entries)
	require.Equal(t, len(f.created), len(f.removed))
}

// echoReport returns a report builder that places inblob in REPORT_DATA of
// a copy of base, the way the firmware answers a request.
func echoReport(base []byte) func([]byte) []byte {
	return func(inblob []byte) []byte {
		r := append([]byte(nil), base...)
		copy(r[sevOffReportData:sevOffReportData+64], inblob)
		return r
	}
}

// genuineReport is a real SEV-SNP report captured on a GCP Confidential VM.
func genuineReport(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(genuineEvidenceDir(t), "report-vaultgenome.bin"))
	require.NoError(t, err)
	return raw
}

// withRealSEVParse serialises with the fake-hardware harness, which swaps
// the package's SEV function variables, and checks the real ones are in place.
func withRealSEVParse(t *testing.T) {
	t.Helper()
	teeFakeMu.Lock()
	t.Cleanup(teeFakeMu.Unlock)
}

// --- configfsTSM ----------------------------------------------------------

func TestConfigfsTSM_ReportAnswersTheRequest(t *testing.T) {
	t.Parallel()
	fs := newFakeConfigfs("sev_guest", func(in []byte) []byte { return append([]byte("report:"), in...) })
	c := configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}
	var rd [64]byte
	copy(rd[:], "caller data")

	raw, err := c.report(rd, 0)
	require.NoError(t, err)
	require.Equal(t, append([]byte("report:"), rd[:]...), raw)
	require.Empty(t, fs.privlevel, "privlevel 0 is the default and is not written")
	fs.allRemoved(t)
}

func TestConfigfsTSM_WritesPrivlevel(t *testing.T) {
	t.Parallel()
	fs := newFakeConfigfs("sev_guest", func(in []byte) []byte { return in })
	_, err := configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}.report([64]byte{1}, 2)
	require.NoError(t, err)
	require.Equal(t, "2", fs.privlevel)
}

// A TDX guest's configfs would sign a different report format; the SEV
// producer refuses to use it rather than hand the verifier garbage.
func TestConfigfsTSM_RefusesAnotherProvider(t *testing.T) {
	t.Parallel()
	fs := newFakeConfigfs("tdx_guest", func(in []byte) []byte { return in })
	_, err := configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}.report([64]byte{1}, 0)
	require.ErrorContains(t, err, `provider is "tdx_guest"`)
	fs.allRemoved(t)
}

// If someone else writes to the entry between our write and our read, the
// report may answer their request, not ours: discard it and retry.
func TestConfigfsTSM_RetriesWhenRaced(t *testing.T) {
	t.Parallel()
	fs := newFakeConfigfs("sev_guest", func(in []byte) []byte { return in })
	fs.interfere = 1
	raw, err := configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}.report([64]byte{7}, 0)
	require.NoError(t, err)
	require.Equal(t, byte(7), raw[0])
	require.Len(t, fs.created, 2, "one discarded attempt, one good")
	fs.allRemoved(t)

	fs = newFakeConfigfs("sev_guest", func(in []byte) []byte { return in })
	fs.interfere = tsmAttempts
	_, err = configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}.report([64]byte{7}, 0)
	require.ErrorContains(t, err, "gave up")
	fs.allRemoved(t)
}

func TestConfigfsTSM_SurfacesFilesystemErrors(t *testing.T) {
	t.Parallel()
	fs := newFakeConfigfs("sev_guest", func(in []byte) []byte { return in })
	fs.mkdirErr = errors.New("no space")
	_, err := configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs}.report([64]byte{}, 0)
	require.ErrorContains(t, err, "create report entry")

	empty := newFakeConfigfs("sev_guest", func([]byte) []byte { return nil })
	_, err = configfsTSM{dir: "/tsm", provider: "sev_guest", fs: empty}.report([64]byte{}, 0)
	require.ErrorContains(t, err, "empty outblob")
}

// --- GCPSEVProducer over configfs-tsm ---------------------------------------

func TestGCPSEVProducer_QuotesThroughConfigfsTSM(t *testing.T) {
	withRealSEVParse(t)
	base := genuineReport(t)
	fs := newFakeConfigfs("sev_guest", echoReport(base))
	p, err := newGCPSEVProducer(GCPSEVProducerConfig{}, configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs})
	require.NoError(t, err)

	// The measurement is the report's whole 48-byte launch measurement.
	require.Equal(t, Measurement(base[sevOffMeasurement:sevOffMeasurement+48]), p.Measurement())

	nonce := bytes.Repeat([]byte{0x5c}, 64) // e.g. an ADR 0009 key-binding challenge
	ev, err := p.Quote(nonce)
	require.NoError(t, err)
	require.Len(t, []byte(ev), sevReportLen)
	report, err := realParseSEVSNPReport(ev)
	require.NoError(t, err)
	require.True(t, nonceMatchesReportDataSEV(report.ReportData, nonce), "REPORT_DATA must bind the challenge")
	want := shared_crypto.SHA256(nonce)
	require.Equal(t, want[:], report.ReportData[:32])
	require.Equal(t, make([]byte, 32), report.ReportData[32:], "the upper half of REPORT_DATA is zero")

	_, err = p.Quote(nonce[:NonceMinBytes-1])
	require.Error(t, err)
	require.NoError(t, p.Close())
	_, err = p.Quote(nonce)
	require.ErrorContains(t, err, "closed")
	fs.allRemoved(t)
}

// A report that does not carry the requested REPORT_DATA does not answer
// this challenge and is refused.
func TestGCPSEVProducer_RefusesReportThatIgnoresTheChallenge(t *testing.T) {
	withRealSEVParse(t)
	base := genuineReport(t)
	fs := newFakeConfigfs("sev_guest", func([]byte) []byte { return base })
	_, err := newGCPSEVProducer(GCPSEVProducerConfig{}, configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs})
	require.ErrorContains(t, err, "does not carry the requested REPORT_DATA")
}

// The launch measurement cannot change under a running producer.
func TestGCPSEVProducer_RefusesChangedMeasurement(t *testing.T) {
	withRealSEVParse(t)
	base := genuineReport(t)
	calls := 0
	fs := newFakeConfigfs("sev_guest", func(in []byte) []byte {
		r := echoReport(base)(in)
		calls++
		if calls > 1 {
			r[sevOffMeasurement] ^= 0xff
		}
		return r
	})
	p, err := newGCPSEVProducer(GCPSEVProducerConfig{}, configfsTSM{dir: "/tsm", provider: "sev_guest", fs: fs})
	require.NoError(t, err)
	_, err = p.Quote(bytes.Repeat([]byte{1}, NonceMinBytes))
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity))
}

func TestGCPSEVProducer_RequiresConfigfsTSM(t *testing.T) {
	t.Parallel()
	_, err := NewGCPSEVProducer(GCPSEVProducerConfig{TSMReportDir: filepath.Join(t.TempDir(), "absent")})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "Confidential VM"), "error should tell the operator why: %v", err)
}
