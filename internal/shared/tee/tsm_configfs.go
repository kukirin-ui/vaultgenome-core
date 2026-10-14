// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

// Linux configfs-tsm: the kernel's vendor-neutral interface for
// requesting a confidential-computing attestation report (Linux ≥ 6.7,
// CONFIG_TSM_REPORTS). A report is requested by creating a directory
// under /sys/kernel/config/tsm/report, writing up to 64 bytes of
// caller data to its `inblob`, and reading the signed report from
// `outblob`; `provider` names the backend (sev_guest, tdx_guest) and
// `generation` counts writes, so a caller can tell whether anyone else
// wrote to the entry between its write and its read. It needs no ioctl
// numbers, no cgo and no third-party module — only file I/O.
//
// See Documentation/ABI/testing/configfs-tsm in the kernel tree.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// DefaultTSMReportDir is where the kernel exposes configfs-tsm reports.
const DefaultTSMReportDir = "/sys/kernel/config/tsm/report"

// tsmFS is the file-system surface configfs-tsm needs. The real one is
// the OS; tests substitute a fake that behaves like the kernel's
// configfs (attribute files appear on mkdir, writes bump generation).
type tsmFS interface {
	Mkdir(path string) error
	Remove(path string) error
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
}

type osTSMFS struct{}

func (osTSMFS) Mkdir(path string) error              { return os.Mkdir(path, 0o700) }
func (osTSMFS) Remove(path string) error             { return os.Remove(path) }
func (osTSMFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile writes data in one write(2) to an existing configfs
// attribute; configfs binary attributes take their value on close.
func (osTSMFS) WriteFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// tsmReporter requests attestation reports carrying caller data.
type tsmReporter interface {
	report(reportData [64]byte, privlevel uint32) ([]byte, error)
}

// configfsTSM requests reports through a configfs-tsm directory.
type configfsTSM struct {
	dir      string // e.g. DefaultTSMReportDir
	provider string // the backend this reporter insists on, e.g. "sev_guest"
	fs       tsmFS
}

// tsmEntrySeq makes every report entry this process creates unique.
var tsmEntrySeq atomic.Uint64

// tsmAttempts bounds retries when another writer races us on an entry.
const tsmAttempts = 3

// report returns the raw report whose caller-data field is reportData.
func (c configfsTSM) report(reportData [64]byte, privlevel uint32) ([]byte, error) {
	var last error
	for attempt := 0; attempt < tsmAttempts; attempt++ {
		raw, raced, err := c.reportOnce(reportData, privlevel)
		if err == nil {
			return raw, nil
		}
		if !raced {
			return nil, err
		}
		last = err
	}
	return nil, fmt.Errorf("configfs-tsm: gave up after %d attempts: %w", tsmAttempts, last)
}

// reportOnce creates a fresh entry, requests one report and removes the
// entry again. raced reports whether the entry's generation moved by
// more than our own write — someone else wrote to it, so the report may
// not answer our request and must be discarded.
func (c configfsTSM) reportOnce(reportData [64]byte, privlevel uint32) (raw []byte, raced bool, err error) {
	entry := filepath.Join(c.dir, fmt.Sprintf("acp-%d-%d", os.Getpid(), tsmEntrySeq.Add(1)))
	if err := c.fs.Mkdir(entry); err != nil {
		return nil, false, fmt.Errorf("configfs-tsm: create report entry %s: %w", entry, err)
	}
	defer func() { _ = c.fs.Remove(entry) }()

	provider, err := c.fs.ReadFile(filepath.Join(entry, "provider"))
	if err != nil {
		return nil, false, fmt.Errorf("configfs-tsm: read provider: %w", err)
	}
	if got := strings.TrimSpace(string(provider)); got != c.provider {
		return nil, false, fmt.Errorf("configfs-tsm: provider is %q, this producer needs %q", got, c.provider)
	}
	if privlevel != 0 {
		if err := c.fs.WriteFile(filepath.Join(entry, "privlevel"), []byte(strconv.FormatUint(uint64(privlevel), 10))); err != nil {
			return nil, false, fmt.Errorf("configfs-tsm: set privlevel %d: %w", privlevel, err)
		}
	}

	before, err := c.generation(entry)
	if err != nil {
		return nil, false, err
	}
	if err := c.fs.WriteFile(filepath.Join(entry, "inblob"), reportData[:]); err != nil {
		return nil, false, fmt.Errorf("configfs-tsm: write inblob: %w", err)
	}
	raw, err = c.fs.ReadFile(filepath.Join(entry, "outblob"))
	if err != nil {
		return nil, false, fmt.Errorf("configfs-tsm: read outblob: %w", err)
	}
	after, err := c.generation(entry)
	if err != nil {
		return nil, false, err
	}
	if after != before+1 {
		return nil, true, fmt.Errorf("configfs-tsm: entry generation moved %d -> %d across one write", before, after)
	}
	if len(raw) == 0 {
		return nil, false, errors.New("configfs-tsm: empty outblob")
	}
	return raw, false, nil
}

func (c configfsTSM) generation(entry string) (uint64, error) {
	b, err := c.fs.ReadFile(filepath.Join(entry, "generation"))
	if err != nil {
		return 0, fmt.Errorf("configfs-tsm: read generation: %w", err)
	}
	g, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("configfs-tsm: generation %q: %w", strings.TrimSpace(string(b)), err)
	}
	return g, nil
}
