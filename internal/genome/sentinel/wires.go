// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package sentinel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A Wire is a tripwire: armed once, then checked every tick. A wire that
// fires means the machine can no longer be trusted with the state it holds.
type Wire interface {
	// Arm records the wire's baseline. A wire that cannot be armed — a path
	// that is missing, a probe that does not pass — is an error: the
	// sentinel does not start with a wire it cannot trust.
	Arm() error
	// Check reports the trip, or nil while the wire is intact.
	Check() *Trip
}

// PathWire fires when anything about a file or directory tree changes:
// content, mode, a symlink's target, an entry added or removed, the path
// itself removed. Canary files, credentials no process should touch, the
// sentinel's own binary, a directory an intruder would drop tools into.
type PathWire struct {
	Path     string
	baseline string
}

func (w *PathWire) Arm() error {
	d, err := pathDigest(w.Path)
	if err != nil {
		return fmt.Errorf("sentinel: tripwire %s: %w", w.Path, err)
	}
	w.baseline = d
	return nil
}

func (w *PathWire) Check() *Trip {
	d, err := pathDigest(w.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &Trip{Wire: "path", Target: w.Path, Want: w.baseline, Got: "missing"}
	case err != nil:
		return &Trip{Wire: "path", Target: w.Path, Want: w.baseline, Got: "unreadable", Detail: err.Error()}
	case d != w.baseline:
		return &Trip{Wire: "path", Target: w.Path, Want: w.baseline, Got: d}
	}
	return nil
}

// pathDigest hashes what a path is: for a file its mode and content, for a
// symlink its target, for a directory every entry beneath it (relative
// path, type, mode, size and content digest), sorted.
func pathDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		line, err := entryLine(path, ".", info)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(line))
		return hex.EncodeToString(sum[:]), nil
	}
	var lines []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(path, p)
		if err != nil {
			return err
		}
		line, err := entryLine(p, filepath.ToSlash(rel), info)
		if err != nil {
			return err
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func entryLine(path, rel string, info fs.FileInfo) (string, error) {
	mode := info.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s\x00link\x00%s\n", rel, target), nil
	case mode.IsRegular():
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s\x00file\x00%o\x00%d\x00%x\n", rel, mode.Perm(), n, h.Sum(nil)), nil
	default:
		return fmt.Sprintf("%s\x00%s\x00%o\n", rel, mode.Type(), mode.Perm()), nil
	}
}

// ProbeWire fires when a command stops passing: a file-integrity checker,
// a process or port check, a re-attestation, anything that exits 0 while
// the machine is as it should be. A probe that cannot run, or runs past
// its timeout, fires too.
type ProbeWire struct {
	Argv    []string
	Timeout time.Duration
}

// probeOutputLimit bounds how much of a probe's output a report keeps.
const probeOutputLimit = 512

func (w *ProbeWire) Arm() error {
	if len(w.Argv) == 0 {
		return errors.New("sentinel: empty probe")
	}
	if t := w.Check(); t != nil {
		return fmt.Errorf("sentinel: probe %q does not pass before the sentinel starts (%s): %s", strings.Join(w.Argv, " "), t.Got, t.Detail)
	}
	return nil
}

func (w *ProbeWire) Check() *Trip {
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.Argv[0], w.Argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if err == nil {
		return nil
	}
	got := "error"
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		got = "timeout after " + timeout.String()
	case errors.As(err, &exit):
		got = fmt.Sprintf("exit %d", exit.ExitCode())
	}
	detail := strings.TrimSpace(out.String())
	if detail == "" {
		detail = err.Error()
	}
	if len(detail) > probeOutputLimit {
		detail = detail[:probeOutputLimit]
	}
	return &Trip{Wire: "probe", Target: strings.Join(w.Argv, " "), Got: got, Detail: detail}
}
