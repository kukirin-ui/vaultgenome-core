// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// budgetWriter accepts the first n writes and refuses every later one,
// so a test can place an io failure on any single line of the exposition.
type budgetWriter struct {
	buf   bytes.Buffer
	left  int
	fault error
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if w.left == 0 {
		return 0, w.fault
	}
	w.left--
	return w.buf.Write(p)
}

// fullRegistry registers one metric of each kind with one cell each, so
// the exposition has every line shape: HELP and TYPE blocks, a counter
// line, a gauge line, bucket lines, the +Inf bucket, sum and count.
func fullRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	c := r.NewCounter("vg_requests_total", "requests")
	c.Add(3, Label{"outcome", "ok"})
	g := r.NewGauge("vg_up", "up")
	g.Set(1)
	h := r.NewHistogram("vg_latency_seconds", "latency", []float64{0.1, 1})
	h.Observe(0.5, Label{"op", "seal"})
	return r
}

// TestWriteMetricsTo_SurfacesWriteErrorOnEveryLine proves that an io
// error on any line of the exposition is returned verbatim, from the
// HELP/TYPE blocks through every counter, gauge and histogram line, and
// that what reached the writer before the fault is exactly the prefix of
// the full rendering — nothing is reordered or retried.
func TestWriteMetricsTo_SurfacesWriteErrorOnEveryLine(t *testing.T) {
	t.Parallel()
	var full bytes.Buffer
	require.NoError(t, fullRegistry(t).WriteMetricsTo(&full))
	lines := strings.Split(strings.TrimSuffix(full.String(), "\n"), "\n")
	require.Len(t, lines, 13, "one write per line:\n%s", full.String())

	fault := errors.New("socket closed")
	for n := range lines {
		t.Run(lines[n], func(t *testing.T) {
			t.Parallel()
			w := &budgetWriter{left: n, fault: fault}
			err := fullRegistry(t).WriteMetricsTo(w)
			require.ErrorIs(t, err, fault)
			want := ""
			if n > 0 {
				want = strings.Join(lines[:n], "\n") + "\n"
			}
			require.Equal(t, want, w.buf.String())
		})
	}
}

// TestCells_UnknownLabelSetReadsZero proves that reading a cell that was
// never written returns zero without creating it: the exposition stays
// free of cells that only a read touched.
func TestCells_UnknownLabelSetReadsZero(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	c := r.NewCounter("vg_c", "c")
	h := r.NewHistogram("vg_h", "h", []float64{1})
	c.Inc(Label{"outcome", "ok"})
	h.Observe(2, Label{"op", "seal"})

	require.Zero(t, c.Value(Label{"outcome", "missing"}))
	require.Zero(t, c.Value())
	require.Zero(t, h.Count(Label{"op", "missing"}))
	require.Zero(t, h.Sum(Label{"op", "missing"}))
	require.Zero(t, h.Count())
	require.Zero(t, h.Sum())

	require.Equal(t, uint64(1), c.Value(Label{"outcome", "ok"}))
	require.Equal(t, uint64(1), h.Count(Label{"op", "seal"}))
	require.Equal(t, 2.0, h.Sum(Label{"op", "seal"}))

	var out bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&out))
	require.NotContains(t, out.String(), "missing")
	require.Equal(t, 1, strings.Count(out.String(), "vg_c{"), "only the written counter cell is exposed")
	require.Equal(t, 1, strings.Count(out.String(), "vg_h_count"), "only the written histogram cell is exposed")
}

// TestInjectLELabel_SortsIntoPlace proves the `le` label lands in sorted
// position among existing labels, and pins labelName on a field that has
// no '=' so a malformed part sorts by its whole text instead of faulting.
func TestInjectLELabel_SortsIntoPlace(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                         `{le="0.5"}`,
		`{op="seal"}`:              `{le="0.5",op="seal"}`,
		`{a="x"}`:                  `{a="x",le="0.5"}`,
		`{a="x",op="seal",z="1"}`:  `{a="x",le="0.5",op="seal",z="1"}`,
		`{a="x",outcome="ok=yes"}`: `{a="x",le="0.5",outcome="ok=yes"}`,
	}
	for base, want := range cases {
		require.Equal(t, want, injectLELabel(base, "0.5"), "base %q", base)
	}
	require.Equal(t, "op", labelName(`op="seal"`))
	require.Equal(t, "plain", labelName("plain"))
	require.Equal(t, `="x"`, labelName(`="x"`), "a field with no name sorts by its whole text")
}

// TestFormatFloat_Table pins the exposition's number rendering: integral
// values print as integers, everything else shortest round-trip.
func TestFormatFloat_Table(t *testing.T) {
	t.Parallel()
	cases := map[float64]string{
		0:       "0",
		1:       "1",
		-3:      "-3",
		0.5:     "0.5",
		0.0005:  "0.0005",
		1e15:    "1000000000000000",
		1e16:    "1e+16",
		-1e15:   "-1000000000000000",
		-1e16:   "-1e+16",
		2.5e-07: "2.5e-07",
	}
	for v, want := range cases {
		require.Equal(t, want, formatFloat(v), "v=%g", v)
	}
}
