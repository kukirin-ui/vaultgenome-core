// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistry_CounterRendersZeroUnlabeled(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.NewCounter("rp_test_unused", "Unused counter")
	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	// Zero-cell counters emit only HELP + TYPE until Inc/Add lights
	// up a cell. This matches client_golang semantics.
	require.Contains(t, buf.String(), "# HELP rp_test_unused Unused counter")
	require.Contains(t, buf.String(), "# TYPE rp_test_unused counter")
	require.NotContains(t, buf.String(), "\nrp_test_unused ")
}

func TestRegistry_CounterInc_Unlabeled(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	c := r.NewCounter("rp_test_count", "counter helper")
	c.Inc()
	c.Add(4)
	require.Equal(t, uint64(5), c.Value())

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	require.Contains(t, buf.String(), "rp_test_count 5\n")
}

func TestRegistry_CounterLabels_DeterministicSerialisation(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	c := r.NewCounter("rp_test_labelled", "labels exercise")

	// Two different cells addressed by labels. Also exercise that the
	// label serialiser sorts by name so the key is canonical regardless
	// of call-site order.
	c.Inc(Label{Name: "outcome", Value: "success"}, Label{Name: "phase", Value: "handshake"})
	c.Inc(Label{Name: "phase", Value: "handshake"}, Label{Name: "outcome", Value: "success"})
	c.Inc(Label{Name: "outcome", Value: "fail"}, Label{Name: "phase", Value: "handshake"})

	// Canonical form merges the two identical-order-ignoring calls.
	require.Equal(t, uint64(2), c.Value(
		Label{Name: "phase", Value: "handshake"},
		Label{Name: "outcome", Value: "success"}))
	require.Equal(t, uint64(1), c.Value(
		Label{Name: "outcome", Value: "fail"},
		Label{Name: "phase", Value: "handshake"}))

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	// Labels must be emitted in sorted order (outcome before phase):
	require.Contains(t, out, `rp_test_labelled{outcome="success",phase="handshake"} 2`)
	require.Contains(t, out, `rp_test_labelled{outcome="fail",phase="handshake"} 1`)
}

func TestRegistry_LabelEscaping(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	c := r.NewCounter("rp_test_escape", "escape exercise")
	c.Inc(Label{Name: "msg", Value: `hi "there"` + "\n" + `\slash`})
	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	// Backslash, double-quote, and newline must be escaped; other
	// characters pass through verbatim.
	require.Contains(t, buf.String(), `rp_test_escape{msg="hi \"there\"\n\\slash"} 1`)
}

func TestRegistry_Gauge_SetValueRendering(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	g := r.NewGauge("rp_test_gauge", "gauge exercise")

	g.Set(1700000000) // integral — must render as "1700000000", no trailing ".0"
	require.Equal(t, float64(1700000000), g.Value())
	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	require.Contains(t, buf.String(), "rp_test_gauge 1700000000\n")

	g.Set(3.14)
	buf.Reset()
	require.NoError(t, r.WriteMetricsTo(&buf))
	require.Contains(t, buf.String(), "rp_test_gauge 3.14\n")
}

func TestRegistry_OrderingIsInsertionOrder(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.NewCounter("rp_c_second", "h2")
	_ = r.NewGauge("rp_a_first", "h1")
	_ = r.NewCounter("rp_b_third", "h3")

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	// Must match the order of registration (not alphabetical), so that
	// tests can assert stable output.
	iC := strings.Index(out, "rp_c_second")
	iA := strings.Index(out, "rp_a_first")
	iB := strings.Index(out, "rp_b_third")
	require.True(t, iC < iA && iA < iB, "order = C,A,B (insertion); got indexes %d,%d,%d", iC, iA, iB)
}

func TestRegistry_DuplicateNamePanics(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.NewCounter("rp_dup", "")
	require.Panics(t, func() { r.NewCounter("rp_dup", "") })
}

func TestCounter_Concurrent(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	c := r.NewCounter("rp_concurrent", "")
	const goroutines = 8
	const per = 10_000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				c.Inc(Label{Name: "k", Value: "v"})
			}
		}()
	}
	wg.Wait()
	require.Equal(t, uint64(goroutines*per), c.Value(Label{Name: "k", Value: "v"}))
}

// ---- Histogram tests -------------------------------------------------------

func TestHistogram_PanicsOnEmptyBuckets(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	require.Panics(t, func() { r.NewHistogram("rp_h", "", nil) })
	require.Panics(t, func() { r.NewHistogram("rp_h", "", []float64{}) })
}

func TestHistogram_PanicsOnNonMonotonicBuckets(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	require.Panics(t, func() { r.NewHistogram("rp_h", "", []float64{1, 0.5, 2}) })
	// Equal boundaries also illegal.
	require.Panics(t, func() { r.NewHistogram("rp_h2", "", []float64{1, 1, 2}) })
}

func TestHistogram_BucketBoundaries(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	h := r.NewHistogram("rp_latency_seconds", "", []float64{0.01, 0.1, 1.0})

	// Five observations spread across buckets:
	//   0.005 → only le=0.01 hits        (counts: [1,1,1,1])
	//   0.05  → le=0.1 and above         (counts: [1,2,2,2])
	//   0.5   → le=1.0 and above         (counts: [1,2,3,3])
	//   1.5   → only +Inf                (counts: [1,2,3,4])
	//   0.001 → all buckets              (counts: [2,3,4,5])
	for _, v := range []float64{0.005, 0.05, 0.5, 1.5, 0.001} {
		h.Observe(v)
	}

	require.Equal(t, uint64(5), h.Count())
	require.InDelta(t, 0.005+0.05+0.5+1.5+0.001, h.Sum(), 1e-9)

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	require.Contains(t, out, `rp_latency_seconds_bucket{le="0.01"} 2`)
	require.Contains(t, out, `rp_latency_seconds_bucket{le="0.1"} 3`)
	require.Contains(t, out, `rp_latency_seconds_bucket{le="1"} 4`)
	require.Contains(t, out, `rp_latency_seconds_bucket{le="+Inf"} 5`)
	require.Contains(t, out, `rp_latency_seconds_count 5`)
	require.Contains(t, out, `# TYPE rp_latency_seconds histogram`)
}

func TestHistogram_PerLabelCells(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	h := r.NewHistogram("rp_per_label", "", []float64{0.01, 0.1})

	h.Observe(0.005, Label{Name: "provider", Value: "aws-nitro"})
	h.Observe(0.05, Label{Name: "provider", Value: "aws-nitro"})
	h.Observe(0.005, Label{Name: "provider", Value: "azure-sgx"})

	require.Equal(t, uint64(2), h.Count(Label{Name: "provider", Value: "aws-nitro"}))
	require.Equal(t, uint64(1), h.Count(Label{Name: "provider", Value: "azure-sgx"}))

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	// le label must be sorted into canonical position alongside provider.
	require.Contains(t, out, `rp_per_label_bucket{le="0.01",provider="aws-nitro"} 1`)
	require.Contains(t, out, `rp_per_label_bucket{le="0.1",provider="aws-nitro"} 2`)
	require.Contains(t, out, `rp_per_label_bucket{le="+Inf",provider="aws-nitro"} 2`)
	require.Contains(t, out, `rp_per_label_bucket{le="0.01",provider="azure-sgx"} 1`)
	require.Contains(t, out, `rp_per_label_count{provider="aws-nitro"} 2`)
}

func TestHistogram_DefaultLatencyBuckets(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	h := r.NewHistogram("rp_default", "", DefaultLatencyBuckets)
	h.Observe(0.0007) // falls into le=0.001 and above
	h.Observe(2.0)    // falls into le=2.5 and +Inf

	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	require.Contains(t, out, `rp_default_bucket{le="+Inf"} 2`)
	require.Contains(t, out, `rp_default_bucket{le="0.001"} 1`)
	require.Contains(t, out, `rp_default_bucket{le="2.5"} 2`)
}

func TestHistogram_ConcurrentObserve(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	h := r.NewHistogram("rp_concurrent_h", "", []float64{0.5, 1.0, 2.0})
	const goroutines = 16
	const per = 1_000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				h.Observe(0.25, Label{Name: "k", Value: "v"})
			}
		}()
	}
	wg.Wait()
	require.Equal(t, uint64(goroutines*per), h.Count(Label{Name: "k", Value: "v"}))
	// 0.25 is below every boundary → all buckets must equal the count.
	require.InDelta(t, float64(goroutines*per)*0.25, h.Sum(Label{Name: "k", Value: "v"}), 1e-6)
}

func TestHistogram_ZeroObservationsRendersHelpTypeOnly(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	_ = r.NewHistogram("rp_zero_h", "Empty histogram", []float64{1.0})
	var buf bytes.Buffer
	require.NoError(t, r.WriteMetricsTo(&buf))
	out := buf.String()
	require.Contains(t, out, "# HELP rp_zero_h Empty histogram")
	require.Contains(t, out, "# TYPE rp_zero_h histogram")
	require.NotContains(t, out, "rp_zero_h_bucket")
	require.NotContains(t, out, "rp_zero_h_count")
}
