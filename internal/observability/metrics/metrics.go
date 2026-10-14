// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds every metric a daemon exposes. All methods are safe
// for concurrent use.
type Registry struct {
	mu sync.RWMutex
	// Insertion-ordered list of metric names so the /metrics endpoint
	// renders deterministically in tests.
	order []string
	items map[string]metric
}

// metric is the internal interface every registered metric satisfies.
// It is unexported; callers manipulate typed wrappers (*Counter, *Gauge).
type metric interface {
	help() string
	kind() string
	// write appends this metric's text-format lines to w, prefixed by
	// the shared HELP/TYPE block emitted by the registry.
	write(w io.Writer, name string) error
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{items: make(map[string]metric)}
}

// NewCounter registers a counter with name + help. A duplicate name
// panics — this is a programmer error caught at startup, not a runtime
// condition.
func (r *Registry) NewCounter(name, help string) *Counter {
	c := &Counter{helpText: help, labelSets: map[string]*uint64{}, labelOrder: []string{}}
	r.register(name, c)
	return c
}

// NewGauge registers a gauge with name + help.
func (r *Registry) NewGauge(name, help string) *Gauge {
	g := &Gauge{helpText: help}
	r.register(name, g)
	return g
}

// NewHistogram registers a histogram with name, help, and a strictly
// increasing list of upper bucket boundaries (the Prometheus `le` label
// values). The implicit `+Inf` bucket is always appended internally.
//
// Empty `buckets` panics — pick boundaries explicitly so the metric's
// resolution is intentional, not a default that may be wrong for the
// workload. For TEE attestation latencies the
// [DefaultLatencyBuckets] preset is a sensible default.
func (r *Registry) NewHistogram(name, help string, buckets []float64) *Histogram {
	if len(buckets) == 0 {
		panic("observability/metrics: NewHistogram requires non-empty buckets")
	}
	for i := 1; i < len(buckets); i++ {
		if buckets[i] <= buckets[i-1] {
			panic(fmt.Sprintf("observability/metrics: histogram buckets must be strictly increasing; got %v at index %d", buckets, i))
		}
	}
	bcopy := make([]float64, len(buckets))
	copy(bcopy, buckets)
	h := &Histogram{
		helpText:   help,
		boundaries: bcopy,
		labelSets:  map[string]*histCells{},
	}
	r.register(name, h)
	return h
}

func (r *Registry) register(name string, m metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.items[name]; dup {
		panic(fmt.Sprintf("observability/metrics: metric %q registered twice", name))
	}
	r.items[name] = m
	r.order = append(r.order, name)
}

// WriteTo emits the Prometheus text format for every registered metric,
// in registration order. Returns any underlying io error verbatim.
func (r *Registry) WriteMetricsTo(w io.Writer) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, name := range r.order {
		m := r.items[name]
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n", name, m.help()); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "# TYPE %s %s\n", name, m.kind()); err != nil {
			return err
		}
		if err := m.write(w, name); err != nil {
			return err
		}
	}
	return nil
}

// ---- Counter --------------------------------------------------------------

// Counter is a monotonically increasing integer metric with optional
// single-label cardinality (label name is encoded in the label key of
// Inc/Add calls).
type Counter struct {
	helpText string

	mu         sync.Mutex
	labelOrder []string           // deterministic emission order
	labelSets  map[string]*uint64 // key = serialised label set, value = counter cell
}

func (c *Counter) help() string { return c.helpText }
func (c *Counter) kind() string { return "counter" }

// Inc is shorthand for Add(1, labels...).
func (c *Counter) Inc(labels ...Label) {
	c.Add(1, labels...)
}

// Add atomically increases the counter cell identified by labels by n.
// A nil/empty labels list writes to the unlabeled cell.
func (c *Counter) Add(n uint64, labels ...Label) {
	key := serialiseLabels(labels)
	c.mu.Lock()
	cell, ok := c.labelSets[key]
	if !ok {
		v := uint64(0)
		cell = &v
		c.labelSets[key] = cell
		c.labelOrder = append(c.labelOrder, key)
	}
	c.mu.Unlock()
	atomic.AddUint64(cell, n)
}

// Value returns the current value of the cell identified by labels.
func (c *Counter) Value(labels ...Label) uint64 {
	key := serialiseLabels(labels)
	c.mu.Lock()
	cell, ok := c.labelSets[key]
	c.mu.Unlock()
	if !ok {
		return 0
	}
	return atomic.LoadUint64(cell)
}

func (c *Counter) write(w io.Writer, name string) error {
	c.mu.Lock()
	keys := make([]string, len(c.labelOrder))
	copy(keys, c.labelOrder)
	c.mu.Unlock()

	for _, key := range keys {
		c.mu.Lock()
		cell := c.labelSets[key]
		c.mu.Unlock()
		v := atomic.LoadUint64(cell)
		if _, err := fmt.Fprintf(w, "%s%s %d\n", name, key, v); err != nil {
			return err
		}
	}
	return nil
}

// ---- Gauge ----------------------------------------------------------------

// Gauge is a single-cell, unlabeled floating-point metric. Sufficient
// for the daemon uptime / last-success-timestamp signals we need at
// Phase 1. If a future daemon needs labelled gauges, extend this type
// rather than introducing a parallel Histogram family.
type Gauge struct {
	helpText string
	// value holds the IEEE-754 bits of the float64 value, so that
	// atomic.Store/LoadUint64 gives us lock-free 64-bit reads/writes
	// without importing sync/atomic's Value type (which boxes).
	value atomic.Uint64
}

func (g *Gauge) help() string { return g.helpText }
func (g *Gauge) kind() string { return "gauge" }

// Set writes v into the gauge atomically.
func (g *Gauge) Set(v float64) {
	g.value.Store(float64bits(v))
}

// Value returns the current gauge value.
func (g *Gauge) Value() float64 {
	return bitsToFloat64(g.value.Load())
}

func (g *Gauge) write(w io.Writer, name string) error {
	v := g.Value()
	_, err := fmt.Fprintf(w, "%s %s\n", name, formatFloat(v))
	return err
}

// ---- Histogram ------------------------------------------------------------

// DefaultLatencyBuckets is a 12-bucket layout that covers the typical
// latency range for TEE attestation, sealing, and validation operations
// (sub-millisecond hardware fast paths up through multi-second cloud
// round-trips for MAA / AWS KMS).
//
// Tune per-metric only when you know why — too many buckets explodes
// label cardinality, too few hides the regression you wanted to see.
var DefaultLatencyBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
}

// Histogram is a bucketed observation distribution with optional label
// cardinality. Each label set owns a private set of bucket counters +
// running sum + observation count. Buckets are CUMULATIVE in the
// Prometheus sense: bucket `le=0.01` includes everything `≤ 0.01`,
// not just the 0.005..0.01 slice.
//
// All operations are concurrency-safe; observations on the hot path
// take the histogram's RLock + an atomic per-bucket increment.
type Histogram struct {
	helpText string
	// boundaries is sorted ascending; the implicit +Inf bucket is at
	// index len(boundaries) within the per-cell counts slice.
	boundaries []float64

	mu         sync.RWMutex
	labelOrder []string              // insertion-deterministic emission order
	labelSets  map[string]*histCells // key = serialised label set
}

// histCells holds per-label-set state. counts has len(boundaries)+1
// entries; the trailing entry is the +Inf bucket. sumBits stores the
// running sum as math.Float64bits so atomic.Add via CAS works.
type histCells struct {
	counts  []uint64      // cumulative bucket counts, one per le boundary + +Inf
	count   atomic.Uint64 // total observation count
	sumBits atomic.Uint64 // running sum (float64 → uint64 bits via math.Float64)
}

func (h *Histogram) help() string { return h.helpText }
func (h *Histogram) kind() string { return "histogram" }

// Observe records a single value into the cell identified by labels.
func (h *Histogram) Observe(v float64, labels ...Label) {
	key := serialiseLabels(labels)
	h.mu.RLock()
	cells, ok := h.labelSets[key]
	h.mu.RUnlock()
	if !ok {
		h.mu.Lock()
		// Re-check under write lock; another goroutine may have allocated.
		if cells, ok = h.labelSets[key]; !ok {
			cells = &histCells{counts: make([]uint64, len(h.boundaries)+1)}
			h.labelSets[key] = cells
			h.labelOrder = append(h.labelOrder, key)
		}
		h.mu.Unlock()
	}

	cells.count.Add(1)
	addToFloatBits(&cells.sumBits, v)

	// Increment the +Inf bucket (always) plus every bucket whose `le`
	// boundary is ≥ v. Bucket counters are uint64; one observation
	// corresponds to a +1 across every applicable bucket.
	atomic.AddUint64(&cells.counts[len(h.boundaries)], 1)
	for i, b := range h.boundaries {
		if v <= b {
			atomic.AddUint64(&cells.counts[i], 1)
		}
	}
}

// Count returns the total number of observations for the cell.
func (h *Histogram) Count(labels ...Label) uint64 {
	key := serialiseLabels(labels)
	h.mu.RLock()
	cells, ok := h.labelSets[key]
	h.mu.RUnlock()
	if !ok {
		return 0
	}
	return cells.count.Load()
}

// Sum returns the running sum of observed values for the cell.
func (h *Histogram) Sum(labels ...Label) float64 {
	key := serialiseLabels(labels)
	h.mu.RLock()
	cells, ok := h.labelSets[key]
	h.mu.RUnlock()
	if !ok {
		return 0
	}
	return bitsToFloat64(cells.sumBits.Load())
}

func (h *Histogram) write(w io.Writer, name string) error {
	h.mu.RLock()
	keys := make([]string, len(h.labelOrder))
	copy(keys, h.labelOrder)
	bounds := h.boundaries // boundaries are immutable post-construction
	h.mu.RUnlock()

	for _, key := range keys {
		h.mu.RLock()
		cells := h.labelSets[key]
		h.mu.RUnlock()

		// Render le="..." bucket lines, then sum + count.
		// Splice the `le` label into the existing label-suffix string.
		base := key // "{a="x",b="y"}" or ""
		for i, b := range bounds {
			leLine := injectLELabel(base, formatFloat(b))
			if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, leLine, atomic.LoadUint64(&cells.counts[i])); err != nil {
				return err
			}
		}
		// Always emit the +Inf bucket.
		infLine := injectLELabel(base, "+Inf")
		if _, err := fmt.Fprintf(w, "%s_bucket%s %d\n", name, infLine, atomic.LoadUint64(&cells.counts[len(bounds)])); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_sum%s %s\n", name, base, formatFloat(bitsToFloat64(cells.sumBits.Load()))); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_count%s %d\n", name, base, cells.count.Load()); err != nil {
			return err
		}
	}
	return nil
}

// injectLELabel splices `le="<val>"` into a Prometheus label suffix.
// `base` is either empty (no labels) or "{a=v,b=v}". The result is in
// canonical sorted order — `le` is alphabetically before any label
// starting with letters after 'l', otherwise it goes inside the brace
// at the right position.
func injectLELabel(base, leVal string) string {
	leField := `le="` + leVal + `"`
	if base == "" {
		return "{" + leField + "}"
	}
	// Strip the surrounding braces, split into existing fields, and
	// re-insert with le in sorted position.
	inner := base[1 : len(base)-1]
	parts := strings.Split(inner, ",")
	parts = append(parts, leField)
	sort.Slice(parts, func(i, j int) bool {
		return labelName(parts[i]) < labelName(parts[j])
	})
	return "{" + strings.Join(parts, ",") + "}"
}

func labelName(field string) string {
	if i := strings.IndexByte(field, '='); i > 0 {
		return field[:i]
	}
	return field
}

// addToFloatBits is a CAS loop that adds delta to the float64 stored
// as bit-encoded uint64 in *target.
func addToFloatBits(target *atomic.Uint64, delta float64) {
	for {
		old := target.Load()
		new := math.Float64bits(math.Float64frombits(old) + delta)
		if target.CompareAndSwap(old, new) {
			return
		}
	}
}

// ---- Labels ---------------------------------------------------------------

// Label is a single key=value label pair. Daemon metrics are
// deliberately low-cardinality (outcome, error class); if a future
// metric needs higher cardinality, consider a histogram or a different
// aggregation strategy — the registry here is not optimized for it.
type Label struct {
	Name  string
	Value string
}

// serialiseLabels produces a Prometheus-text-format label suffix
// (including the leading curly brace), or the empty string for no
// labels. Labels are sorted by name so the suffix is deterministic.
// Values are escaped per the exposition format: backslash, double-
// quote, and newline get backslash-escaped; everything else passes
// through.
func serialiseLabels(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	sorted := make([]Label, len(labels))
	copy(sorted, labels)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	b.WriteByte('{')
	for i, lb := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(lb.Name)
		b.WriteByte('=')
		b.WriteByte('"')
		b.WriteString(escapeLabelValue(lb.Value))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func escapeLabelValue(v string) string {
	if !strings.ContainsAny(v, `\"`+"\n") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---- small numeric helpers -----------------------------------------------

// formatFloat returns the Prometheus-friendly rendering of v: either an
// integer literal if v is integral and within int64 range, or a
// shortest-round-trip float otherwise. This mirrors what
// client_golang emits for counters upgraded to floats.
func formatFloat(v float64) string {
	if v == float64(int64(v)) && v >= -1e15 && v <= 1e15 {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}

// float64bits / bitsToFloat64 wrap math.Float64bits so the gauge helper
// lands in one named pair of shims (keeps the exposition code readable).
func float64bits(f float64) uint64   { return math.Float64bits(f) }
func bitsToFloat64(b uint64) float64 { return math.Float64frombits(b) }
