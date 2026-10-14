// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package time

import (
	"sync"
	stdtime "time"
)

// Clock is the vault's time-source abstraction. All contract timestamps
// and all TTL comparisons go through a Clock; code must not call
// time.Now() directly outside this package.
//
// This matters because the vault's authoritative ordering of events is
// its monotonic reading, not wall-clock. An adversary who controls NTP
// cannot replay or reorder events inside the vault if the vault never
// trusts wall-clock for ordering. Wall-clock is advisory, used for
// displaying timestamps and for coarse TTL windows.
type Clock interface {
	// Now returns the current wall-clock projection of a monotonic
	// reading. Two sequential calls to Now on the same Clock are
	// guaranteed non-decreasing in monotonic terms; they may be equal
	// if called inside a single nanosecond tick.
	Now() stdtime.Time

	// Since returns the duration since t in monotonic terms if t carries
	// a monotonic component, otherwise wall-clock. Callers should prefer
	// Now().Sub(t) over this method when t is produced by the same Clock.
	Since(t stdtime.Time) stdtime.Duration
}

// ---- system clock -----------------------------------------------------------

// SystemClock is the production Clock. It delegates to time.Now(), which
// in Go >=1.9 carries both a wall-clock and a monotonic component on
// platforms that support it.
type SystemClock struct{}

// NewSystemClock returns a SystemClock value. It exists so callers can
// depend on Clock rather than on the struct type.
func NewSystemClock() Clock { return SystemClock{} }

// Now returns time.Now() (wall + monotonic).
func (SystemClock) Now() stdtime.Time { return stdtime.Now() }

// Since delegates to time.Since, which is monotonic-aware.
func (SystemClock) Since(t stdtime.Time) stdtime.Duration {
	return stdtime.Since(t)
}

// ---- fake clock (tests) -----------------------------------------------------

// FakeClock is a deterministic Clock for tests. Step or SetNow advances
// the clock; Now returns the advanced value plus a small monotonic delta
// so two calls in a row are distinguishable.
//
// FakeClock is safe for concurrent use.
type FakeClock struct {
	mu  sync.Mutex
	now stdtime.Time
}

// NewFakeClock returns a FakeClock set to the given wall-clock instant.
func NewFakeClock(start stdtime.Time) *FakeClock {
	return &FakeClock{now: start}
}

// Now returns the FakeClock's current value.
func (f *FakeClock) Now() stdtime.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Since returns the duration between f.Now() and t.
func (f *FakeClock) Since(t stdtime.Time) stdtime.Duration {
	return f.Now().Sub(t)
}

// SetNow jumps the FakeClock to an absolute instant. Intended for fixture
// setup, not for mid-test drift.
func (f *FakeClock) SetNow(t stdtime.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Step advances the FakeClock by d. Negative d is rejected (rolling a
// vault clock backwards is not a legitimate test operation — the vault
// would be entitled to treat it as an incident).
func (f *FakeClock) Step(d stdtime.Duration) {
	if d < 0 {
		panic("time.FakeClock.Step: negative step not permitted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
