// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package intake

import (
	"sync"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/recovery_request"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
)

// Refusal codes of intake. Every one is Structural: intake never refuses
// on policy grounds (that is trust's decision, stage 2).
const (
	// CodeDuplicateRequest: a RecoveryRequest with this request_id was
	// already admitted within the window intake remembers.
	CodeDuplicateRequest = "intake.duplicate_request"
)

// Defaults for Options.
const (
	DefaultCapacity = 4096
	DefaultWindow   = 24 * time.Hour
)

// Options tunes what intake remembers.
type Options struct {
	// Capacity is how many admitted request_ids intake remembers; the
	// oldest is forgotten when a new one arrives past it. Default 4096.
	Capacity int
	// Window is how long an admitted request_id stays a duplicate.
	// Default 24 h.
	Window time.Duration
}

// Intake is stage 1 of the nine-stage flow: the entry point of
// RecoveryRequests into the vault. It decides only whether a request is
// well-formed enough to present to trust — the schema is supported, every
// required field is set, the request_id was not already admitted — and
// nothing about continuity policy.
type Intake struct {
	mu       sync.Mutex
	clock    shared_time.Clock
	capacity int
	window   time.Duration
	seen     map[ids.RequestID]time.Time
	order    []ids.RequestID
}

// New builds an Intake. clock is required.
func New(clock shared_time.Clock, opts Options) (*Intake, error) {
	if clock == nil {
		return nil, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "vault/intake: clock is required", nil)
	}
	if opts.Capacity < 0 || opts.Window < 0 {
		return nil, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "vault/intake: capacity and window must not be negative", nil)
	}
	capacity := opts.Capacity
	if capacity == 0 {
		capacity = DefaultCapacity
	}
	window := opts.Window
	if window == 0 {
		window = DefaultWindow
	}
	return &Intake{clock: clock, capacity: capacity, window: window, seen: map[ids.RequestID]time.Time{}}, nil
}

// Admit checks req and remembers its request_id. A malformed request is
// refused with the contract's own Structural error; a request_id already
// admitted within the window is refused with CodeDuplicateRequest. A
// refused request is not remembered.
func (i *Intake) Admit(req recovery_request.RecoveryRequest) error {
	if err := req.Validate(); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock.Now().UTC()
	i.forget(now)
	if at, dup := i.seen[req.RequestID]; dup {
		return shared_errors.Structural(CodeDuplicateRequest,
			"vault/intake: request_id "+req.RequestID.String()+" was already admitted at "+at.Format(time.RFC3339Nano), nil)
	}
	i.seen[req.RequestID] = now
	i.order = append(i.order, req.RequestID)
	for len(i.order) > i.capacity {
		delete(i.seen, i.order[0])
		i.order = i.order[1:]
	}
	return nil
}

// forget drops request_ids older than the window. Called under i.mu.
func (i *Intake) forget(now time.Time) {
	for len(i.order) > 0 {
		oldest := i.order[0]
		if now.Sub(i.seen[oldest]) < i.window {
			return
		}
		delete(i.seen, oldest)
		i.order = i.order[1:]
	}
}

// Remembered is how many request_ids intake currently holds as
// duplicates.
func (i *Intake) Remembered() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.seen)
}
