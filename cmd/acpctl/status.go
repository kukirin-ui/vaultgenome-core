// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
)

// statusCmd implements `acpctl status` — a local read-only summary of
// the daemon's persisted audit log. Designed to be safe to run on a
// production host: takes no daemon-side action, opens bbolt read-only
// behind the scenes (bbolt doesn't have a strict RO mode but our
// access is Load-only), exits non-zero only if the file itself is
// unreachable.
//
// Use cases:
//   - On-call sanity check ("what's the most recent event?")
//   - Pre-recovery verification ("how many events am I about to walk
//     during chain verify?")
//   - Operator monitoring scripts (--json mode pipes into jq)
func statusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		auditPath = fs.String("audit", "", "Path to the audit bbolt file (required)")
		jsonOut   = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl status --audit PATH [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Print a read-only summary of the audit log: event count, time range,")
		fmt.Fprintln(stderr, "kinds histogram, and the most recent event's metadata.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" {
		fmt.Fprintln(stderr, "acpctl status: --audit is required")
		fs.Usage()
		return 2
	}

	s, err := store.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl status: open audit store: %v\n", err)
		return 1
	}
	defer func() { _ = s.Close() }()

	events, err := s.Load()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl status: load events: %v\n", err)
		return 1
	}

	summary := buildStatusSummary(events)
	emitStatus(stdout, *jsonOut, summary)
	return 0
}

type statusSummary struct {
	AuditEventCount int                    `json:"audit_event_count"`
	FirstEventAt    *time.Time             `json:"first_event_at,omitempty"`
	LastEventAt     *time.Time             `json:"last_event_at,omitempty"`
	KindHistogram   map[string]int         `json:"kind_histogram"`
	UniqueSessions  int                    `json:"unique_sessions"`
	UniqueManifests int                    `json:"unique_manifests"`
	LastEvent       *statusLastEventDetail `json:"last_event,omitempty"`
}

type statusLastEventDetail struct {
	EventID    string    `json:"event_id"`
	Kind       string    `json:"kind"`
	OccurredAt time.Time `json:"occurred_at"`
	SessionID  string    `json:"session_id,omitempty"`
	ManifestID string    `json:"manifest_id,omitempty"`
}

func buildStatusSummary(events []audit_event.AuditEvent) statusSummary {
	s := statusSummary{
		AuditEventCount: len(events),
		KindHistogram:   map[string]int{},
	}
	if len(events) == 0 {
		return s
	}

	sessions := map[string]struct{}{}
	manifests := map[string]struct{}{}
	first := events[0].OccurredAt
	last := events[0].OccurredAt
	for i := range events {
		evt := &events[i]
		s.KindHistogram[string(evt.Kind)]++
		if evt.SessionID != "" {
			sessions[string(evt.SessionID)] = struct{}{}
		}
		if evt.ManifestID != "" {
			manifests[string(evt.ManifestID)] = struct{}{}
		}
		if evt.OccurredAt.Before(first) {
			first = evt.OccurredAt
		}
		if evt.OccurredAt.After(last) {
			last = evt.OccurredAt
		}
	}
	s.FirstEventAt = &first
	s.LastEventAt = &last
	s.UniqueSessions = len(sessions)
	s.UniqueManifests = len(manifests)

	tail := events[len(events)-1]
	s.LastEvent = &statusLastEventDetail{
		EventID:    string(tail.EventID),
		Kind:       string(tail.Kind),
		OccurredAt: tail.OccurredAt,
		SessionID:  string(tail.SessionID),
		ManifestID: string(tail.ManifestID),
	}
	return s
}

func emitStatus(w io.Writer, asJSON bool, s statusSummary) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(s)
		return
	}
	fmt.Fprintf(w, "audit events:    %d\n", s.AuditEventCount)
	if s.FirstEventAt != nil {
		fmt.Fprintf(w, "first event at:  %s\n", s.FirstEventAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(w, "last event at:   %s\n", s.LastEventAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(w, "unique sessions: %d\n", s.UniqueSessions)
	fmt.Fprintf(w, "unique manifests:%d\n", s.UniqueManifests)
	if len(s.KindHistogram) > 0 {
		fmt.Fprintln(w, "kind histogram:")
		// Sort kinds for stable output.
		kinds := make([]string, 0, len(s.KindHistogram))
		for k := range s.KindHistogram {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			fmt.Fprintf(w, "  %-32s %d\n", k, s.KindHistogram[k])
		}
	}
	if s.LastEvent != nil {
		fmt.Fprintln(w, "most recent event:")
		fmt.Fprintf(w, "  event_id:    %s\n", s.LastEvent.EventID)
		fmt.Fprintf(w, "  kind:        %s\n", s.LastEvent.Kind)
		fmt.Fprintf(w, "  occurred_at: %s\n", s.LastEvent.OccurredAt.UTC().Format(time.RFC3339))
		if s.LastEvent.SessionID != "" {
			fmt.Fprintf(w, "  session_id:  %s\n", s.LastEvent.SessionID)
		}
		if s.LastEvent.ManifestID != "" {
			fmt.Fprintf(w, "  manifest_id: %s\n", s.LastEvent.ManifestID)
		}
	}
	_ = os.Stdout
}
