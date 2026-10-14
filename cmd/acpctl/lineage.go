// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
)

// lineageCmd implements `acpctl lineage` — given a session or manifest
// ID, walk the audit log to assemble the chronological lineage of
// events tied to that identifier.
//
// Use cases:
//   - Regulator query: "what was running for session X at time Y?"
//   - GDPR Article 22: "what model produced this recommendation?"
//   - Incident root-cause: "trace this release back to its genome"
//
// The output is operator-readable by default and machine-readable
// with --json for ingestion into the lab's existing tooling.
func lineageCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lineage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		auditPath  = fs.String("audit", "", "Path to the audit bbolt file (required)")
		sessionID  = fs.String("session-id", "", "Session ID to trace")
		manifestID = fs.String("manifest-id", "", "Manifest ID to trace")
		jsonOut    = fs.Bool("json", false, "Emit machine-readable JSON output")
	)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: acpctl lineage --audit PATH (--session-id ID | --manifest-id ID) [--json]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Walk the audit log chronologically, returning every event tied to")
		fmt.Fprintln(stderr, "the supplied session or manifest. Exactly one of --session-id and")
		fmt.Fprintln(stderr, "--manifest-id MUST be set.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *auditPath == "" {
		fmt.Fprintln(stderr, "acpctl lineage: --audit is required")
		return 2
	}
	if (*sessionID == "" && *manifestID == "") || (*sessionID != "" && *manifestID != "") {
		fmt.Fprintln(stderr, "acpctl lineage: exactly one of --session-id and --manifest-id is required")
		return 2
	}

	s, err := store.Open(*auditPath)
	if err != nil {
		fmt.Fprintf(stderr, "acpctl lineage: open audit store: %v\n", err)
		return 1
	}
	defer func() { _ = s.Close() }()
	events, err := s.Load()
	if err != nil {
		fmt.Fprintf(stderr, "acpctl lineage: load: %v\n", err)
		return 1
	}

	matched := assembleLineage(events, *sessionID, *manifestID)

	if len(matched) == 0 {
		if *jsonOut {
			_ = json.NewEncoder(stdout).Encode(lineageResult{Matched: 0})
		} else {
			fmt.Fprintln(stdout, "no events found for the requested ID")
		}
		return 0
	}

	emitLineage(stdout, *jsonOut, lineageResult{
		Matched:       len(matched),
		Events:        matched,
		QuerySession:  *sessionID,
		QueryManifest: *manifestID,
	})
	return 0
}

type lineageResult struct {
	QuerySession  string         `json:"query_session,omitempty"`
	QueryManifest string         `json:"query_manifest,omitempty"`
	Matched       int            `json:"matched"`
	Events        []lineageEvent `json:"events,omitempty"`
}

type lineageEvent struct {
	EventID    string    `json:"event_id"`
	Kind       string    `json:"kind"`
	OccurredAt time.Time `json:"occurred_at"`
	SessionID  string    `json:"session_id,omitempty"`
	ManifestID string    `json:"manifest_id,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	Index      int       `json:"index"`
}

func assembleLineage(events []audit_event.AuditEvent, session, manifest string) []lineageEvent {
	matched := []lineageEvent{}
	for i := range events {
		evt := &events[i]
		if session != "" && string(evt.SessionID) != session {
			continue
		}
		if manifest != "" && string(evt.ManifestID) != manifest {
			continue
		}
		matched = append(matched, lineageEvent{
			EventID:    string(evt.EventID),
			Kind:       string(evt.Kind),
			OccurredAt: evt.OccurredAt,
			SessionID:  string(evt.SessionID),
			ManifestID: string(evt.ManifestID),
			RequestID:  string(evt.RequestID),
			Index:      i,
		})
	}
	// Already in storage order, but sort by OccurredAt explicitly so
	// out-of-order writes (extremely unlikely on a single-writer chain
	// but possible during cross-region merges) render predictably.
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].OccurredAt.Before(matched[j].OccurredAt)
	})
	return matched
}

func emitLineage(w io.Writer, asJSON bool, r lineageResult) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(r)
		return
	}
	if r.QuerySession != "" {
		fmt.Fprintf(w, "lineage for session %s:\n", r.QuerySession)
	} else {
		fmt.Fprintf(w, "lineage for manifest %s:\n", r.QueryManifest)
	}
	for _, e := range r.Events {
		fmt.Fprintf(w, "  [%4d] %s  %-30s  %s",
			e.Index,
			e.OccurredAt.UTC().Format(time.RFC3339),
			e.Kind,
			e.EventID)
		if r.QuerySession == "" && e.SessionID != "" {
			fmt.Fprintf(w, "  session=%s", e.SessionID)
		}
		if r.QueryManifest == "" && e.ManifestID != "" {
			fmt.Fprintf(w, "  manifest=%s", e.ManifestID)
		}
		if e.RequestID != "" {
			fmt.Fprintf(w, "  request=%s", e.RequestID)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "\n%d events in lineage\n", r.Matched)
}
