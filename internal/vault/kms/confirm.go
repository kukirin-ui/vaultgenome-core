// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// ReceiptFetcher fetches a destination's signed restore receipt.
// HTTPTransport implements it.
type ReceiptFetcher interface {
	FetchRestoreReceipt(ctx context.Context, endpoint string, kid ids.KeyID) (receipt.Signed, error)
}

// AuthorizedRelease is what the audit log recorded when a key release was
// authorized. A restore confirmation is checked against these facts and
// nothing else: the destination's receipt has to agree with them.
type AuthorizedRelease struct {
	DecisionID             ids.DecisionID
	RequestID              ids.RequestID
	TokenID                ids.DecisionID
	DestinationKind        tee.Provider
	DestinationMeasurement []byte
	KeyIDs                 []ids.KeyID
	AuthorizedAt           time.Time
	AuditID                ids.AuditEventID
}

// FindAuthorizedRelease returns the release the audit log recorded for
// decisionID — the latest, if the decision was released more than once.
// Pass the events of a log that has been verified.
func FindAuthorizedRelease(events []audit_event.AuditEvent, decisionID ids.DecisionID) (AuthorizedRelease, error) {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Kind != audit_event.KindKeyReleaseAuthorized {
			continue
		}
		var p keyReleaseAuthorizedPayload
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return AuthorizedRelease{}, shared_errors.Integrity(shared_errors.CodeFieldValueInvalid,
				fmt.Sprintf("kms.FindAuthorizedRelease: audit event %s does not decode", e.EventID), err)
		}
		if p.DecisionID != decisionID {
			continue
		}
		return AuthorizedRelease{
			DecisionID:             p.DecisionID,
			RequestID:              p.RequestID,
			TokenID:                p.TokenID,
			DestinationKind:        p.DestinationKind,
			DestinationMeasurement: p.DestinationMeasurement,
			KeyIDs:                 p.KeyIDs,
			AuthorizedAt:           p.AuthorizedAt,
			AuditID:                e.EventID,
		}, nil
	}
	return AuthorizedRelease{}, shared_errors.Authority(shared_errors.CodeRequiredFieldMissing,
		fmt.Sprintf("kms.FindAuthorizedRelease: the audit log records no authorized release for decision %q", decisionID), nil)
}

// ExpectedGenome is the genome the operator released the key for, read
// from the bundle they hold. With it, ConfirmRestore also requires the
// destination to have restored exactly that genome.
type ExpectedGenome struct {
	BundleSHA256  string // hex, of the bundle file
	PayloadSHA256 string // "sha256:<hex>", from its header
	TreeSHA256    string // hex: tree.Digest(tree.Files(header))
}

// ConfirmRequest asks for a released genome's restore to be confirmed.
type ConfirmRequest struct {
	Release             AuthorizedRelease
	DestinationEndpoint string
	KeyID               ids.KeyID
	Expect              *ExpectedGenome
	// RequireGate, when set (receipt.GateEquivalent or receipt.GateExact),
	// requires the destination to have gated the restored model and the
	// verdict to be at least that.
	RequireGate string
	SessionID   ids.SessionID
	ManifestID  ids.ManifestID
}

// ConfirmResult is a confirmed restore.
type ConfirmResult struct {
	Receipt       receipt.Receipt
	ReceiptSHA256 []byte
	// MatchedOperatorBundle is true when the request carried an
	// ExpectedGenome and the receipt matched it.
	MatchedOperatorBundle bool
	ConfirmedAt           time.Time
	AuditID               ids.AuditEventID
}

// restoreConfirmedPayload is the JSON payload of a
// KindCrossCloudRestoreCompleted audit event: the destination's receipt,
// checked, and what it was checked against.
type restoreConfirmedPayload struct {
	DecisionID             ids.DecisionID `json:"decision_id"`
	RequestID              ids.RequestID  `json:"request_id"`
	TokenID                ids.DecisionID `json:"token_id"`
	KeyID                  ids.KeyID      `json:"key_id"`
	ReleaseAuditID         string         `json:"release_audit_id"`
	DestinationKind        tee.Provider   `json:"destination_kind"`
	DestinationMeasurement []byte         `json:"destination_measurement"`
	BundleSHA256           string         `json:"bundle_sha256"`
	Generation             uint64         `json:"generation"`
	PayloadSHA256          string         `json:"payload_sha256"`
	TreeSHA256             string         `json:"tree_sha256"`
	Files                  int            `json:"files"`
	Bytes                  int64          `json:"bytes"`
	KeyReceivedAt          time.Time      `json:"key_received_at"`
	RestoredAt             time.Time      `json:"restored_at"`
	RestoreSeconds         float64        `json:"restore_seconds"`
	ReceiptSHA256          []byte         `json:"receipt_sha256"`
	EvidenceSHA256         []byte         `json:"evidence_sha256"`
	MatchedOperatorBundle  bool           `json:"matched_operator_bundle"`
	Gate                   *receipt.Gate  `json:"gate,omitempty"`
	RequiredGate           string         `json:"required_gate,omitempty"`
	ConfirmedAt            time.Time      `json:"confirmed_at"`
}

// ConfirmRestore fetches the destination's receipt for a released
// genome, verifies the Evidence over it with the verifier for the
// destination's TEE family, and requires it to agree with the recorded
// release: the same TEE measurement the key went to, and the same
// decision, request, token and key. With req.Expect it also requires the
// restored genome to be the operator's. Only then does it record the
// restore as completed (KindCrossCloudRestoreCompleted). Nothing is
// recorded for a receipt that fails.
func (c *Coordinator) ConfirmRestore(ctx context.Context, req ConfirmRequest) (ConfirmResult, error) {
	if c.receipts == nil {
		return ConfirmResult{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.ConfirmRestore: no ReceiptFetcher configured", nil)
	}
	rel := req.Release
	if rel.DecisionID.IsZero() || rel.RequestID.IsZero() || rel.TokenID.IsZero() || len(rel.DestinationMeasurement) == 0 {
		return ConfirmResult{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.ConfirmRestore: the recorded release is incomplete", nil)
	}
	if req.DestinationEndpoint == "" {
		return ConfirmResult{}, shared_errors.Structural(shared_errors.CodeRequiredFieldMissing, "kms.ConfirmRestore: DestinationEndpoint required", nil)
	}
	if req.RequireGate != "" && req.RequireGate != receipt.GateEquivalent && req.RequireGate != receipt.GateExact {
		return ConfirmResult{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid,
			fmt.Sprintf("kms.ConfirmRestore: RequireGate %q (want %s or %s)", req.RequireGate, receipt.GateEquivalent, receipt.GateExact), nil)
	}
	if !slices.Contains(rel.KeyIDs, req.KeyID) {
		return ConfirmResult{}, shared_errors.Authority(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("kms.ConfirmRestore: key %q was not released under decision %q", req.KeyID, rel.DecisionID), nil)
	}
	verifier, err := c.verifiers.Resolve(rel.DestinationKind)
	if err != nil {
		return ConfirmResult{}, err
	}

	signed, err := c.receipts.FetchRestoreReceipt(ctx, req.DestinationEndpoint, req.KeyID)
	if err != nil {
		return ConfirmResult{}, err
	}
	rc, measurement, err := receipt.Verify(signed, verifier)
	if err != nil {
		return ConfirmResult{}, shared_errors.Integrity(shared_errors.CodeAttestationDenied, "kms.ConfirmRestore: receipt refused", err)
	}
	if !bytes.Equal(measurement, rel.DestinationMeasurement) {
		return ConfirmResult{}, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("kms.ConfirmRestore: the receipt is signed by TEE measurement %x, but the key was released to %x", []byte(measurement), rel.DestinationMeasurement), nil)
	}
	for _, m := range []struct{ field, got, want string }{
		{"decision_id", rc.DecisionID, string(rel.DecisionID)},
		{"request_id", rc.RequestID, string(rel.RequestID)},
		{"token_id", rc.TokenID, string(rel.TokenID)},
		{"key_id", rc.KeyID, string(req.KeyID)},
		{"destination_kind", rc.DestinationKind, string(rel.DestinationKind)},
	} {
		if m.got != m.want {
			return ConfirmResult{}, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
				fmt.Sprintf("kms.ConfirmRestore: receipt %s %q, the recorded release says %q", m.field, m.got, m.want), nil)
		}
	}
	matched := false
	if e := req.Expect; e != nil {
		for _, m := range []struct{ field, got, want string }{
			{"bundle_sha256", rc.BundleSHA256, e.BundleSHA256},
			{"payload_sha256", rc.PayloadSHA256, e.PayloadSHA256},
			{"tree_sha256", rc.TreeSHA256, e.TreeSHA256},
		} {
			if m.got != m.want {
				return ConfirmResult{}, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
					fmt.Sprintf("kms.ConfirmRestore: the destination restored %s %s, the operator's genome has %s", m.field, m.got, m.want), nil)
			}
		}
		matched = true
	}

	if req.RequireGate != "" && !rc.Gate.Meets(req.RequireGate) {
		got := "no gate verdict"
		if rc.Gate != nil {
			got = "gate verdict " + rc.Gate.Level
		}
		return ConfirmResult{}, shared_errors.Integrity(shared_errors.CodeAttestationDenied,
			fmt.Sprintf("kms.ConfirmRestore: the destination signed %s; %s or better is required", got, req.RequireGate), nil)
	}

	receiptSum := sha256.Sum256(signed.Receipt)
	evidenceSum := sha256.Sum256(signed.Evidence)
	confirmedAt := c.clock.Now().UTC()
	payload, err := json.Marshal(restoreConfirmedPayload{
		DecisionID:             rel.DecisionID,
		RequestID:              rel.RequestID,
		TokenID:                rel.TokenID,
		KeyID:                  req.KeyID,
		ReleaseAuditID:         string(rel.AuditID),
		DestinationKind:        rel.DestinationKind,
		DestinationMeasurement: rel.DestinationMeasurement,
		BundleSHA256:           rc.BundleSHA256,
		Generation:             rc.Generation,
		PayloadSHA256:          rc.PayloadSHA256,
		TreeSHA256:             rc.TreeSHA256,
		Files:                  rc.Files,
		Bytes:                  rc.Bytes,
		KeyReceivedAt:          rc.KeyReceivedAt,
		RestoredAt:             rc.RestoredAt,
		RestoreSeconds:         rc.RestoreSeconds,
		ReceiptSHA256:          receiptSum[:],
		EvidenceSHA256:         evidenceSum[:],
		MatchedOperatorBundle:  matched,
		Gate:                   rc.Gate,
		RequiredGate:           req.RequireGate,
		ConfirmedAt:            confirmedAt,
	})
	if err != nil {
		return ConfirmResult{}, shared_errors.Structural(shared_errors.CodeFieldValueInvalid, "kms.ConfirmRestore: payload marshal failed", err)
	}
	auditID, err := c.auditChain.Emit(audit_event.KindCrossCloudRestoreCompleted, payload, req.SessionID, req.ManifestID, rel.RequestID)
	if err != nil {
		return ConfirmResult{}, err
	}
	return ConfirmResult{Receipt: rc, ReceiptSHA256: receiptSum[:], MatchedOperatorBundle: matched, ConfirmedAt: confirmedAt, AuditID: auditID}, nil
}
