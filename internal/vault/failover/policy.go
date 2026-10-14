// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package failover moves a genome to a standby when its primary can no
// longer be trusted, under a policy the operator signed in advance
// (ADR 0012).
//
// The decision is never the model's, the primary's, or the release
// authority's own. The operator signs a failover policy with the same key
// that signs the stop list (ADR 0010). The policy names the primary's
// sentinel by its public key. It names the one standby a genome may go to,
// by TEE kind, endpoint and measurement. It says which signs of failure
// count: a compromise report, or a heartbeat that stops. It also says what
// the restore must prove: a gate verdict. The release authority's executor
// only carries the policy out:
//
//   - it watches the primary's outbox, accepting nothing that does not
//     verify under the pinned sentinel key;
//   - when a trigger fires, it chooses the newest genome the sentinel
//     sealed before the trigger. It checks that genome's chain and files,
//     and it records its decision (FAILOVER_DECIDED) before any key moves;
//   - it opens the genome's escrowed key and releases it, through the
//     ordinary attested release, only to the standby the policy names. The
//     operator's stop list still applies in front of everything;
//   - it confirms the standby's signed restore, with the gate verdict the
//     policy requires, and reports how long it all took (RTO) and how much
//     state the chosen genome misses (RPO).
//
// One policy serial performs at most one failover. Moving again takes a new
// policy, and so a new operator signature for every hop. Nothing can make a
// genome travel on its own.
package failover

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/receipt"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/exposure"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// Schema identifies version 1 of the failover policy.
const Schema = "vault-genome/failover-policy/v1"

// Policy is the operator's signed, standing instruction for one failover.
type Policy struct {
	Schema   string    `json:"schema"`
	Serial   uint64    `json:"serial"`
	IssuedAt time.Time `json:"issued_at"`
	// NotAfter bounds how long the instruction stands.
	NotAfter time.Time `json:"not_after"`
	// SentinelPublicKey is the primary's sentinel key (Ed25519, 32 bytes):
	// only records, heartbeats and reports it signed count.
	SentinelPublicKey []byte `json:"sentinel_public_key"`
	// Primary, when set, pins the primary's TEE (ADR 0017): a record from
	// the outbox counts only when it carries a report from that TEE, at
	// one of these measurements, bound to the record's content. The
	// sentinel's key alone is then not enough to keep the authority quiet.
	Primary  *Primary `json:"primary,omitempty"`
	Standby  Standby  `json:"standby"`
	Triggers Triggers `json:"triggers"`
	// QuarantineSeconds distrusts genomes sealed within this long before
	// the trigger: an intrusion may start before a wire sees it.
	QuarantineSeconds int64 `json:"quarantine_seconds,omitempty"`
	// MaxRPOSeconds declines a failover whose newest trustworthy genome is
	// older than this at the trigger; 0 sets no bound.
	MaxRPOSeconds int64 `json:"max_rpo_seconds,omitempty"`
	// RequireGate is the gate verdict the standby's receipt must carry:
	// EQUIVALENT (or better), EXACT, or empty for none.
	RequireGate  string `json:"require_gate,omitempty"`
	Reason       string `json:"reason,omitempty"`
	SigningKeyID string `json:"signing_key_id"`
	Signature    []byte `json:"signature,omitempty"`
}

// Primary is the primary's TEE, as the policy pins it.
type Primary struct {
	Kind string `json:"kind"`
	// Measurements (hex) the primary's TEE must attest one of.
	Measurements []string `json:"measurements"`
	// AttestorPublicKey is the simulated primary's attestation key (32
	// bytes); a hardware kind leaves it empty, its chain being the
	// authority's own anchor.
	AttestorPublicKey []byte `json:"attestor_public_key,omitempty"`
}

// Standby is the one destination the policy lets a genome go to.
type Standby struct {
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
	// Measurements (hex) the standby's TEE must attest one of. The release
	// also still needs the release authority's allow-list.
	Measurements []string `json:"measurements"`
}

// Triggers are the signs of failure the policy acts on.
type Triggers struct {
	// CompromiseReport: a signed compromise report from the sentinel.
	CompromiseReport bool `json:"compromise_report"`
	// HeartbeatTimeoutSeconds: no new heartbeat for this long; 0 disables.
	HeartbeatTimeoutSeconds int64 `json:"heartbeat_timeout_seconds,omitempty"`
	// StoppedGraceSeconds bounds how long a heartbeat that says `stopped`
	// stands the authority down: a sentinel that does not come back
	// watching within this long is a trigger (stopped-overdue). 0 honours
	// `stopped` indefinitely, as before ADR 0017. The primary's word
	// should not disarm the authority for good.
	StoppedGraceSeconds int64 `json:"stopped_grace_seconds,omitempty"`
}

func (p Policy) validate() error {
	switch {
	case p.Schema != Schema:
		return fmt.Errorf("failover: schema %q, want %q", p.Schema, Schema)
	case p.Serial == 0:
		return errors.New("failover: serial must be at least 1")
	case p.IssuedAt.IsZero() || !p.NotAfter.After(p.IssuedAt):
		return errors.New("failover: issued_at required, and not_after must follow it")
	case len(p.SentinelPublicKey) != ed25519.PublicKeySize:
		return fmt.Errorf("failover: sentinel_public_key must be %d bytes", ed25519.PublicKeySize)
	case !p.Triggers.CompromiseReport && p.Triggers.HeartbeatTimeoutSeconds <= 0:
		return errors.New("failover: the policy names no trigger")
	case p.Triggers.HeartbeatTimeoutSeconds < 0 || p.Triggers.StoppedGraceSeconds < 0 || p.QuarantineSeconds < 0 || p.MaxRPOSeconds < 0:
		return errors.New("failover: durations must not be negative")
	case p.RequireGate != "" && p.RequireGate != receipt.GateEquivalent && p.RequireGate != receipt.GateExact:
		return fmt.Errorf("failover: require_gate %q (want %s, %s or none)", p.RequireGate, receipt.GateEquivalent, receipt.GateExact)
	case p.SigningKeyID == "":
		return errors.New("failover: signing_key_id required")
	}
	if _, err := tee.ParseProvider(p.Standby.Kind); err != nil {
		return fmt.Errorf("failover: standby kind: %w", err)
	}
	if err := checkEndpoint(p.Standby.Endpoint); err != nil {
		return err
	}
	if len(p.Standby.Measurements) == 0 {
		return errors.New("failover: the standby must be pinned to at least one measurement")
	}
	if err := checkMeasurements("standby", p.Standby.Measurements); err != nil {
		return err
	}
	return p.Primary.validate()
}

func (pr *Primary) validate() error {
	if pr == nil {
		return nil
	}
	kind, err := tee.ParseProvider(pr.Kind)
	if err != nil {
		return fmt.Errorf("failover: primary kind: %w", err)
	}
	if len(pr.Measurements) == 0 {
		return errors.New("failover: a pinned primary needs at least one measurement")
	}
	if err := checkMeasurements("primary", pr.Measurements); err != nil {
		return err
	}
	switch {
	case kind == tee.ProviderSimulated && len(pr.AttestorPublicKey) != ed25519.PublicKeySize:
		return fmt.Errorf("failover: a simulated primary is pinned by its attestation key (%d bytes)", ed25519.PublicKeySize)
	case kind != tee.ProviderSimulated && len(pr.AttestorPublicKey) != 0:
		return fmt.Errorf("failover: a %s primary has no attestation key to pin; its chain is the authority's anchor", kind)
	}
	return nil
}

func checkMeasurements(who string, ms []string) error {
	for _, m := range ms {
		b, err := hex.DecodeString(m)
		if err != nil || hex.EncodeToString(b) != m {
			return fmt.Errorf("failover: %s measurement %q is not lower-case hex", who, m)
		}
		if _, err := tee.MeasurementFromBytes(b); err != nil {
			return fmt.Errorf("failover: %s measurement: %w", who, err)
		}
	}
	return nil
}

// PinsPrimary reports whether the policy pins the primary's TEE.
func (p Policy) PinsPrimary() bool { return p.Primary != nil }

// PrimaryAllows reports whether measurement is one the policy pins the
// primary at.
func (p Policy) PrimaryAllows(measurement tee.Measurement) bool {
	return p.Primary != nil && slices.Contains(p.Primary.Measurements, hex.EncodeToString(measurement))
}

// checkEndpoint accepts https, and plain http only to a loopback host.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("failover: standby endpoint %q is not an absolute URL", raw)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && exposure.IsLoopbackHost(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("failover: standby endpoint %q: https required (plain http only to a loopback host)", raw)
}

func (p Policy) signedBytes() ([]byte, error) {
	p.Signature = nil
	return crypto.CanonicalJSON(p)
}

// Sign validates p and signs it with the operator key. Schema is filled in
// when empty.
func Sign(p Policy, priv ed25519.PrivateKey) (Policy, error) {
	if p.Schema == "" {
		p.Schema = Schema
	}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	msg, err := p.signedBytes()
	if err != nil {
		return Policy{}, err
	}
	p.Signature = ed25519.Sign(priv, msg)
	return p, nil
}

// Parse decodes a signed policy and accepts it only if it is well formed,
// names kid as its signer and verifies under the operator key pub.
func Parse(raw []byte, pub ed25519.PublicKey, kid string) (Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("failover: decode: %w", err)
	}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	if p.SigningKeyID != kid {
		return Policy{}, fmt.Errorf("failover: the policy is signed by %q; this authority trusts operator key %q", p.SigningKeyID, kid)
	}
	msg, err := p.signedBytes()
	if err != nil {
		return Policy{}, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, p.Signature) {
		return Policy{}, errors.New("failover: signature does not verify under the operator key")
	}
	return p, nil
}

// Sentinel returns the pinned sentinel key and its ID.
func (p Policy) Sentinel() (ed25519.PublicKey, string) {
	pub := ed25519.PublicKey(p.SentinelPublicKey)
	return pub, sentinel.KeyID(pub)
}

// Digest is the SHA-256 of the signed policy, as recorded with every
// decision taken under it.
func (p Policy) Digest() []byte {
	raw, _ := crypto.CanonicalJSON(p)
	sum := sha256.Sum256(raw)
	return sum[:]
}

// Allows reports whether the policy lets a genome go to measurement on kind.
func (p Policy) Allows(kind tee.Provider, measurement []byte) bool {
	return string(kind) == p.Standby.Kind && slices.Contains(p.Standby.Measurements, hex.EncodeToString(measurement))
}

// ActiveAt reports whether the policy stands at t.
func (p Policy) ActiveAt(t time.Time) error {
	if t.Before(p.IssuedAt.Add(-5 * time.Minute)) {
		return fmt.Errorf("failover: policy serial %d is issued at %s, in the future", p.Serial, p.IssuedAt.Format(time.RFC3339))
	}
	if !t.Before(p.NotAfter) {
		return fmt.Errorf("failover: policy serial %d expired at %s", p.Serial, p.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// CheckNotSpent refuses a policy that already carried out a failover, and
// one older than a policy already applied, per the verified audit log.
func CheckNotSpent(p Policy, events []audit_event.AuditEvent) error {
	var highest uint64
	for _, e := range events {
		if e.Kind != audit_event.KindFailoverDecided {
			continue
		}
		var d struct {
			Decision     string `json:"decision"`
			PolicySerial uint64 `json:"policy_serial"`
		}
		if json.Unmarshal(e.Payload, &d) != nil {
			return fmt.Errorf("failover: audit event %s does not decode", e.EventID)
		}
		highest = max(highest, d.PolicySerial)
		if d.PolicySerial == p.Serial && d.Decision == DecisionFailover {
			return fmt.Errorf("failover: policy serial %d already carried out a failover (audit event %s); moving again needs a new policy", p.Serial, e.EventID)
		}
	}
	if p.Serial < highest {
		return fmt.Errorf("failover: policy serial %d is older than serial %d already applied in the audit log (rollback refused)", p.Serial, highest)
	}
	return nil
}
