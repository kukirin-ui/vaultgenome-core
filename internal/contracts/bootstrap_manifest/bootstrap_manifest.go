// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Package bootstrap_manifest defines the BootstrapManifest canonical
// contract — the receive-side recipe for assembling an AI Genome from a
// sequence of authorized disclosures.
//
// # Doctrinal role
//
// Staged Disclosure is enforced at the Vault: the release-side
// ReconstructionJobManifest names which components will be emitted, and
// each DisclosureMessage carries one component. The receive-side needs
// its own artifact that states, before any bytes arrive: "in this
// session, under this policy version, I expect exactly these component
// disclosures, in this order, and I will refuse any disclosure outside
// that list."
//
// That artifact is BootstrapManifest. It is the RECEIVE-SIDE MIRROR of
// ReconstructionJobManifest:
//
//	Vault side                       Receive side
//	────────────────────────────     ────────────────────────────
//	ReconstructionJobManifest    →   BootstrapManifest
//	   (what the Vault authorizes)      (what the recipient will accept)
//
// The two shapes are deliberately separate. If they were the same type,
// silent drift between "authorized" and "accepted" could not be named by
// the type system. Keeping them distinct makes identity mismatch an
// explicit doctrine-level claim that can be asserted cross-contract.
//
// A BootstrapManifest is signed by the receiving environment's signing
// authority (separate key, separate purpose) and bound to a specific
// SessionID and ManifestID. It carries no keys, no payloads, and no
// Genome material — only the ordered list of ExpectedDisclosureIDs and
// the shape assertions required to accept the stream.
//
// Corresponds to P1 §[0051]–[0052] (self-bootstrapping receive-side
// orchestration) and P3 §[0042].
package bootstrap_manifest

import (
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

const (
	SchemaVersionMin     uint16 = 1
	SchemaVersionMax     uint16 = 1
	SchemaVersionCurrent uint16 = 1
)

// BootstrapManifest is the receive-side recipe that binds a reconstitution
// attempt to a specific session, manifest, policy version, and ordered
// list of expected disclosures.
type BootstrapManifest struct {
	SchemaVersion uint16                  `json:"schema_version"`
	BootstrapID   ids.BootstrapManifestID `json:"bootstrap_id"`

	// SessionID pins the trusted session under which the associated
	// disclosures were authorized. A BootstrapManifest whose SessionID
	// does not match the SessionObject issued by the Vault is invalid.
	SessionID ids.SessionID `json:"session_id"`

	// ManifestID pins the release-side ReconstructionJobManifest that
	// this bootstrap mirrors. The two must agree on SessionID,
	// PolicyVersion, and the set of DisclosureIDs (see §3 of the
	// Bootstrap Contracts Doctrine).
	ManifestID ids.ManifestID `json:"manifest_id"`

	// GenomeID identifies the AI Genome being reassembled.
	GenomeID ids.GenomeID `json:"genome_id"`

	// PolicyVersion pins the policy revision under which acceptance will
	// be judged. Must match the release-side manifest.
	PolicyVersion ids.PolicyVersion `json:"policy_version"`

	// ExpectedDisclosureIDs are the release-side DisclosureIDs this
	// bootstrap will accept, in acceptance order. The receive-side
	// orchestrator MUST refuse any DisclosureMessage whose DisclosureID
	// is not in this list, and MUST refuse out-of-order arrival. Must
	// be non-empty and contain no duplicates.
	ExpectedDisclosureIDs []ids.DisclosureID `json:"expected_disclosure_ids"`

	// ExpectedComponentIDs names the components in the same order as
	// ExpectedDisclosureIDs. Keeping the two lists parallel (rather
	// than a single [ ]{DisclosureID, ComponentID} struct) keeps the
	// canonical JSON shape minimal and machine-comparable against the
	// release-side manifest. Length MUST equal len(ExpectedDisclosureIDs).
	ExpectedComponentIDs []ids.ComponentID `json:"expected_component_ids"`

	// Deadline is the latest wall-clock moment by which the full set of
	// disclosures must have arrived. Arrivals after the deadline are
	// treated as failed bootstrap and MUST NOT be assembled. Must be
	// strictly after IssuedAt.
	Deadline time.Time `json:"deadline"`

	IssuedAt     time.Time `json:"issued_at"`
	SigningKeyID ids.KeyID `json:"signing_key_id"`
	Signature    []byte    `json:"signature"`
}
