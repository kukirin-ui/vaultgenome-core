// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe_battery

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
)

// ---- doctrinal drift budgets -----------------------------------------------
//
// Each DerivationMethod carries a doctrinal drift budget for
// capability probes — the maximum fraction of capability probes whose
// response hash is allowed to change between parent and child. These
// constants are part of the platform's public contract: changing one
// is a schema bump, because existing scorecards assume specific
// bounds.

const (
	// MaxDriftFineTune — continued training perturbs a bounded subset
	// of weights; capability responses shift a little, identity is
	// preserved. 5% is tight enough to catch a swap, loose enough to
	// tolerate a legitimate fine-tune.
	MaxDriftFineTune float64 = 0.05

	// MaxDriftDistill — a smaller student approximates, not matches.
	// 15% allows legitimate capacity loss while still failing on a
	// substitution with a completely different teacher.
	MaxDriftDistill float64 = 0.15

	// MaxDriftMerge — averaging weights from multiple parents yields
	// blended behavior. 8% is an aggregate cap across all parents
	// considered; per-parent enforcement is a policy layer concern.
	MaxDriftMerge float64 = 0.08

	// MaxDriftQuantize — lossy numerical precision reduction produces
	// small per-token differences that accumulate on open-ended
	// generation. 25% accepts a well-calibrated int8 from fp32 but
	// still fails a nonsense re-quantization.
	MaxDriftQuantize float64 = 0.25

	// MaxDriftReconstruct — the doctrinal reconstruction path must be
	// faithful. 8% is deliberately tight: reconstruction is the
	// canonical continuity path and the one most prone to attack.
	MaxDriftReconstruct float64 = 0.08
)

// MethodBudget returns the doctrinal capability-drift budget for m.
// Returns 0 and an Integrity error if m is not one of the known
// DerivationMethods — a method we don't have a doctrinal budget for
// cannot produce a valid continuity claim.
func MethodBudget(m genome_descriptor.DerivationMethod) (float64, error) {
	switch m {
	case genome_descriptor.DerivationFineTune:
		return MaxDriftFineTune, nil
	case genome_descriptor.DerivationDistill:
		return MaxDriftDistill, nil
	case genome_descriptor.DerivationMerge:
		return MaxDriftMerge, nil
	case genome_descriptor.DerivationQuantize:
		return MaxDriftQuantize, nil
	case genome_descriptor.DerivationReconstruct:
		return MaxDriftReconstruct, nil
	default:
		return 0, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: unknown derivation method: "+string(m),
			nil,
		)
	}
}

// TolerancePolicy is the signed, per-method drift algebra carried by
// a ProbeBattery. The map keys the five doctrinal DerivationMethods.
// A battery's Validate rejects a policy that omits any method or
// exceeds the doctrinal ceiling.
type TolerancePolicy struct {
	// MaxCapabilityDrift is the per-method cap, in [0, ceiling], where
	// ceiling is the doctrinal MaxDrift* constant for that method. A
	// battery MAY publish a stricter bound (tighter than the ceiling)
	// but MUST NOT publish a looser one.
	//
	// Keys MUST include all five known DerivationMethods. Validate
	// enforces this — missing keys are rejected.
	MaxCapabilityDrift map[genome_descriptor.DerivationMethod]float64 `json:"max_capability_drift"`
}

// DefaultTolerancePolicy returns the policy that pins every method to
// its doctrinal ceiling. Callers who want a stricter policy copy this
// and tighten individual entries.
func DefaultTolerancePolicy() TolerancePolicy {
	return TolerancePolicy{
		MaxCapabilityDrift: map[genome_descriptor.DerivationMethod]float64{
			genome_descriptor.DerivationFineTune:    MaxDriftFineTune,
			genome_descriptor.DerivationDistill:     MaxDriftDistill,
			genome_descriptor.DerivationMerge:       MaxDriftMerge,
			genome_descriptor.DerivationQuantize:    MaxDriftQuantize,
			genome_descriptor.DerivationReconstruct: MaxDriftReconstruct,
		},
	}
}

// Validate enforces: every known DerivationMethod is present; each
// bound is in [0, doctrinalCeiling]; no unknown method keys. A
// battery is forbidden from publishing a looser bound than the
// platform's doctrine.
func (p *TolerancePolicy) Validate() error {
	if p == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: nil tolerance policy",
			nil,
		)
	}
	if p.MaxCapabilityDrift == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: tolerance policy has no method entries",
			nil,
		)
	}
	knownMethods := []genome_descriptor.DerivationMethod{
		genome_descriptor.DerivationFineTune,
		genome_descriptor.DerivationDistill,
		genome_descriptor.DerivationMerge,
		genome_descriptor.DerivationQuantize,
		genome_descriptor.DerivationReconstruct,
	}
	for _, m := range knownMethods {
		v, ok := p.MaxCapabilityDrift[m]
		if !ok {
			return shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"probe_battery: tolerance policy missing method: "+string(m),
				nil,
			)
		}
		ceiling, err := MethodBudget(m)
		if err != nil {
			return err
		}
		if v < 0 {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"probe_battery: tolerance below zero for "+string(m),
				nil,
			)
		}
		if v > ceiling {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"probe_battery: tolerance exceeds doctrinal ceiling for "+string(m),
				nil,
			)
		}
	}
	// No unknown keys.
	known := map[genome_descriptor.DerivationMethod]struct{}{}
	for _, m := range knownMethods {
		known[m] = struct{}{}
	}
	for k := range p.MaxCapabilityDrift {
		if _, ok := known[k]; !ok {
			return shared_errors.Structural(
				shared_errors.CodeFieldValueInvalid,
				"probe_battery: tolerance policy has unknown method: "+string(k),
				nil,
			)
		}
	}
	return nil
}

// ---- continuity outcome algebra --------------------------------------------

// ContinuityOutcome is the structured verdict produced by Compare.
// Outcome is the binary pass/fail; Diagnostics enumerates per-probe
// violations in stable (sorted-by-ProbeID) order for operator use.
type ContinuityOutcome struct {
	// Pass is true iff all three doctrinal invariants hold:
	//   - Every identity probe's response hash is identical.
	//   - Every negative probe's response hash is identical.
	//   - The fraction of drifted capability probes is within the
	//     policy's cap for the declared DerivationMethod.
	Pass bool

	// CapabilityDriftFraction is the computed ratio of capability
	// probes whose response hashes differ, in [0, 1]. Always reported
	// even on Pass so operators can see "we used 40% of our budget".
	CapabilityDriftFraction float64

	// CapabilityDriftBudget is the bound against which
	// CapabilityDriftFraction was compared, copied from the policy.
	CapabilityDriftBudget float64

	// IdentityViolations lists ProbeIDs of identity probes that
	// drifted (non-empty on a failed check).
	IdentityViolations []ProbeID

	// NegativeFlips lists ProbeIDs of negative probes whose response
	// hash changed (non-empty on a failed check).
	NegativeFlips []ProbeID

	// CapabilityDrifts lists ProbeIDs of capability probes that
	// drifted. Informational — these only fail when their count
	// exceeds CapabilityDriftBudget * (#capability probes).
	CapabilityDrifts []ProbeID
}

// Compare evaluates whether child is a legitimate behavioral
// successor of parent under method, using policy's drift budgets.
// Both scorecards MUST have been measured against the SAME battery;
// compare fails if their BatteryMerkleRoots disagree.
//
// The battery argument is supplied so Compare can look up each
// probe's Kind — scorecards carry ProbeIDs and response hashes only.
// The battery is used read-only and is not re-verified here; the
// caller is expected to have Validated + VerifySignatured it
// beforehand.
//
// Compare is pure: no crypto, no signatures, no clock. Given the
// same inputs it returns the same outcome byte-for-byte.
func Compare(
	parent *Scorecard,
	child *Scorecard,
	battery *ProbeBattery,
	method genome_descriptor.DerivationMethod,
	policy TolerancePolicy,
) (ContinuityOutcome, error) {
	if parent == nil || child == nil {
		return ContinuityOutcome{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: compare: nil scorecard",
			nil,
		)
	}
	if battery == nil {
		return ContinuityOutcome{}, shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"probe_battery: compare: nil battery",
			nil,
		)
	}
	budget, ok := policy.MaxCapabilityDrift[method]
	if !ok {
		return ContinuityOutcome{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: compare: policy has no entry for method "+string(method),
			nil,
		)
	}
	ceiling, err := MethodBudget(method)
	if err != nil {
		return ContinuityOutcome{}, err
	}
	if budget > ceiling {
		return ContinuityOutcome{}, shared_errors.Structural(
			shared_errors.CodeFieldValueInvalid,
			"probe_battery: compare: policy bound for "+string(method)+" exceeds doctrinal ceiling",
			nil,
		)
	}
	// Both scorecards must reference the same battery root — otherwise
	// we're comparing apples to oranges.
	if !byteSlicesEqual(parent.BatteryMerkleRoot, child.BatteryMerkleRoot) {
		return ContinuityOutcome{}, shared_errors.Integrity(
			shared_errors.CodeCrossFieldInconsistent,
			"probe_battery: compare: scorecards reference different batteries",
			nil,
		)
	}
	// And both must match the battery's own root.
	if !byteSlicesEqual(parent.BatteryMerkleRoot, battery.MerkleRoot) {
		return ContinuityOutcome{}, shared_errors.Integrity(
			shared_errors.CodeCrossFieldInconsistent,
			"probe_battery: compare: scorecards do not reference provided battery",
			nil,
		)
	}

	// Build lookup tables keyed by ProbeID.
	parentByID := make(map[ProbeID]ScoreEntry, len(parent.Entries))
	for i := range parent.Entries {
		parentByID[parent.Entries[i].ProbeID] = parent.Entries[i]
	}
	childByID := make(map[ProbeID]ScoreEntry, len(child.Entries))
	for i := range child.Entries {
		childByID[child.Entries[i].ProbeID] = child.Entries[i]
	}
	kindByID := make(map[ProbeID]ProbeKind, len(battery.Probes))
	for i := range battery.Probes {
		kindByID[battery.Probes[i].ID] = battery.Probes[i].Kind
	}

	// Both scorecards must cover exactly the battery's probes. A
	// scorecard that skips a probe has an undefined result for it;
	// one with an extra probe has a claim the battery does not
	// authorize.
	if len(parent.Entries) != len(battery.Probes) {
		return ContinuityOutcome{}, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"probe_battery: compare: parent scorecard entry count differs from battery probe count",
			nil,
		)
	}
	if len(child.Entries) != len(battery.Probes) {
		return ContinuityOutcome{}, shared_errors.Structural(
			shared_errors.CodeCrossFieldInconsistent,
			"probe_battery: compare: child scorecard entry count differs from battery probe count",
			nil,
		)
	}

	out := ContinuityOutcome{
		CapabilityDriftBudget: budget,
	}
	var capabilityTotal, capabilityDrift int
	// Walk battery in deterministic order so Diagnostics are stable.
	probes := append([]Probe(nil), battery.Probes...)
	sortProbesByID(probes)
	for i := range probes {
		pid := probes[i].ID
		parentEntry, pOK := parentByID[pid]
		childEntry, cOK := childByID[pid]
		if !pOK || !cOK {
			return ContinuityOutcome{}, shared_errors.Structural(
				shared_errors.CodeCrossFieldInconsistent,
				"probe_battery: compare: scorecard missing entry for probe "+pid.String(),
				nil,
			)
		}
		kind := probes[i].Kind
		same := byteSlicesEqual(parentEntry.ResponseHash, childEntry.ResponseHash)
		switch kind {
		case ProbeKindIdentity:
			if !same {
				out.IdentityViolations = append(out.IdentityViolations, pid)
			}
		case ProbeKindNegative:
			if !same {
				out.NegativeFlips = append(out.NegativeFlips, pid)
			}
		case ProbeKindCapability:
			capabilityTotal++
			if !same {
				capabilityDrift++
				out.CapabilityDrifts = append(out.CapabilityDrifts, pid)
			}
		}
	}
	if capabilityTotal > 0 {
		out.CapabilityDriftFraction = float64(capabilityDrift) / float64(capabilityTotal)
	}
	out.Pass = len(out.IdentityViolations) == 0 &&
		len(out.NegativeFlips) == 0 &&
		out.CapabilityDriftFraction <= budget
	return out, nil
}

// byteSlicesEqual is a small equality helper. Not using crypto-
// constant-time here: scorecard roots and response hashes are public
// information once signed, and constant-time equality has no
// adversary-exploitable information leak in this code path.
func byteSlicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
