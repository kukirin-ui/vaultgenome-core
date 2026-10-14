// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package doctrine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/validation_result"
	"github.com/vault-genome/vaultgenome-core/internal/recvvalidator"
	"github.com/vault-genome/vaultgenome-core/internal/validation/service"
	"github.com/vault-genome/vaultgenome-core/internal/vault/orchestration"
)

// TestInvariant_01_VaultIsAuthority asserts that every authority DECISION
// — trust admission, session issuance, disclosure authorization, release
// — is constructed by a package under /internal/vault. Put differently:
// no non-vault /internal/ package may reach INTO a vault decision-maker
// package. Outside consumers interact with vault decisions only through
// their signed contract artifacts (verify signatures, compare hashes).
//
// Vault sub-packages come in two flavors:
//
//   - AUTHORITY-DECISION packages — they construct signed artifacts that
//     are authority records. These are forbidden from being imported
//     outside /internal/vault/: disclosure, session, trust, incident,
//     intake, orchestration, policy, storage.
//
//   - SHARED KEY-MANAGEMENT surface — /internal/vault/keys is the
//     interface layer for Signer / Verifier / Sealer / Resolver types
//     that the contracts' Sign/VerifySignature methods depend on. It
//     does not itself construct authority decisions. It is explicitly
//     permitted to be imported outside vault; moving it out of
//     /internal/vault/ is a V2 refactor, not a doctrine violation
//     today.
//
// Strategy — AST-level import scan of every non-test .go file:
//
//  1. Walk /internal/, skip _test.go files and skip anything under
//     /internal/vault/ (those are the authority layer itself).
//  2. Parse each file's import block; flag any import path that begins
//     with a forbidden vault-subpackage prefix.
//
// Allowlist: /internal/integration/ is permitted to import any vault
// package because it is the end-to-end wiring layer. Adding any other
// allowlisted path requires pointing at a specific doctrinal paragraph
// that justifies the crossing.
func TestInvariant_01_VaultIsAuthority(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	internal := filepath.Join(root, "internal")

	// Authority-decision packages — non-vault callers must not import any
	// of these. Every path is the canonical module prefix + subpackage.
	const vaultMod = "github.com/vault-genome/vaultgenome-core/internal/vault/"
	forbiddenVaultImports := []string{
		vaultMod + "disclosure",
		vaultMod + "session",
		vaultMod + "trust",
		vaultMod + "incident",
		vaultMod + "intake",
		vaultMod + "orchestration",
		vaultMod + "policy",
		vaultMod + "storage",
	}
	// vaultCrossingAllowedPrefixes are paths permitted to cross even the
	// authority-decision boundary. Today only /internal/integration/.
	vaultCrossingAllowedPrefixes := []string{
		"internal/integration/",
	}

	var violations []string
	walkErr := filepath.WalkDir(internal, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		// Skip files inside /internal/vault/ — they ARE the authority layer.
		if strings.HasPrefix(relSlash, "internal/vault/") {
			return nil
		}
		// Skip the explicit allowlist.
		for _, pfx := range vaultCrossingAllowedPrefixes {
			if strings.HasPrefix(relSlash, pfx) {
				return nil
			}
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", relSlash, parseErr)
		}
		for _, imp := range f.Imports {
			raw := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenVaultImports {
				// Exact match or a nested package under the forbidden prefix.
				if raw == bad || strings.HasPrefix(raw, bad+"/") {
					pos := fset.Position(imp.Pos())
					violations = append(violations,
						relSlash+":"+strconv.Itoa(pos.Line)+" — imports authority-decision package "+raw)
					break
				}
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking internal/: %v", walkErr)
	}

	if len(violations) > 0 {
		t.Errorf("doctrine invariant 01 (vault-is-authority) violated by %d import(s):",
			len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
		t.Errorf("non-vault packages must consume authority artifacts via /internal/contracts/; " +
			"crossing into a vault authority-decision package requires amending the " +
			"allowlist with a doctrine-paragraph rationale")
	}
}

// TestInvariant_02_TrustIsGateNotLog asserts that a deny or restrict
// AttestationResult blocks the pipeline at StateTrust — not merely that
// the deny is recorded in audit. Specifically: from StateTrust, a deny
// or restrict trigger must NOT be capable of reaching StateSession (nor
// any state downstream of StateSession) within a single transition.
//
// The test reads orchestration.TransitionTable — the single source of
// truth for legal progression in the nine-stage flow — and asserts the
// trust-as-gate property against it. A future edit to the transition
// table that loosens this property (e.g., introducing a "soft-deny"
// that still progresses to session) trips this test.
func TestInvariant_02_TrustIsGateNotLog(t *testing.T) {
	t.Parallel()
	// Collect every transition out of StateTrust, grouped by trigger.
	byTrigger := map[string][]orchestration.State{}
	for _, tr := range orchestration.TransitionTable {
		if tr.From != orchestration.StateTrust {
			continue
		}
		byTrigger[tr.Trigger] = append(byTrigger[tr.Trigger], tr.To)
	}

	// Must have the three canonical trust triggers present.
	for _, trigger := range []string{"attestation.allow", "attestation.deny", "attestation.restrict"} {
		require.Containsf(t, byTrigger, trigger,
			"transition table must define StateTrust+%q (trust is a governed gate, not silent)", trigger)
	}

	// Allow moves to session — any other target under this trigger would
	// be a compliance-gate bypass because it would skip session issuance.
	require.Equalf(t, []orchestration.State{orchestration.StateSession}, byTrigger["attestation.allow"],
		"attestation.allow must route ONLY to StateSession; saw %v", byTrigger["attestation.allow"])

	// Deny and restrict must NEVER route to StateSession or to any state
	// downstream of session — every such target would let a non-admitted
	// flow reach genome access.
	gatedTargets := map[orchestration.State]struct{}{
		orchestration.StateSession:           {},
		orchestration.StateDisclosure:        {},
		orchestration.StateExternalCompute:   {},
		orchestration.StateReturn:            {},
		orchestration.StateValidation:        {},
		orchestration.StateAudit:             {},
		orchestration.StateReleaseAuthorized: {},
	}
	for _, gatingTrigger := range []string{"attestation.deny", "attestation.restrict"} {
		for _, target := range byTrigger[gatingTrigger] {
			_, gated := gatedTargets[target]
			require.Falsef(t, gated,
				"trigger %q must not reach %s — trust is a gate, deny/restrict short-circuits the pipeline",
				gatingTrigger, target)
		}
	}

	// There must be no transition table entry that reaches StateSession from
	// anywhere OTHER than StateTrust. Otherwise the gate has a side door.
	for _, tr := range orchestration.TransitionTable {
		if tr.To == orchestration.StateSession {
			require.Equalf(t, orchestration.StateTrust, tr.From,
				"StateSession must be reachable only from StateTrust; saw transition from %s", tr.From)
		}
	}
}

// TestInvariant_03_SessionsMandatory asserts that no code path touches
// genome components without a valid SessionObject. Enforcement has two
// complementary layers:
//
//  1. State-machine layer — StateDisclosure (the first state in which a
//     genome component is touched at all) can be reached only from
//     StateSession. Enforced against orchestration.TransitionTable.
//
//  2. Contract layer — every artifact that rides the release-side flow
//     (DisclosureMessage, ReconstructionJobManifest, ContinuityProof,
//     ReleaseDecision) carries a required SessionID field. Without this,
//     a post-hoc artifact could be presented without a binding session.
//     Enforced via AST scan of /internal/contracts/.
func TestInvariant_03_SessionsMandatory(t *testing.T) {
	t.Parallel()
	// Layer 1 — state machine.
	for _, tr := range orchestration.TransitionTable {
		if tr.To == orchestration.StateDisclosure {
			require.Equalf(t, orchestration.StateSession, tr.From,
				"StateDisclosure must be reachable only from StateSession; "+
					"saw transition (%s → disclosure) under trigger %q",
				tr.From, tr.Trigger)
		}
	}

	// Layer 2 — contract SessionID fields.
	// Map: contract-package name → exported struct type the SessionID lives on.
	sessionBoundContracts := map[string]string{
		"disclosure_message":          "DisclosureMessage",
		"reconstruction_job_manifest": "ReconstructionJobManifest",
		"release_decision":            "ReleaseDecision",
	}

	root := locateModuleRoot(t)
	for pkg, typeName := range sessionBoundContracts {
		pkgDir := filepath.Join(root, "internal", "contracts", pkg)
		has := structHasFieldOfType(t, pkgDir, typeName, "SessionID")
		require.Truef(t, has,
			"contract %s.%s must declare a SessionID field — sessions are mandatory", pkg, typeName)
	}
}

// TestInvariant_04_DisclosureIsStaged asserts the structural preconditions
// for staged disclosure. The behavioral property (monotonic sequence with
// no gaps, one DisclosureMessage per emitted component) is exercised in
// /internal/vault/disclosure/staged_test.go and sequencer_test.go; this
// doctrine test guards the static shape those behavioral tests depend on.
//
// Properties asserted here:
//
//  1. DisclosureMessage carries a SequenceIndex uint32 field — every
//     emission is ordered. A uint64 or missing field would let the
//     protocol silently drop its "one at a time, in order" promise.
//  2. DisclosureMessage carries a ComponentID field — every emission
//     names EXACTLY ONE component. A `ComponentIDs []ids.ComponentID`
//     would let a single message authorize a bulk disclosure, violating
//     the staged rule.
//  3. StagedIssuer.Emit returns exactly one DisclosureMessage (not a
//     slice). Checked as part of the AST scan of issuer.go.
func TestInvariant_04_DisclosureIsStaged(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	dmDir := filepath.Join(root, "internal/contracts/disclosure_message")

	// 1 & 2 — structural shape of DisclosureMessage.
	seqFieldType := structFieldType(t, dmDir, "DisclosureMessage", "SequenceIndex")
	require.Equalf(t, "uint32", seqFieldType,
		"DisclosureMessage.SequenceIndex must be uint32; saw %q", seqFieldType)

	compFieldType := structFieldType(t, dmDir, "DisclosureMessage", "ComponentID")
	require.NotEmpty(t, compFieldType,
		"DisclosureMessage must declare a ComponentID field — every emission names one component")
	require.NotContainsf(t, compFieldType, "[]",
		"DisclosureMessage.ComponentID must be scalar, not slice; saw %q (bulk disclosure is not staged)",
		compFieldType)

	// Guard against any plausible bulk-disclosure fields creeping in.
	for _, bulkField := range []string{"ComponentIDs", "Components", "Payloads"} {
		require.Emptyf(t, structFieldType(t, dmDir, "DisclosureMessage", bulkField),
			"DisclosureMessage must not carry bulk field %q — staged disclosure is strictly per-component",
			bulkField)
	}

	// 3 — StagedIssuer.Emit signature check.
	// StagedIssuer and its Emit method live in staged.go (issuer.go holds
	// the unrelated ContinuityProof Issuer). We parse the file and locate
	// the Emit method, then assert it returns a
	// disclosure_message.DisclosureMessage value (not a slice). The return
	// form is *disclosure_message.DisclosureMessage (pointer) — the
	// per-emission promise is satisfied as long as it is NOT a slice.
	stagedPath := filepath.Join(root, "internal/vault/disclosure/staged.go")
	emitRet := methodReturnTypes(t, stagedPath, "StagedIssuer", "Emit")
	require.NotEmptyf(t, emitRet,
		"StagedIssuer.Emit not found — disclosure is no longer staged through a single-emission method")
	sawMessage := false
	for _, rt := range emitRet {
		require.NotContainsf(t, rt, "[]",
			"StagedIssuer.Emit must not return a slice; saw return type %q — staged disclosure is per-component",
			rt)
		if strings.HasSuffix(rt, "DisclosureMessage") {
			sawMessage = true
		}
	}
	require.Truef(t, sawMessage,
		"StagedIssuer.Emit must return a disclosure_message.DisclosureMessage; saw returns %v", emitRet)
}

// TestInvariant_05_ValidationPrecedesRelease asserts that a
// ReleaseDecision cannot be constructed without a preceding
// ValidationResult. Enforcement has two layers:
//
//  1. State machine — transitions INTO StateRelease may come only from
//     StateValidation (happy path) or StateTrust (fast-fail when trust
//     is denied or restricted, at which point validation is moot because
//     there is nothing to validate). No other predecessor is legal.
//
//  2. Contract — ReleaseDecision carries a required
//     ValidationResultID field binding the decision to a specific
//     validation verdict. A ReleaseDecision that omits this field can
//     not be the terminal authority artifact of a governed flow.
func TestInvariant_05_ValidationPrecedesRelease(t *testing.T) {
	t.Parallel()
	// Layer 1 — predecessors of StateRelease.
	allowedPredecessors := map[orchestration.State]struct{}{
		orchestration.StateValidation: {},
		orchestration.StateTrust:      {},
	}
	sawValidation := false
	for _, tr := range orchestration.TransitionTable {
		if tr.To != orchestration.StateRelease {
			continue
		}
		_, ok := allowedPredecessors[tr.From]
		require.Truef(t, ok,
			"StateRelease may be entered only from StateValidation or StateTrust; "+
				"saw transition (%s → release) under trigger %q",
			tr.From, tr.Trigger)
		if tr.From == orchestration.StateValidation {
			sawValidation = true
		}
	}
	require.Truef(t, sawValidation,
		"transition table must include a StateValidation → StateRelease arc; "+
			"happy-path release cannot skip validation")

	// Layer 2 — contract shape.
	root := locateModuleRoot(t)
	rdDir := filepath.Join(root, "internal/contracts/release_decision")

	vrType := structFieldType(t, rdDir, "ReleaseDecision", "ValidationResultID")
	require.NotEmptyf(t, vrType,
		"ReleaseDecision must declare a ValidationResultID field — release binds to a validation verdict")
	require.Containsf(t, vrType, "ValidationResultID",
		"ReleaseDecision.ValidationResultID must be typed as ids.ValidationResultID; saw %q", vrType)
}

// TestInvariant_06_OperationalVetoes asserts the doctrine that an
// operational-fail dimension verdict FORCES ValidationResult.OverallVerdict
// = fail, regardless of semantic and behavioral scores.
//
// Enforcement has two layers:
//
//  1. Dimension layer: /internal/validation/operational.Run is binary —
//     Threshold=1.0, any failing sub-check → VerdictFail. Tested in
//     that package's own tests.
//
//  2. Aggregation layer: /internal/validation/service.Aggregate must
//     short-circuit on operational-fail per
//     docs/doctrine/validation-thresholds.md §5. Iteration 2 lands that
//     function; this test now pins it DIRECTLY against the production
//     aggregator, so a regression there trips CI immediately.
//
// The referenceAggregate function below remains as an independent
// specification of the §5 rule. TestInvariant_06c cross-checks that
// the production aggregator agrees with the reference across a
// multi-dimensional truth table — drift between the two is a doctrine
// break regardless of which side is "wrong".
//
// The inverse case (operational-pass does NOT imply OverallVerdict=pass
// — the other two dimensions must also pass) is asserted at the end as
// a sanity guard against aggregator regressions.
func TestInvariant_06_OperationalVetoes(t *testing.T) {
	t.Parallel()
	op := func(v validation_result.Verdict, score float64) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: v, Score: score, Threshold: 1.0}
	}
	sem := func(v validation_result.Verdict, score float64) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: v, Score: score, Threshold: 1.0}
	}
	beh := func(v validation_result.Verdict, score float64) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: v, Score: score, Threshold: 0.95}
	}

	// Core veto cases — operational is Fail. Every combination of
	// semantic/behavioral MUST produce OverallVerdict=fail.
	table := []struct {
		name string
		semV validation_result.Verdict
		behV validation_result.Verdict
	}{
		{"sem_pass/beh_pass", validation_result.VerdictPass, validation_result.VerdictPass},
		{"sem_fail/beh_pass", validation_result.VerdictFail, validation_result.VerdictPass},
		{"sem_pass/beh_cond", validation_result.VerdictPass, validation_result.VerdictConditionalFail},
		{"sem_cond/beh_pass", validation_result.VerdictConditionalFail, validation_result.VerdictPass},
		{"all_fail", validation_result.VerdictFail, validation_result.VerdictFail},
	}
	for _, tc := range table {
		t.Run("op_fail/"+tc.name, func(t *testing.T) {
			got := service.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: op(validation_result.VerdictFail, 0.5),
				validation_result.DimensionSemantic:    sem(tc.semV, 1.0),
				validation_result.DimensionBehavioral:  beh(tc.behV, 0.97),
			})
			require.Equalf(t, validation_result.VerdictFail, got,
				"operational-fail must force OverallVerdict=fail, saw %s (sem=%s, beh=%s)",
				got, tc.semV, tc.behV)
		})
	}

	// Inverse sanity: operational-pass does NOT rubber-stamp the result.
	// Behavioral-fail with operational-pass must still be OverallVerdict=fail.
	inverse := service.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
		validation_result.DimensionOperational: op(validation_result.VerdictPass, 1.0),
		validation_result.DimensionSemantic:    sem(validation_result.VerdictPass, 1.0),
		validation_result.DimensionBehavioral:  beh(validation_result.VerdictFail, 0.80),
	})
	require.Equal(t, validation_result.VerdictFail, inverse,
		"behavioral-fail must produce OverallVerdict=fail even with operational-pass")
}

// TestInvariant_06c_AggregatorMatchesReference cross-checks the
// production service.Aggregate against the referenceAggregate rule
// encoded below. Any divergence is a doctrine regression: either the
// reference drifted from §5, or the production code drifted from the
// reference. Both are bugs we want CI to catch.
//
// The truth table exercises every (op, sem, beh) ∈ {pass, fail,
// conditional_fail}³ combination — 27 cases in total. ConditionalFail
// on operational is included to pin the defensive mapping that both
// implementations apply.
func TestInvariant_06c_AggregatorMatchesReference(t *testing.T) {
	t.Parallel()
	dv := func(v validation_result.Verdict) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: v, Score: 1.0, Threshold: 1.0}
	}
	verdicts := []validation_result.Verdict{
		validation_result.VerdictPass,
		validation_result.VerdictFail,
		validation_result.VerdictConditionalFail,
	}
	for _, o := range verdicts {
		for _, s := range verdicts {
			for _, b := range verdicts {
				dims := map[validation_result.Dimension]validation_result.DimensionVerdict{
					validation_result.DimensionOperational: dv(o),
					validation_result.DimensionSemantic:    dv(s),
					validation_result.DimensionBehavioral:  dv(b),
				}
				ref := referenceAggregate(dims)
				prod := service.Aggregate(dims)
				require.Equalf(t, ref, prod,
					"production aggregator disagrees with reference on op=%s sem=%s beh=%s",
					o, s, b)
			}
		}
	}
}

// referenceAggregate encodes the aggregation rule from
// docs/doctrine/validation-thresholds.md §5 plus the doctrine-consistent
// defensive mappings that §2.3, §4.3, and §9(4) require. It is the
// contract that /internal/validation/service.Aggregate must satisfy and
// is stored in the doctrine test so the rule is executable and
// versioned alongside the invariant that depends on it.
//
//   - Operational Fail → OverallVerdict Fail (short-circuit, §5).
//   - Operational ConditionalFail → Fail (defensive; operational is
//     binary by §4.3, a producer emitting conditional is buggy).
//   - Operational Pass + Sem Pass + Beh Pass → Pass (§5).
//   - Operational Pass + any other-dim Fail → Fail (§5).
//   - Operational Pass + Sem ConditionalFail → Fail (defensive; semantic
//     has no conditional band in MVP per §2.3).
//   - Operational Pass + Sem Pass + Beh ConditionalFail → ConditionalFail (§5).
//   - Missing operational dimension → Fail (§9(4): un-evidenced
//     decisions are not governed decisions; the veto anchor MUST be
//     present).
func referenceAggregate(dims map[validation_result.Dimension]validation_result.DimensionVerdict) validation_result.Verdict {
	op, hasOp := dims[validation_result.DimensionOperational]
	if !hasOp {
		return validation_result.VerdictFail
	}
	if op.Verdict == validation_result.VerdictFail || op.Verdict == validation_result.VerdictConditionalFail {
		return validation_result.VerdictFail
	}
	if op.Verdict != validation_result.VerdictPass {
		return validation_result.VerdictFail
	}
	sem, hasSem := dims[validation_result.DimensionSemantic]
	beh, hasBeh := dims[validation_result.DimensionBehavioral]
	if !hasSem || !hasBeh {
		return validation_result.VerdictFail
	}
	if sem.Verdict == validation_result.VerdictFail || beh.Verdict == validation_result.VerdictFail {
		return validation_result.VerdictFail
	}
	if sem.Verdict == validation_result.VerdictConditionalFail {
		return validation_result.VerdictFail
	}
	if sem.Verdict != validation_result.VerdictPass {
		return validation_result.VerdictFail
	}
	switch beh.Verdict {
	case validation_result.VerdictPass:
		return validation_result.VerdictPass
	case validation_result.VerdictConditionalFail:
		return validation_result.VerdictConditionalFail
	default:
		return validation_result.VerdictFail
	}
}

// TestInvariant_06b_OperationalVetoes_ReceiveMirror is the receive-side
// mirror of Invariant #6. The release-side invariant pins the §5 rule
// via referenceAggregate; this one pins the receive-side rule against
// the PRODUCTION aggregator — /internal/recvvalidator.Aggregate — so
// regressions there trip CI immediately.
//
// Receive-side doctrine (operational-only today, forward-compatible):
//
//  1. Operational missing → Fail (there is no veto dimension to anchor
//     on, so the aggregator must refuse).
//  2. Operational = Fail or ConditionalFail → Fail (veto; ConditionalFail
//     is defensively mapped since operational is binary by contract).
//  3. Operational = Pass + no other dim → Pass (Stage G today).
//  4. Operational = Pass + any other-dim Fail → Fail (forward-compat
//     with future semantic / behavioral sub-dimensions).
//  5. Operational = Pass + any other-dim ConditionalFail and no Fail
//     → ConditionalFail (never silently promotes to Pass).
//  6. Operational = Pass + all other dims Pass → Pass.
//  7. Unknown verdict on a non-operational dimension → Fail (defensive).
//
// Rules (4)–(7) are asserted even though Stage G emits only operational
// today, so that the day a release of semantic/behavioral lands on the
// receive side (Iteration 2+), the aggregator is already constrained.
func TestInvariant_06b_OperationalVetoes_ReceiveMirror(t *testing.T) {
	t.Parallel()
	dv := func(v validation_result.Verdict) validation_result.DimensionVerdict {
		return validation_result.DimensionVerdict{Verdict: v, Score: 1.0, Threshold: 1.0}
	}

	// (1) Operational missing.
	require.Equal(t, validation_result.VerdictFail,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{}),
		"operational-missing must fail: no veto dim to anchor on")
	require.Equal(t, validation_result.VerdictFail,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionSemantic: dv(validation_result.VerdictPass),
		}),
		"semantic-only (no operational) must still fail")

	// (2) Operational Fail / ConditionalFail — veto with any other combo.
	vetoTable := []struct {
		name string
		op   validation_result.Verdict
		semV validation_result.Verdict
		behV validation_result.Verdict
	}{
		{"op_fail/sem_pass/beh_pass", validation_result.VerdictFail, validation_result.VerdictPass, validation_result.VerdictPass},
		{"op_fail/sem_fail/beh_pass", validation_result.VerdictFail, validation_result.VerdictFail, validation_result.VerdictPass},
		{"op_fail/sem_cond/beh_pass", validation_result.VerdictFail, validation_result.VerdictConditionalFail, validation_result.VerdictPass},
		{"op_cond/sem_pass/beh_pass", validation_result.VerdictConditionalFail, validation_result.VerdictPass, validation_result.VerdictPass},
	}
	for _, tc := range vetoTable {
		t.Run("veto/"+tc.name, func(t *testing.T) {
			got := recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
				validation_result.DimensionOperational: dv(tc.op),
				validation_result.DimensionSemantic:    dv(tc.semV),
				validation_result.DimensionBehavioral:  dv(tc.behV),
			})
			require.Equalf(t, validation_result.VerdictFail, got,
				"operational=%s must force Fail regardless of sem=%s, beh=%s",
				tc.op, tc.semV, tc.behV)
		})
	}

	// (3) Operational Pass alone.
	require.Equal(t, validation_result.VerdictPass,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: dv(validation_result.VerdictPass),
		}),
		"operational=Pass with no other dims must yield Pass (Stage G today)")

	// (4) Operational Pass + non-op Fail.
	require.Equal(t, validation_result.VerdictFail,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: dv(validation_result.VerdictPass),
			validation_result.DimensionSemantic:    dv(validation_result.VerdictFail),
		}),
		"future sem=Fail must propagate even with operational=Pass")

	// (5) Operational Pass + non-op ConditionalFail → ConditionalFail.
	require.Equal(t, validation_result.VerdictConditionalFail,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: dv(validation_result.VerdictPass),
			validation_result.DimensionBehavioral:  dv(validation_result.VerdictConditionalFail),
		}),
		"non-op conditional must lift overall to ConditionalFail, never to Pass")

	// (6) All dims Pass → Pass.
	require.Equal(t, validation_result.VerdictPass,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: dv(validation_result.VerdictPass),
			validation_result.DimensionSemantic:    dv(validation_result.VerdictPass),
			validation_result.DimensionBehavioral:  dv(validation_result.VerdictPass),
		}),
		"all-Pass aggregation must yield Pass")

	// (7) Unknown verdict on a non-operational dim — defensive Fail.
	require.Equal(t, validation_result.VerdictFail,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: dv(validation_result.VerdictPass),
			validation_result.DimensionSemantic: {
				Verdict:   validation_result.Verdict("UnknownFutureState"),
				Score:     1.0,
				Threshold: 1.0,
			},
		}),
		"unrecognised producer must be treated as Fail; no silent promotion")

	// Fail-dominates-conditional: ordering must not cause the weaker
	// signal to win over a Fail elsewhere.
	require.Equal(t, validation_result.VerdictFail,
		recvvalidator.Aggregate(map[validation_result.Dimension]validation_result.DimensionVerdict{
			validation_result.DimensionOperational: dv(validation_result.VerdictPass),
			validation_result.DimensionSemantic:    dv(validation_result.VerdictFail),
			validation_result.DimensionBehavioral:  dv(validation_result.VerdictConditionalFail),
		}),
		"hardest-signal-wins — Fail dominates ConditionalFail even when ordering varies")
}

// forbiddenWriteSelectors lists standard-library write sinks that, if
// invoked from a file outside allowedWriteSinkPrefixes, constitute a
// potential raw-export violation.
//
// Matching is SYNTACTIC: we recognise `pkg.Func(...)` where `pkg` is the
// import's default name. Renamed imports and dot-imports are out of
// scope for this test — they are a review concern, and reviewers have a
// low bar to reject them in packages that touch genome plaintext.
//
// Inspired by Freeze #6 in docs/doctrine/open-decisions-resolved.md:
// "No direct raw AI Genome export path. None."
var forbiddenWriteSelectors = map[string]struct{}{
	"os.WriteFile":     {},
	"os.Create":        {},
	"os.CreateTemp":    {},
	"os.OpenFile":      {},
	"ioutil.WriteFile": {},
	"io.Copy":          {},
	"io.CopyBuffer":    {},
}

// allowedWriteSinkPrefixes are the /internal/ subtrees permitted to
// invoke any selector in forbiddenWriteSelectors. They justify it on
// the grounds that what they write is either:
//
//   - sealed ciphertext (vault/storage — the persistence layer for
//     vault-owned state, including sealed genome components), or
//   - audit records that are not genome material (audit/store), or
//   - hardware character-device handles and the kernel's configfs-tsm
//     report entries for the TEE producer (shared/tee — /dev/nsm,
//     /dev/sev-guest, /dev/sgx_enclave, /sys/kernel/config/tsm/report;
//     these never carry plaintext genome material in either direction,
//     they exchange attestation challenges and quotes only — see
//     00_TEE_Adapter_Doctrine.md §2 "device-file boundary"), and the
//     SEV-SNP verifier's on-disk cache of AMD VCEK certificates (public,
//     and re-verified against the pinned AMD chain on every use), or
//   - client-side restore materialisation consumed by `cmd/acpctl`
//     on the operator's machine (`contentdir` for arbitrary directory
//     trees — LoRA adapters, fine-tune checkpoints, RAG corpora;
//     `ollama` for the OLLAMA_MODELS on-disk layout). At restore
//     time the bundle has already been unsealed by the sealer; what
//     these packages do is materialise the plaintext bytes back into
//     a target directory the operator owns. Both packages are
//     consumed only by acpctl (verified in cmd/acpctl/genome.go) and
//     are kept out of the sagvd authority binary and the acp-compute
//     worker binary by Invariants #01 and #02 (vault/worker import
//     graph). The unsealing itself remains the sealer's responsibility;
//     the materialisation step is a client-side concern.
//   - the tar extraction step shared by those restore packages
//     (shared/safetar). It is not a new export surface: they delegate
//     their extraction to it so the confinement logic (os.Root; no "..",
//     absolute or symlink escape) exists once.
//     TestInvariant_07_SafetarOnlyServesRestore pins its importers, so the
//     allowance cannot be reused by any other package.
//   - the v3 genome bundle format (genome/bundle). It writes sealed
//     ciphertext only — the payload leaves it AES-256-GCM-sealed under a
//     DEK that is not in the file (ADR 0011) — and its io.Copy calls feed
//     hash functions.
//   - the all-or-nothing materialisation of an opened genome
//     (genome/restore): by acpctl on the operator's machine, and by
//     acp-bootstrap inside the destination TEE the operator's policy
//     released the genome's key to (ADR 0009, 0010, 0011). The payload
//     reaching it has been authenticated segment by segment under that
//     key; it extracts into a staging directory inside the target, checks
//     the tree against the sealed snapshot, and only then moves it into
//     place. TestInvariant_07c_AuthorityLinksNoMaterialisation keeps it —
//     and safetar — out of the sagvd authority and the acp-compute worker.
//   - restore receipts (genome/receipt): public statements — digests,
//     identifiers and TEE Evidence — that carry no genome material.
//   - the sentinel's outbox (genome/sentinel, ADR 0012): escrow envelopes —
//     a genome key encapsulated to the release authority, ciphertext to
//     everyone else — and signed seal records, heartbeats and compromise
//     reports, which are public statements of digests, generations and
//     times. The genomes it seals are written by genome/bundle, sealed; its
//     io.Copy feeds tripwire hashes. It never materialises an opened genome.
//
// Anything outside these prefixes must route writes through the sealer
// in /internal/vault/disclosure or through one of the allowlisted
// packages above. Expanding this list is a review-visible decision.
var allowedWriteSinkPrefixes = []string{
	"internal/vault/storage/",
	"internal/audit/store/",
	"internal/shared/tee/",
	"internal/contentdir/",      // client-side restore: directory-tree materialisation
	"internal/ollama/",          // client-side restore: OLLAMA_MODELS materialisation
	"internal/shared/safetar/",  // extraction step of the restore packages
	"internal/genome/bundle/",   // sealed ciphertext only
	"internal/genome/restore/",  // materialisation of an authenticated, opened genome
	"internal/genome/receipt/",  // restore receipts: public, no genome material
	"internal/genome/sentinel/", // outbox: escrow envelopes (ciphertext) and signed records
}

// safetarImporters are the only packages permitted to import
// internal/shared/safetar; see allowedWriteSinkPrefixes.
var safetarImporters = []string{
	"internal/contentdir/",
	"internal/ollama/",
	"internal/genome/restore/",
}

// materialisingPackages put genome plaintext on disk. Only the binaries
// in materialisingBinaries may link them.
var materialisingPackages = []string{
	"github.com/vault-genome/vaultgenome-core/internal/shared/safetar",
	"github.com/vault-genome/vaultgenome-core/internal/genome/restore",
	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/restorer",
}

// materialisingBinaries: acpctl restores on the operator's machine with
// the operator's key file; acp-bootstrap restores inside the attested
// destination the key was released to. The sagvd authority releases keys
// and confirms restores from receipts; it never holds a genome's
// plaintext, so it must not even link the code that writes one.
var materialisingBinaries = map[string]bool{
	"./cmd/acpctl":        true,
	"./cmd/acp-bootstrap": true,
}

// TestInvariant_07_NoRawExport asserts there is no code path under
// /internal/ that writes unsealed AI Genome material to any sink other
// than via the GCM sealing function inside /internal/vault/disclosure.
//
// Strategy — AST-level static audit of every non-test .go file:
//
//  1. Walk /internal/ and skip _test.go files (tests may write fixtures
//     freely; they are not production code paths).
//  2. For each file NOT under an allowedWriteSinkPrefixes entry, parse
//     its AST and flag any call whose SelectorExpr matches a
//     forbiddenWriteSelectors key.
//  3. Collect every hit and fail the test with a human-readable report.
//
// This is a syntactic check — it proves the absence of easy-to-spot
// exfiltration, not the absence of all exfiltration. Any renaming or
// obfuscation would show up in review. The stronger property here is
// that a future PR cannot accidentally introduce a well-known write
// sink outside the allowlist without tripping CI.
//
// If a new file legitimately needs a write sink, the reviewer's choice
// is: (a) move the file under an allowlisted directory, or (b) extend
// allowedWriteSinkPrefixes in a separate commit with a rationale
// pointing at a specific patent / doctrinal paragraph.
func TestInvariant_07_NoRawExport(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	internal := filepath.Join(root, "internal")

	var violations []string
	walkErr := filepath.WalkDir(internal, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if isAllowlistedSinkPath(rel) {
			return nil
		}
		violations = append(violations, scanForRawSinks(t, path, rel)...)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking internal/: %v", walkErr)
	}

	if len(violations) > 0 {
		t.Errorf("doctrine invariant 07 (no-raw-export) violated by %d call site(s):",
			len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
		t.Errorf("if the write is legitimate, either place the file under one of %v"+
			" or extend allowedWriteSinkPrefixes with a doctrine-paragraph rationale",
			allowedWriteSinkPrefixes)
	}
}

// TestInvariant_07_SafetarOnlyServesRestore keeps the write-sink allowance
// granted to internal/shared/safetar from becoming a general-purpose raw
// export path: across the whole module, only the two client-side restore
// packages may import it. An import from anywhere else — the sagvd
// authority, the acp-compute worker, any vault package — fails here.
func TestInvariant_07_SafetarOnlyServesRestore(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	const safetarPath = "github.com/vault-genome/vaultgenome-core/internal/shared/safetar"

	var offenders []string
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil || p != safetarPath {
				continue
			}
			allowed := false
			for _, prefix := range safetarImporters {
				if strings.HasPrefix(rel, prefix) {
					allowed = true
				}
			}
			if !allowed {
				offenders = append(offenders, rel)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking module: %v", walkErr)
	}
	if len(offenders) > 0 {
		t.Errorf("internal/shared/safetar imported outside %v: %v", safetarImporters, offenders)
	}
}

// TestInvariant_07c_AuthorityLinksNoMaterialisation checks, over the
// real link graph (go list -deps), that no binary other than acpctl and
// acp-bootstrap links a package that writes genome plaintext to disk.
func TestInvariant_07c_AuthorityLinksNoMaterialisation(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatalf("read cmd/: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		bin := "./cmd/" + e.Name()
		cmd := exec.Command("go", "list", "-deps", bin)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", bin, err)
		}
		checked++
		deps := strings.Fields(string(out))
		for _, pkg := range materialisingPackages {
			if slices.Contains(deps, pkg) && !materialisingBinaries[bin] {
				t.Errorf("%s links %s; only %v may put genome plaintext on disk", bin, pkg, materialisingBinaries)
			}
		}
	}
	if checked < 4 {
		t.Fatalf("checked %d binaries; expected sagvd, acp-compute, acp-bootstrap and acpctl at least", checked)
	}
}

// isAllowlistedSinkPath reports whether a repo-relative path begins with
// one of the allowed write-sink prefixes.
func isAllowlistedSinkPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, prefix := range allowedWriteSinkPrefixes {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

// scanForRawSinks parses one file and returns "<relPath>:<line> — pkg.Func"
// strings, one per forbidden call expression found.
func scanForRawSinks(t *testing.T, absPath, relPath string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, absPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", relPath, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		fq := pkgIdent.Name + "." + sel.Sel.Name
		if _, bad := forbiddenWriteSelectors[fq]; bad {
			pos := fset.Position(call.Pos())
			out = append(out,
				filepath.ToSlash(relPath)+":"+strconv.Itoa(pos.Line)+" — "+fq)
		}
		return true
	})
	return out
}

// locateModuleRoot walks upward from the test package's working
// directory until it finds a go.mod. Used so the AST walk can resolve
// internal/ regardless of where `go test` was invoked from.
func locateModuleRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate go.mod starting from %s", cwd)
	return ""
}

// TestInvariant_07b_DisclosurePackageImports is a tighter sibling of
// Invariant #7. It targets /internal/vault/disclosure specifically —
// the ONE package in the codebase that handles genome plaintext
// in memory (via EmitParams.Plaintext on the StagedIssuer pathway).
//
// Where Invariant #7 allowlists packages with justified write-sinks,
// this test goes stricter: the disclosure package's non-test files
// must not IMPORT any standard package that exposes a persistence
// or transport writer, regardless of whether the package calls a
// forbidden selector. The goal is to make the import graph itself
// a wall — a future contributor cannot stash a plaintext leak behind
// a wrapper type or a renamed import without first landing an
// obviously-reviewable import-statement change.
//
// Forbidden on production files under /internal/vault/disclosure:
//   - os, io/ioutil, bufio (filesystem sinks)
//   - net, net/http (network sinks)
//   - log (stdlib log writes to stderr without going through the
//     vault's audit pipeline)
//
// Legitimate writes in this package are limited to keys.Sealer.Seal.
// Test files (_test.go) are unrestricted — they may stage os-level
// operations for fixtures.
func TestInvariant_07b_DisclosurePackageImports(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	pkgDir := filepath.Join(root, "internal/vault/disclosure")

	forbidden := map[string]struct{}{
		"os":        {},
		"io/ioutil": {},
		"bufio":     {},
		"net":       {},
		"net/http":  {},
		"log":       {},
	}

	var violations []string
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read %s: %v", pkgDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			// imp.Path.Value is quoted; strip.
			raw := strings.Trim(imp.Path.Value, `"`)
			if _, bad := forbidden[raw]; bad {
				violations = append(violations,
					name+": imports forbidden package "+raw)
			}
		}
	}
	if len(violations) > 0 {
		t.Errorf("disclosure package import discipline violated (%d case(s)):", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
		t.Errorf("disclosure may write only via keys.Sealer.Seal; to land one of %v "+
			"in a production file requires amending this allowlist with rationale",
			[]string{"os", "io/ioutil", "bufio", "net", "net/http", "log"})
	}
}

// TestInvariant_08_AuditFirstClass asserts the static preconditions for
// "audit is a first-class artifact, not a log line":
//
//  1. ReleaseDecision — the terminal authority artifact — carries a
//     required AuditEventID field binding the decision to its
//     RELEASE_DECIDED audit record. A decision without an audit pointer
//     is an un-evidenced decision and is structurally invalid.
//
//  2. The audit_event.Kind enumeration covers every operational stage
//     of the nine-stage flow. Each stage that produces an authority
//     decision has at least one dedicated Kind constant — this is the
//     static skeleton that behavioral code (issuer + audit append)
//     hangs on. Missing Kinds would mean some stage has no typed audit
//     slot and must improvise, which is the failure mode the invariant
//     exists to prevent.
//
// The behavioral property — that the audit record is APPENDED before
// the decision becomes visible to its caller — is exercised in the
// per-package tests (notably sequencer_test.go for StagedSequencer).
func TestInvariant_08_AuditFirstClass(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)

	// 1 — ReleaseDecision carries AuditEventID.
	rdDir := filepath.Join(root, "internal/contracts/release_decision")
	aeType := structFieldType(t, rdDir, "ReleaseDecision", "AuditEventID")
	require.NotEmptyf(t, aeType,
		"ReleaseDecision must declare an AuditEventID field — audit is first-class, not decorative")
	require.Containsf(t, aeType, "AuditEventID",
		"ReleaseDecision.AuditEventID must be typed as ids.AuditEventID; saw %q", aeType)

	// 2 — audit_event.Kind covers the flow.
	aeDir := filepath.Join(root, "internal/contracts/audit_event")
	kinds := collectStringConstants(t, aeDir, "Kind")
	// The flow's stage-bearing kinds. This list deliberately omits
	// internal/sub-kinds like VALIDATION_DIMENSION_EVALUATED and
	// VALIDATION_FINDING because they are interior to stage 7. The
	// assertion is on the stage SKELETON, which is what governs
	// first-class-audit.
	required := []string{
		"REQUEST_RECEIVED",      // stage 1
		"TRUST_EVALUATED",       // stage 2
		"SESSION_ISSUED",        // stage 3
		"DISCLOSURE_AUTHORIZED", // stage 4
		"MANIFEST_ISSUED",       // stage 5 (delegated compute dispatch)
		"CANDIDATE_RECEIVED",    // stage 6
		"VALIDATION_STARTED",    // stage 7 open
		"VALIDATION_COMPLETED",  // stage 7 close
		"RELEASE_DECIDED",       // stage 8
	}
	for _, name := range required {
		require.Containsf(t, kinds, name,
			"audit_event.Kind must define constant with value %q — every stage needs a typed audit slot", name)
	}
}

// TestInvariant_09_ContractsFrozen asserts that every subdirectory of
// /internal/contracts/ defines the canonical artifact shape required by
// docs/doctrine/terminology.md §3 and docs/doctrine/open-decisions-resolved.md R-13:
//
//  1. At least one exported struct in the package declares a field
//     named SchemaVersion of type uint16 as its FIRST field.
//  2. The package declares the three schema-version constants
//     SchemaVersionMin, SchemaVersionMax, SchemaVersionCurrent.
//  3. No package OUTSIDE /internal/contracts/ declares a local copy of
//     the canonical struct type names (RecoveryRequest, SessionObject,
//     AttestationResult, DisclosureMessage, ReleaseDecision,
//     ValidationResult, ReconstructionJobManifest, AuditEvent,
//     ContinuityProof, GenomeDescriptor, ProbeBattery,
//     BootstrapManifest, ReceivedDisclosure, ReconstitutionDecision).
//     A redefinition would fragment the contract and silently create
//     parallel wire formats.
//
// The witness package is a composite (LogEntry, SignedTreeHead,
// WitnessReceipt) rather than a single named contract type; the
// per-struct checks still apply individually and are exercised here as
// a structural survey.
//
// Bootstrap family. The receive-side mirror trio
// (BootstrapManifest, ReceivedDisclosure, ReconstitutionDecision) is
// covered here on the same footing as the release-side contracts. The
// two families are deliberately distinct types — the doctrine forbids
// silent collapse — and the redefinition check defends both.
func TestInvariant_09_ContractsFrozen(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	contractsRoot := filepath.Join(root, "internal/contracts")

	// Map: package dir → at least one struct name expected in it. The
	// canonical struct name is derived from the package-dir snake_case.
	// Packages listed here have a single headline contract type.
	requiredStructs := map[string]string{
		"attestation_result":          "AttestationResult",
		"audit_event":                 "AuditEvent",
		"bootstrap_manifest":          "BootstrapManifest",
		"continuity_proof":            "ContinuityProof",
		"disclosure_message":          "DisclosureMessage",
		"genome_descriptor":           "GenomeDescriptor",
		"probe_battery":               "ProbeBattery",
		"received_disclosure":         "ReceivedDisclosure",
		"reconstitution_decision":     "ReconstitutionDecision",
		"reconstruction_job_manifest": "ReconstructionJobManifest",
		"recovery_request":            "RecoveryRequest",
		"release_decision":            "ReleaseDecision",
		"session_object":              "SessionObject",
		"validation_result":           "ValidationResult",
	}

	entries, err := os.ReadDir(contractsRoot)
	require.NoError(t, err, "read %s", contractsRoot)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgDir := filepath.Join(contractsRoot, e.Name())

		// (2) Required constants — once per package, regardless of headline struct.
		consts := collectConstNames(t, pkgDir)
		for _, want := range []string{"SchemaVersionMin", "SchemaVersionMax", "SchemaVersionCurrent"} {
			require.Containsf(t, consts, want,
				"contract package %s must declare constant %s", e.Name(), want)
		}

		// (1) First-field check on the headline struct if one is expected;
		//     otherwise ensure at least one exported struct in the package
		//     has SchemaVersion uint16 as first field (covers witness).
		typeName, hasHeadline := requiredStructs[e.Name()]
		if hasHeadline {
			first, ftype := structFirstField(t, pkgDir, typeName)
			require.Equalf(t, "SchemaVersion", first,
				"%s.%s must have SchemaVersion as FIRST field; saw %q", e.Name(), typeName, first)
			require.Equalf(t, "uint16", ftype,
				"%s.%s.SchemaVersion must be uint16; saw %q", e.Name(), typeName, ftype)
		} else {
			found := packageHasStructWithFirstSchemaVersion(t, pkgDir)
			require.Truef(t, found,
				"contract package %s must define at least one exported struct with SchemaVersion uint16 as first field",
				e.Name())
		}
	}

	// (3) Forbidden redefinition outside /internal/contracts/.
	forbidden := map[string]struct{}{}
	for _, name := range requiredStructs {
		forbidden[name] = struct{}{}
	}
	var violations []string
	walkErr := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if strings.HasPrefix(relSlash, "internal/contracts/") {
			return nil
		}
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", relSlash, parseErr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			if _, isStruct := ts.Type.(*ast.StructType); !isStruct {
				return true
			}
			if _, bad := forbidden[ts.Name.Name]; bad {
				pos := fset.Position(ts.Pos())
				violations = append(violations,
					relSlash+":"+strconv.Itoa(pos.Line)+" — redefines contract struct "+ts.Name.Name)
			}
			return true
		})
		return nil
	})
	require.NoError(t, walkErr, "walking internal/")
	if len(violations) > 0 {
		t.Errorf("doctrine invariant 09 (contracts-frozen) violated by %d redefinition(s):",
			len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
		t.Errorf("canonical contract types must exist only under /internal/contracts/; " +
			"any local struct that shadows a canonical name fragments the wire format")
	}
}

// TestInvariant_10_TerminologyEnforced is a meta-test on
// scripts/terminology_check.sh — the script that sub-check 09 of the
// vault-gate workflow invokes against the working tree. It asserts:
//
//  1. The script exists at the canonical path.
//  2. When a temporary tree contains a deprecated token (from the frozen
//     list in docs/doctrine/terminology.md §4), the script exits non-zero
//     and the failing token appears in stderr/stdout.
//  3. When the same tree contains only canonical terms, the script
//     passes.
//
// The script is invoked with bash in a temp cwd; CI needs bash available,
// which is true on the ubuntu-latest runner the vault-gate workflow uses.
// The test is skipped if bash is not on PATH so developers on exotic
// setups are not blocked; CI never skips because bash is guaranteed
// there.
func TestInvariant_10_TerminologyEnforced(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("bash not available on PATH (%v); script-based meta-test cannot run", err)
	}
	root := locateModuleRoot(t)
	script := filepath.Join(root, "scripts", "terminology_check.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("terminology_check.sh must exist at %s: %v", script, err)
	}

	// Negative case — a file containing "NSV" (one of the frozen
	// deprecated tokens) must trip the script.
	t.Run("negative_deprecated_token_fails", func(t *testing.T) {
		tmp := t.TempDir()
		require.NoError(t,
			os.WriteFile(filepath.Join(tmp, "bad.go"),
				[]byte("// SPDX-License-Identifier: AGPL-3.0-or-later\npackage x\n// mentions NSV somewhere\n"),
				0o644))
		out, err := runScript(t, script, tmp)
		require.Errorf(t, err,
			"terminology_check.sh must exit non-zero when deprecated token NSV is present; output was:\n%s", out)
		require.Containsf(t, out, "NSV",
			"failure output must name the matched token; output was:\n%s", out)
	})

	// Positive case — a file with only canonical terms must pass.
	t.Run("positive_canonical_passes", func(t *testing.T) {
		tmp := t.TempDir()
		require.NoError(t,
			os.WriteFile(filepath.Join(tmp, "good.go"),
				[]byte("// SPDX-License-Identifier: AGPL-3.0-or-later\npackage x\n// canonical terms only\n"),
				0o644))
		out, err := runScript(t, script, tmp)
		require.NoErrorf(t, err,
			"terminology_check.sh must exit 0 for a clean tree; output was:\n%s", out)
	})
}

// TestInvariant_11_SupplyChainAttested asserts (in offline form) that the
// release workflow produces signatures and SBOMs for every binary and
// that a SLSA provenance generator is wired in. End-to-end verification
// can only happen at release time; this test asserts the workflow
// FILE's structural contents so a future edit that drops one of the
// three attestation pillars (SBOM / cosign signature / SLSA provenance)
// trips CI.
//
// The workflow file is parsed as text rather than unmarshaled as YAML
// to avoid pulling a YAML dependency into the test module — the
// string-level checks are sufficient: the workflow names each tool
// explicitly and those names are stable (syft, cosign, slsa-framework).
func TestInvariant_11_SupplyChainAttested(t *testing.T) {
	t.Parallel()
	root := locateModuleRoot(t)
	// The repo-relative workflow path is independent of which directory
	// `go test` was invoked from. locateModuleRoot returns the /core/
	// directory; the workflow lives at core/.github/workflows/release.yml.
	workflow := filepath.Join(root, ".github", "workflows", "release.yml")
	raw, err := os.ReadFile(workflow)
	require.NoErrorf(t, err, "release workflow must exist at %s", workflow)

	content := string(raw)

	// SBOM pillar — syft invoked per binary with SPDX JSON output.
	require.Containsf(t, content, "syft",
		"release workflow must call syft to produce an SBOM per artifact; see docs/doctrine/ci-security-policy.md §6")
	require.Containsf(t, content, "spdx-json",
		"SBOM must be emitted in SPDX-JSON (the format the policy pins)")

	// Signing pillar — cosign with keyless signing and transparency-log entry.
	require.Containsf(t, content, "cosign",
		"release workflow must sign binaries with cosign (keyless)")
	require.Containsf(t, content, "sign-blob",
		"cosign invocation must be sign-blob (detached signatures over build artifacts)")

	// Provenance pillar — SLSA generator.
	require.Containsf(t, content, "slsa-framework",
		"release workflow must invoke the SLSA provenance generator")
	require.Containsf(t, content, "generator_generic_slsa",
		"SLSA provenance generator reference must be the canonical reusable workflow")

	// Triggering discipline — only signed tags matching v*.*.* trigger releases.
	require.Containsf(t, content, "v*.*.*",
		"release workflow must be tag-driven with a semver tag pattern")
	require.Containsf(t, content, "verify-tag",
		"release workflow must verify the tag's signature before building")

	// Binary coverage — every operational binary participates in the supply chain.
	for _, bin := range []string{"sagvd", "acp-compute", "acpctl", "acp-bootstrap"} {
		require.Containsf(t, content, bin,
			"release workflow must include binary %q in the signed/SBOM'd set", bin)
	}
}

// parsePackageFiles parses every non-test .go file in pkgDir and returns
// the resulting ast.File slice alongside the fileset. The call fatals on
// any parse error — a doctrine test cannot report meaningfully against a
// source tree that does not parse.
func parsePackageFiles(t *testing.T, pkgDir string) (*token.FileSet, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(pkgDir)
	require.NoErrorf(t, err, "read %s", pkgDir)

	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	return fset, files
}

// exprString renders an ast.Expr (a field type) as its surface-form
// Go source, minus whitespace. Selectors are rendered as pkg.Name.
// Slices are rendered as []X. Pointers as *X. Anything exotic falls
// back to the go/token position description.
func exprString(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	case *ast.ArrayType:
		if v.Len == nil {
			return "[]" + exprString(v.Elt)
		}
		return "[" + exprString(v.Len) + "]" + exprString(v.Elt)
	case *ast.MapType:
		return "map[" + exprString(v.Key) + "]" + exprString(v.Value)
	case *ast.BasicLit:
		return v.Value
	case *ast.InterfaceType:
		return "interface{...}"
	case *ast.StructType:
		return "struct{...}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.ChanType:
		return "chan " + exprString(v.Value)
	case *ast.Ellipsis:
		return "..." + exprString(v.Elt)
	}
	return "<unknown>"
}

// findStruct locates an exported struct by name in a parsed package.
// Returns the *ast.StructType or nil if the name is not declared as a
// struct in any non-test file of the package.
func findStruct(files []*ast.File, typeName string) *ast.StructType {
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != typeName {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				return st
			}
		}
	}
	return nil
}

// structFields returns the flattened list of (name, type-as-string) pairs
// for a struct's fields, in declaration order. Embedded fields are
// reported with their implicit name (the type's rightmost Ident).
func structFields(st *ast.StructType) []struct {
	Name string
	Type string
} {
	var out []struct {
		Name string
		Type string
	}
	if st == nil || st.Fields == nil {
		return out
	}
	for _, field := range st.Fields.List {
		typeStr := exprString(field.Type)
		if len(field.Names) == 0 {
			// Embedded — use the rightmost identifier as name.
			implicit := typeStr
			if idx := strings.LastIndex(implicit, "."); idx >= 0 {
				implicit = implicit[idx+1:]
			}
			out = append(out, struct {
				Name string
				Type string
			}{Name: implicit, Type: typeStr})
			continue
		}
		for _, n := range field.Names {
			out = append(out, struct {
				Name string
				Type string
			}{Name: n.Name, Type: typeStr})
		}
	}
	return out
}

// structFieldType returns the surface-form type string of a named field on
// an exported struct in pkgDir. Returns "" if either the struct or the
// field is not found. Used to assert structural contract properties
// without importing the contract at test-compile time.
func structFieldType(t *testing.T, pkgDir, typeName, fieldName string) string {
	t.Helper()
	_, files := parsePackageFiles(t, pkgDir)
	st := findStruct(files, typeName)
	if st == nil {
		return ""
	}
	for _, f := range structFields(st) {
		if f.Name == fieldName {
			return f.Type
		}
	}
	return ""
}

// structHasFieldOfType reports whether typeName in pkgDir declares a
// field named fieldName. Type is not checked; callers that need a type
// check use structFieldType.
func structHasFieldOfType(t *testing.T, pkgDir, typeName, fieldName string) bool {
	t.Helper()
	return structFieldType(t, pkgDir, typeName, fieldName) != ""
}

// structFirstField returns the (name, type) of the first declared field
// of typeName in pkgDir. Name is "" if the struct is not found.
func structFirstField(t *testing.T, pkgDir, typeName string) (string, string) {
	t.Helper()
	_, files := parsePackageFiles(t, pkgDir)
	st := findStruct(files, typeName)
	if st == nil {
		return "", ""
	}
	fields := structFields(st)
	if len(fields) == 0 {
		return "", ""
	}
	return fields[0].Name, fields[0].Type
}

// packageHasStructWithFirstSchemaVersion reports whether any exported
// struct in pkgDir has a field named "SchemaVersion" of type uint16 as
// its FIRST declared field. Used for packages that do not have a single
// headline contract type (notably witness).
func packageHasStructWithFirstSchemaVersion(t *testing.T, pkgDir string) bool {
	t.Helper()
	_, files := parsePackageFiles(t, pkgDir)
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !ts.Name.IsExported() {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				fields := structFields(st)
				if len(fields) == 0 {
					continue
				}
				if fields[0].Name == "SchemaVersion" && fields[0].Type == "uint16" {
					return true
				}
			}
		}
	}
	return false
}

// collectConstNames returns the sorted set of package-level constant
// identifiers declared in pkgDir.
func collectConstNames(t *testing.T, pkgDir string) []string {
	t.Helper()
	_, files := parsePackageFiles(t, pkgDir)
	seen := map[string]struct{}{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, n := range vs.Names {
					seen[n.Name] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// collectStringConstants returns the set of STRING-LITERAL VALUES assigned
// to typed constants of the named type in pkgDir. Untyped or non-string
// constants are skipped. Result is sorted for determinism.
func collectStringConstants(t *testing.T, pkgDir, typeName string) []string {
	t.Helper()
	_, files := parsePackageFiles(t, pkgDir)
	seen := map[string]struct{}{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			// Track the last explicit type in the const group. When a
			// ValueSpec omits its type AND its value list, Go carries
			// the prior spec's type+value+iota forward; in that case we
			// keep currentType. When a ValueSpec gives an explicit
			// value without a type, the constant is untyped — we do
			// not match an untyped constant against typeName.
			var currentType string
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if vs.Type != nil {
					currentType = exprString(vs.Type)
				} else if len(vs.Values) > 0 {
					// Explicit value without explicit type → the
					// constant is untyped; it is not a typed member
					// of typeName. Clear currentType so that a
					// subsequent typed spec must re-assert.
					currentType = ""
				}
				if currentType != typeName {
					continue
				}
				for _, val := range vs.Values {
					lit, ok := val.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					// lit.Value is quoted — strip.
					unq, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					seen[unq] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// methodReturnTypes parses the file at path, finds the method named
// methodName on the receiver type receiverType (matching both pointer
// and value receivers), and returns the surface-form types of its
// return parameters in order. Returns nil if the method is not found.
func methodReturnTypes(t *testing.T, path, receiverType, methodName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || fd.Name.Name != methodName {
			continue
		}
		if len(fd.Recv.List) == 0 {
			continue
		}
		// Strip leading '*' for pointer receivers.
		recvType := strings.TrimPrefix(exprString(fd.Recv.List[0].Type), "*")
		if recvType != receiverType {
			continue
		}
		if fd.Type.Results == nil {
			return nil
		}
		var out []string
		for _, r := range fd.Type.Results.List {
			typeStr := exprString(r.Type)
			n := len(r.Names)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				out = append(out, typeStr)
			}
		}
		return out
	}
	return nil
}

// runScript invokes bash against a script with cwd set to dir and
// returns the combined stdout/stderr alongside the exec error. Used by
// the terminology meta-test.
func runScript(t *testing.T, script, dir string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", script)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
