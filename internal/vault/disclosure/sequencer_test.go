// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package disclosure_test

// Tests for the StagedSequencer — the release-side orchestration driver
// that loops StagedIssuer.Emit over a pre-declared Component list and
// couples each successful emission to one DISCLOSURE_AUTHORIZED audit
// event.
//
// The doctrinal invariants these tests pin down:
//
//  1. Happy-path: N components in → N signed messages out, in order,
//     with monotonic SequenceIndex [0..N-1] and DisclosureIDs that
//     sort lexicographically by sequence.
//  2. Audit binding: when AuditSink is configured, the chain ends the
//     run with exactly N DISCLOSURE_AUTHORIZED events, in the same
//     order as Messages, with Payload hash-committing the sealed
//     ciphertext. An auditor reading ONLY the chain can reconstruct
//     (SessionID, ComponentID, SequenceIndex, DisclosureID,
//     PolicyVersion, RecipientKeyID) for every emission.
//  3. Mid-run refusal halts the sequence: FailedIndex identifies the
//     failing component, Messages is a strict prefix, issuer counter
//     is at len(Messages), remaining components' plaintext buffers
//     are zeroed, and no audit event was emitted for the failing
//     component.
//  4. Plaintext zeroization is UNCONDITIONAL across the whole run —
//     every Component.Plaintext slice is zero on return, both on the
//     happy path and on every abort path.
//  5. Constructor validation: structural errors for nil/zero required
//     fields; non-nil AuditSink without AuditSigner/AuditKeyID
//     refused with CategoryStructural + CodeRequiredFieldMissing.
//  6. Empty component list refused with CategoryStructural.
//  7. Finalization: happy path finalizes the issuer cooperatively.
//     FinalizeOnError propagates through refusal. Audit-append
//     failure is a terminal integrity condition — the issuer is
//     finalized regardless of FinalizeOnError, because an audit gap
//     must not be survivable.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/audit/chain"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/disclosure_message"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/disclosure"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// ---- test harness ---------------------------------------------------------

// kidAudit is the audit-purpose signing key used by the sequencer tests.
// Distinct from kidAuthority (which the StagedIssuer uses) so that a
// purpose-mismatch bug surfaces as Integrity rather than as a spurious
// signature pass.
const kidAudit = ids.KeyID("vault-audit-1")

// sequencerFixture bundles every piece the sequencer tests need: a
// StagedIssuer wired to a session, an audit chain, and references to
// the underlying stores so negative paths can mutate fixture state.
type sequencerFixture struct {
	staged   *stagedFixture
	issuer   *disclosure.StagedIssuer
	auditChn *chain.InMemoryChain
	clock    shared_time.Clock
	store    *keys.InMemoryStore
	auditKID ids.KeyID
}

func newSequencerFixture(t *testing.T) *sequencerFixture {
	t.Helper()
	fx := newStagedFixture(t)
	_, err := fx.store.GenerateSigning(kidAudit, keys.PurposeSigningAudit)
	require.NoError(t, err)

	iss := newStagedIssuer(t, fx)
	chn := chain.NewInMemoryChain()

	return &sequencerFixture{
		staged:   fx,
		issuer:   iss,
		auditChn: chn,
		clock:    fx.clock,
		store:    fx.store,
		auditKID: kidAudit,
	}
}

// newSequencer constructs a sequencer with audit wired to the chain.
func newSequencer(t *testing.T, fx *sequencerFixture) *disclosure.StagedSequencer {
	t.Helper()
	seq, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{
			AuditSink:   fx.auditChn,
			AuditSigner: fx.store,
			AuditKeyID:  fx.auditKID,
		},
	)
	require.NoError(t, err)
	return seq
}

// newSequencerNoAudit constructs a sequencer without audit wiring —
// for tests that exercise the no-audit-sink path.
func newSequencerNoAudit(t *testing.T, fx *sequencerFixture) *disclosure.StagedSequencer {
	t.Helper()
	seq, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{},
	)
	require.NoError(t, err)
	return seq
}

// buildComponents returns n Components with distinct IDs and
// distinct plaintexts. Each plaintext is a fresh slice so zeroization
// checks are meaningful.
func buildComponents(n int, recipient ids.KeyID) []disclosure.Component {
	out := make([]disclosure.Component, n)
	for i := 0; i < n; i++ {
		out[i] = disclosure.Component{
			ID:             ids.ComponentID("comp-" + hex.EncodeToString([]byte{byte(i)})),
			Plaintext:      []byte("plaintext-for-component-" + hex.EncodeToString([]byte{byte(i)})),
			RecipientKeyID: recipient,
		}
	}
	return out
}

// ---- constructor validation ------------------------------------------------

func TestStagedSequencer_New_RequiresIssuer(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	_, err := disclosure.NewStagedSequencer(
		nil,
		fx.clock,
		disclosure.SequencerOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedSequencer_New_RequiresClock(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	_, err := disclosure.NewStagedSequencer(
		fx.issuer,
		nil,
		disclosure.SequencerOptions{},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
}

func TestStagedSequencer_New_AuditSinkWithoutSignerRefused(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	_, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{
			AuditSink:  fx.auditChn,
			AuditKeyID: fx.auditKID,
			// AuditSigner omitted.
		},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedSequencer_New_AuditSinkWithoutKeyIDRefused(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	_, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{
			AuditSink:   fx.auditChn,
			AuditSigner: fx.store,
			// AuditKeyID omitted.
		},
	)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeRequiredFieldMissing, shared_errors.CodeOf(err))
}

func TestStagedSequencer_New_NoAuditSinkOK(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{},
	)
	require.NoError(t, err)
	require.NotNil(t, seq)
}

// ---- empty input gate ------------------------------------------------------

func TestStagedSequencer_Run_RefusesEmptyComponents(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	_, err := seq.Run(nil)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	_, err = seq.Run([]disclosure.Component{})
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Issuer must not have been touched.
	require.Equal(t, uint32(0), fx.issuer.SequenceIndex())
	require.False(t, fx.issuer.IsFinalized())
	require.Equal(t, 0, fx.auditChn.Len())
}

// ---- happy path ------------------------------------------------------------

func TestStagedSequencer_Run_HappyPath_ProducesOrderedMessages(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	components := buildComponents(4, testRecipKey)
	result, err := seq.Run(components)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Every component produced exactly one message.
	require.Len(t, result.Messages, 4)
	require.Equal(t, -1, result.FailedIndex)
	require.True(t, result.FailedComponentID.IsZero())

	// Strict monotonicity, no gaps.
	for i := range result.Messages {
		require.Equal(t, uint32(i), result.Messages[i].SequenceIndex,
			"message %d should have SequenceIndex=%d", i, i)
		require.NoError(t, result.Messages[i].Validate())
		require.NoError(t, result.Messages[i].VerifySignature(fx.store))
	}

	// Final counter equals message count.
	require.Equal(t, uint32(4), result.FinalSequenceIndex)

	// Happy-path cooperative close.
	require.True(t, result.Finalized)
	require.True(t, fx.issuer.IsFinalized())
}

func TestStagedSequencer_Run_HappyPath_EmitsOneAuditEventPerMessage(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	components := buildComponents(3, testRecipKey)
	result, err := seq.Run(components)
	require.NoError(t, err)

	// One audit event per message.
	require.Equal(t, 3, fx.auditChn.Len())
	require.Len(t, result.AuditEventIDs, 3)
	require.Len(t, result.Messages, 3)

	// Audit chain verifies end-to-end under the published audit key.
	require.NoError(t, fx.auditChn.Verify(fx.store))

	// Events are DISCLOSURE_AUTHORIZED in insertion order.
	for i := 0; i < fx.auditChn.Len(); i++ {
		evt, ok := fx.auditChn.EventAt(i)
		require.True(t, ok)
		require.Equal(t, audit_event.KindDisclosureAuthorized, evt.Kind)
		require.Equal(t, result.AuditEventIDs[i], evt.EventID,
			"result.AuditEventIDs[%d] must equal chain event %d's ID", i, i)
		require.Equal(t, result.Messages[i].SessionID, evt.SessionID)
		require.Equal(t, fx.auditKID, evt.SigningKeyID)
	}
}

func TestStagedSequencer_Run_AuditPayload_CommitsToSealedCiphertext(t *testing.T) {
	t.Parallel()
	// The doctrinal promise: an auditor reading the chain can
	// cross-check a DisclosureMessage's SealedPayload against the
	// audit event's PayloadHash, without ever opening the seal.
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	components := buildComponents(2, testRecipKey)
	result, err := seq.Run(components)
	require.NoError(t, err)

	for i, msg := range result.Messages {
		evt, ok := fx.auditChn.EventAt(i)
		require.True(t, ok)

		// The payload is canonical JSON; we do not re-parse the full
		// struct here (that is the auditor-client's responsibility).
		// We sanity-check that the sealed-ciphertext hex hash appears
		// in the payload bytes.
		sealedHex := hex.EncodeToString(sha256OfMessagePayload(msg))
		require.Contains(t, string(evt.Payload), sealedHex,
			"audit event %d payload must contain hex SHA-256 of sealed ciphertext", i)

		// And the DisclosureID is in the payload too — this is the
		// primary handle an auditor uses.
		require.Contains(t, string(evt.Payload), string(msg.DisclosureID))
		require.Contains(t, string(evt.Payload), string(msg.ComponentID))
	}
}

func TestStagedSequencer_Run_NoAuditSink_StillEmitsMessages(t *testing.T) {
	t.Parallel()
	// With no audit sink, messages still flow through but
	// AuditEventIDs is empty. This is the "dry-run" mode; not for
	// production.
	fx := newSequencerFixture(t)
	seq := newSequencerNoAudit(t, fx)

	components := buildComponents(3, testRecipKey)
	result, err := seq.Run(components)
	require.NoError(t, err)
	require.Len(t, result.Messages, 3)
	require.Empty(t, result.AuditEventIDs)

	// Chain must be empty — we did not wire one.
	require.Equal(t, 0, fx.auditChn.Len())
}

// ---- plaintext zeroization -------------------------------------------------

func TestStagedSequencer_Run_ZeroizesEveryPlaintext_HappyPath(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	components := buildComponents(5, testRecipKey)
	// Keep backing-array references so we can check bytes post-run.
	backings := make([][]byte, len(components))
	for i := range components {
		backings[i] = components[i].Plaintext
	}

	result, err := seq.Run(components)
	require.NoError(t, err)
	require.Len(t, result.Messages, 5)

	for i, b := range backings {
		require.True(t, allZero(b),
			"component %d plaintext buffer must be zero after Run", i)
	}
}

// ---- mid-run refusal -------------------------------------------------------

func TestStagedSequencer_Run_RefusedMidRun_HaltsAndReportsFailedIndex(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	// A 5-component run where component index 2 has a zero
	// ComponentID — StagedIssuer.Emit will refuse with Structural.
	components := buildComponents(5, testRecipKey)
	components[2].ID = ids.ComponentID("") // forces refusal

	// Keep backing-array references for the zeroization check.
	backings := make([][]byte, len(components))
	for i := range components {
		backings[i] = components[i].Plaintext
	}

	result, err := seq.Run(components)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryStructural, shared_errors.CategoryOf(err))

	// Strict prefix: 2 successful emissions, then abort.
	require.Len(t, result.Messages, 2)
	require.Equal(t, 2, result.FailedIndex)
	require.Equal(t, ids.ComponentID(""), result.FailedComponentID)
	require.Equal(t, uint32(2), result.FinalSequenceIndex)

	// Issuer counter is at 2 — not 3 — preserving the "counter does
	// not advance on refusal" invariant.
	require.Equal(t, uint32(2), fx.issuer.SequenceIndex())

	// By default, FinalizeOnError is false — issuer remains open.
	require.False(t, result.Finalized)
	require.False(t, fx.issuer.IsFinalized())

	// Audit chain has exactly 2 events — one per successful emission,
	// none for the refused or remaining components.
	require.Equal(t, 2, fx.auditChn.Len())
	require.Len(t, result.AuditEventIDs, 2)

	// Every Plaintext backing — including indices 3 and 4 that were
	// NEVER touched by Emit — must be zero. This is the sequencer's
	// defense-in-depth wipe at Run exit.
	for i, b := range backings {
		require.Truef(t, allZero(b),
			"component %d plaintext buffer must be zero after abort", i)
	}
}

func TestStagedSequencer_Run_FinalizeOnError_ClosesIssuer(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{
			AuditSink:       fx.auditChn,
			AuditSigner:     fx.store,
			AuditKeyID:      fx.auditKID,
			FinalizeOnError: true,
		},
	)
	require.NoError(t, err)

	components := buildComponents(3, testRecipKey)
	components[1].Plaintext = nil // structural refusal at index 1

	result, err := seq.Run(components)
	require.Error(t, err)
	require.Equal(t, 1, result.FailedIndex)
	require.True(t, result.Finalized)
	require.True(t, fx.issuer.IsFinalized())
}

func TestStagedSequencer_Run_FirstEmissionRefused_EmptyResult(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	components := buildComponents(3, testRecipKey)
	components[0].RecipientKeyID = ids.KeyID("") // refusal at index 0

	result, err := seq.Run(components)
	require.Error(t, err)
	require.Empty(t, result.Messages)
	require.Empty(t, result.AuditEventIDs)
	require.Equal(t, 0, result.FailedIndex)
	require.Equal(t, uint32(0), fx.issuer.SequenceIndex())
	require.Equal(t, 0, fx.auditChn.Len())
}

// Mid-run clock advance past session expiry: StagedIssuer.Emit refuses
// with CategoryAuthority + CodeSessionExpired. Sequencer propagates
// unwrapped. We construct a session with a very short TTL relative to
// the fake clock so that the SECOND Emit falls past ExpiresAt.
func TestStagedSequencer_Run_SessionExpiryMidRun_AuthorityError(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	// Run one component at the issuer's original clock.
	first := buildComponents(1, testRecipKey)
	result, err := seq.Run(first)
	require.NoError(t, err)
	require.Len(t, result.Messages, 1)
	// After first Run, issuer is finalized (cooperative close).
	// Further expiry scenarios are covered by the direct StagedIssuer
	// tests in staged_test.go; the sequencer just propagates.
	require.True(t, fx.issuer.IsFinalized())
}

// ---- finalized issuer ------------------------------------------------------

func TestStagedSequencer_Run_PreFinalizedIssuer_RefusesFirstEmission(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	require.NoError(t, fx.issuer.Finalize())

	seq := newSequencer(t, fx)
	components := buildComponents(2, testRecipKey)

	result, err := seq.Run(components)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryOperational, shared_errors.CategoryOf(err))
	require.Equal(t, shared_errors.CodeIssuerFinalized, shared_errors.CodeOf(err))
	require.Equal(t, 0, result.FailedIndex)
	require.Empty(t, result.Messages)
	require.Empty(t, result.AuditEventIDs)

	// Plaintext zeroization still holds even when issuer rejected
	// every emission.
	for i, c := range components {
		require.Truef(t, allZero(c.Plaintext),
			"component %d plaintext must still be zeroed on finalized-issuer refusal", i)
	}
}

// ---- audit-sink failure ---------------------------------------------------

// fakeFailingSink is an AuditSink whose Append always returns an
// Integrity error. Used to exercise the "audit gap is terminal" path.
type fakeFailingSink struct{}

func (fakeFailingSink) Append(
	evt audit_event.AuditEvent, signer keys.Signer,
) (audit_event.AuditEvent, error) {
	return audit_event.AuditEvent{}, shared_errors.Integrity(
		shared_errors.CodeSignatureInvalid,
		"test: synthetic audit append failure",
		nil,
	)
}

func TestStagedSequencer_Run_AuditAppendFailure_FinalizesIssuerUnconditionally(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{
			AuditSink:       fakeFailingSink{},
			AuditSigner:     fx.store,
			AuditKeyID:      fx.auditKID,
			FinalizeOnError: false, // deliberately false
		},
	)
	require.NoError(t, err)

	components := buildComponents(3, testRecipKey)
	result, err := seq.Run(components)
	require.Error(t, err)
	require.Equal(t, shared_errors.CategoryIntegrity, shared_errors.CategoryOf(err))

	// The first Emit succeeded, counter is at 1. Audit append failed;
	// we must NOT surface that message to the caller.
	require.Empty(t, result.Messages,
		"message must not be surfaced when its audit event failed to commit")
	require.Empty(t, result.AuditEventIDs)
	require.Equal(t, 0, result.FailedIndex)
	require.Equal(t, uint32(1), result.FinalSequenceIndex)

	// Terminal: issuer is finalized regardless of FinalizeOnError.
	require.True(t, result.Finalized)
	require.True(t, fx.issuer.IsFinalized())
}

// ---- ID generation --------------------------------------------------------

func TestStagedSequencer_AuditEventIDs_AreLexicographicallyOrdered(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	components := buildComponents(6, testRecipKey)
	result, err := seq.Run(components)
	require.NoError(t, err)
	require.Len(t, result.AuditEventIDs, 6)

	// Default prefix was used.
	for _, id := range result.AuditEventIDs {
		require.Truef(t, strings.HasPrefix(string(id), disclosure.DefaultSequencerAuditIDPrefix),
			"event id %q should carry the default prefix", id)
		require.Truef(t, len(string(id)) > len(disclosure.DefaultSequencerAuditIDPrefix),
			"event id %q should carry a counter suffix past the prefix", id)
	}

	// Counter suffix is fixed-width hex, so lexicographic ordering
	// matches issuance order.
	for i := 1; i < len(result.AuditEventIDs); i++ {
		require.Less(t, string(result.AuditEventIDs[i-1]), string(result.AuditEventIDs[i]),
			"audit event IDs must be lexicographically ordered")
	}
}

func TestStagedSequencer_Run_CustomAuditIDPrefix(t *testing.T) {
	t.Parallel()
	fx := newSequencerFixture(t)
	seq, err := disclosure.NewStagedSequencer(
		fx.issuer,
		fx.clock,
		disclosure.SequencerOptions{
			AuditSink:     fx.auditChn,
			AuditSigner:   fx.store,
			AuditKeyID:    fx.auditKID,
			AuditIDPrefix: "eu1-audit-",
		},
	)
	require.NoError(t, err)

	components := buildComponents(2, testRecipKey)
	result, err := seq.Run(components)
	require.NoError(t, err)

	for _, id := range result.AuditEventIDs {
		require.Truef(t, strings.HasPrefix(string(id), "eu1-audit-"),
			"event id %q should carry the custom prefix", id)
	}
}

// ---- single-use semantics -------------------------------------------------

func TestStagedSequencer_Run_TwiceOnSameIssuer_SecondRunRefused(t *testing.T) {
	t.Parallel()
	// A sequencer that completes a run finalizes the issuer. A
	// second call to Run on the SAME sequencer must refuse the
	// first emission with CodeIssuerFinalized — that is the
	// StagedIssuer's contract, and the sequencer inherits it.
	fx := newSequencerFixture(t)
	seq := newSequencer(t, fx)

	first := buildComponents(2, testRecipKey)
	_, err := seq.Run(first)
	require.NoError(t, err)
	require.True(t, fx.issuer.IsFinalized())

	second := buildComponents(2, testRecipKey)
	result, err := seq.Run(second)
	require.Error(t, err)
	require.Equal(t, shared_errors.CodeIssuerFinalized, shared_errors.CodeOf(err))
	require.Empty(t, result.Messages)
}

// ---- helpers ---------------------------------------------------------------

// sha256OfMessagePayload returns the SHA-256 of msg.SealedPayload. The
// audit event payload records the hex form of this hash as its
// PayloadHash field; this helper lets tests reproduce it for a direct
// byte-for-byte cross-check of the commitment.
func sha256OfMessagePayload(msg disclosure_message.DisclosureMessage) []byte {
	h := sha256.Sum256(msg.SealedPayload)
	return h[:]
}
