// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package chain

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vault-genome/vaultgenome-core/internal/audit/store"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// memPersister is an in-memory Persister whose contents a test can edit,
// the way someone with write access to the log file could.
type memPersister struct {
	events  []audit_event.AuditEvent
	failing bool
}

func (m *memPersister) Append(evt audit_event.AuditEvent) error {
	if m.failing {
		return errors.New("disk full")
	}
	m.events = append(m.events, evt)
	return nil
}

func (m *memPersister) Load() ([]audit_event.AuditEvent, error) {
	return append([]audit_event.AuditEvent(nil), m.events...), nil
}

// A chain on a real bbolt file survives the process: reopened, it has the
// same events and tip, and new events link on to the old ones.
func TestPersistentChain_SurvivesReopen(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	keysStore := newAuditStore(t, kid)
	path := filepath.Join(t.TempDir(), "audit.db")

	s, err := store.Open(path)
	require.NoError(t, err)
	c, err := OpenPersistentChain(s, keysStore)
	require.NoError(t, err)
	for _, id := range []string{"evt-1", "evt-2", "evt-3"} {
		_, err := c.Append(skeleton(id, kid), keysStore)
		require.NoError(t, err)
	}
	tip := c.Tip()
	require.NoError(t, s.Close())

	s, err = store.Open(path)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	c, err = OpenPersistentChain(s, keysStore)
	require.NoError(t, err)
	require.Equal(t, 3, c.Len())
	require.Equal(t, tip, c.Tip())

	fourth, err := c.Append(skeleton("evt-4", kid), keysStore)
	require.NoError(t, err)
	require.Equal(t, tip, fourth.PrevHash, "the new event links to the last persisted one")
	require.NoError(t, c.Verify(keysStore))
	stored, err := s.Load()
	require.NoError(t, err)
	require.Len(t, stored, 4)
}

// Opening refuses any log that does not verify end to end.
func TestPersistentChain_RefusesTamperedLog(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	keysStore := newAuditStore(t, kid)
	build := func() *memPersister {
		p := &memPersister{}
		c, err := OpenPersistentChain(p, keysStore)
		require.NoError(t, err)
		for _, id := range []string{"evt-1", "evt-2", "evt-3"} {
			_, err := c.Append(skeleton(id, kid), keysStore)
			require.NoError(t, err)
		}
		return p
	}

	for name, tamper := range map[string]func(p *memPersister){
		"payload edited": func(p *memPersister) { p.events[1].Payload = []byte(`{"note":"nothing happened"}`) },
		"event removed":  func(p *memPersister) { p.events = append(p.events[:1], p.events[2:]...) },
		"reordered":      func(p *memPersister) { p.events[0], p.events[1] = p.events[1], p.events[0] },
		"re-signed by another key": func(p *memPersister) {
			other := ids.KeyID("intruder")
			otherStore := newAuditStore(t, other)
			evt := p.events[2]
			evt.SigningKeyID = other
			resealed, err := seal(evt, p.events[1].Hash, otherStore)
			require.NoError(t, err)
			p.events[2] = resealed
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := build()
			tamper(p)
			_, err := OpenPersistentChain(p, keysStore)
			require.Error(t, err)
			require.True(t, shared_errors.Is(err, shared_errors.CategoryIntegrity), "got %v", err)
		})
	}
}

// The chain cannot see its own tail being cut off; the tip recorded
// elsewhere can.
func TestPersistentChain_TruncationShowsInTheTip(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	keysStore := newAuditStore(t, kid)
	p := &memPersister{}
	c, err := OpenPersistentChain(p, keysStore)
	require.NoError(t, err)
	for _, id := range []string{"evt-1", "evt-2"} {
		_, err := c.Append(skeleton(id, kid), keysStore)
		require.NoError(t, err)
	}
	recorded := c.Tip()

	p.events = p.events[:1]
	reopened, err := OpenPersistentChain(p, keysStore)
	require.NoError(t, err, "a clean prefix still verifies")
	require.NotEqual(t, recorded, reopened.Tip(), "but its tip is not the recorded one")
}

// If the event cannot be persisted, the decision it records is not taken:
// the chain does not advance.
func TestPersistentChain_PersistFailureLeavesChainUnchanged(t *testing.T) {
	t.Parallel()
	kid := ids.KeyID("audit-key-1")
	keysStore := newAuditStore(t, kid)
	p := &memPersister{}
	c, err := OpenPersistentChain(p, keysStore)
	require.NoError(t, err)
	_, err = c.Append(skeleton("evt-1", kid), keysStore)
	require.NoError(t, err)
	tip := c.Tip()

	p.failing = true
	_, err = c.Append(skeleton("evt-2", kid), keysStore)
	require.Error(t, err)
	require.True(t, shared_errors.Is(err, shared_errors.CategoryOperational))
	require.Equal(t, 1, c.Len())
	require.Equal(t, tip, c.Tip())

	_, err = OpenPersistentChain(nil, keysStore)
	require.Error(t, err)
	_, err = c.Append(skeleton("evt-3", kid), nil)
	require.Error(t, err)
}
