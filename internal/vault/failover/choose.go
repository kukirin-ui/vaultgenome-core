// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package failover

import (
	"fmt"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/genome/sentinel"
	"github.com/vault-genome/vaultgenome-core/internal/genome/tree"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// Choice is the genome a failover restores, and what was passed over.
type Choice struct {
	Record   sentinel.SealRecord
	Identity bundle.Identity
	Envelope escrow.Envelope
	// Expected is what the standby's receipt must show it restored.
	Expected kms.ExpectedGenome
	// RPO is how much earlier than the trigger the genome was sealed: the
	// state it does not hold.
	RPO time.Duration
	// ChainEnd is the newest generation of the verified chain; nil when the
	// outbox holds none.
	ChainEnd *uint64
	// SetAside lists the records, newest first, that were not chosen and
	// why: after the cutoff, files that do not check out, outside the chain.
	SetAside []sentinel.Rejected
}

// Choose picks the genome to restore: the newest generation of the verified
// chain in outbox that the trigger's own record vouches for, that was
// sealed at or before the cutoff — the trigger less the policy's
// quarantine — and whose bundle and escrow envelope check out against its
// signed record. It returns a reason instead when no genome qualifies, or
// when the best one misses more state than the policy allows.
//
// The trigger's record — the compromise report, or the last heartbeat —
// names the last generation the sentinel sealed (ADR 0017). Nothing past
// it is trusted: a record put in the outbox after the sentinel's last
// word is set aside. And if the outbox holds that generation as another
// bundle, the outbox contradicts the sentinel and nothing in it is
// trusted. When the policy pins the primary, the chosen record must also
// carry the primary TEE's report, verified under primary.
func Choose(outbox string, p Policy, t Trigger, escrowTag string, primary tee.Verifier) (Choice, string, error) {
	pub, _ := p.Sentinel()
	chain, rejected, err := sentinel.ReadChain(outbox, pub)
	if err != nil {
		return Choice{}, "", err
	}
	c := Choice{SetAside: rejected}
	if len(chain) == 0 {
		return c, "the outbox holds no genome the pinned sentinel sealed", nil
	}
	end := chain[len(chain)-1].Generation
	c.ChainEnd = &end
	last := t.reportedLast()
	if last == nil {
		return c, "the sentinel's last record names no sealed generation: nothing in the outbox is vouched for", nil
	}
	cutoff := t.At.Add(-time.Duration(p.QuarantineSeconds) * time.Second)
	for i := len(chain) - 1; i >= 0; i-- {
		rec := chain[i]
		switch {
		case rec.Generation > last.Generation:
			c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation),
				Reason: fmt.Sprintf("after generation %d, the last the sentinel's %s names", last.Generation, t.Kind)})
			continue
		case rec.Generation == last.Generation && rec.BundleSHA256 != last.BundleSHA256:
			c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation),
				Reason: fmt.Sprintf("the sentinel's %s names bundle %s for generation %d; the outbox holds %s", t.Kind, last.BundleSHA256[:12], last.Generation, rec.BundleSHA256[:12])})
			return c, fmt.Sprintf("generation %d in the outbox is not the bundle the sentinel's %s names: the outbox contradicts the sentinel, and nothing in it is trusted", last.Generation, t.Kind), nil
		case rec.SealedAt.After(cutoff):
			c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation),
				Reason: fmt.Sprintf("sealed at %s, after the cutoff %s", rec.SealedAt.Format(time.RFC3339Nano), cutoff.Format(time.RFC3339Nano))})
			continue
		}
		if p.PinsPrimary() {
			m, err := rec.Attested(primary)
			if err == nil && !p.PrimaryAllows(m) {
				err = fmt.Errorf("attested by %s measurement %x, which the policy does not pin as the primary", p.Primary.Kind, m)
			}
			if err != nil {
				c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation), Reason: err.Error()})
				continue
			}
		}
		id, env, err := sentinel.CheckGenome(outbox, rec)
		if err == nil && env.EscrowKey != escrowTag {
			err = fmt.Errorf("its key is escrowed to %s, not to this authority's %s", env.EscrowKey, escrowTag)
		}
		var files map[string]string
		if err == nil {
			files, err = tree.Files(id.Header)
		}
		if err != nil {
			c.SetAside = append(c.SetAside, sentinel.Rejected{File: sentinel.RecordName(rec.Generation), Reason: err.Error()})
			continue
		}
		c.Record, c.Identity, c.Envelope = rec, id, env
		c.Expected = kms.ExpectedGenome{BundleSHA256: id.SHA256, PayloadSHA256: id.Header.PayloadSHA256, TreeSHA256: tree.Digest(files)}
		c.RPO = t.At.Sub(rec.SealedAt)
		if limit := time.Duration(p.MaxRPOSeconds) * time.Second; limit > 0 && c.RPO > limit {
			return c, fmt.Sprintf("the newest trustworthy genome, generation %d, was sealed %s before the trigger; the policy allows at most %s", rec.Generation, c.RPO.Round(time.Millisecond), limit), nil
		}
		return c, "", nil
	}
	return c, fmt.Sprintf("no genome in the verified chain was sealed by %s and checks out", cutoff.Format(time.RFC3339Nano)), nil
}
