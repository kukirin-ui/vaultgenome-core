// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package succession

import (
	"github.com/vault-genome/vaultgenome-core/internal/contracts/genome_descriptor"
	"github.com/vault-genome/vaultgenome-core/internal/genome/store"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
)

// Node is the data surface of a single visit during a walk. Descriptor
// is a fresh copy owned by the caller — mutating it does not affect the
// store. Depth is 0 at the root and increments per parent-edge traversed.
// ParentOf is the GenomeID of the descendant that reached this node, or
// zero at the root.
type Node struct {
	GenomeID   ids.GenomeID
	Descriptor *genome_descriptor.GenomeDescriptor
	Depth      int
	ParentOf   ids.GenomeID // the child that "called us" — zero at root
}

// VisitFunc is the pre-order visitor for Walk. Returning a non-nil error
// halts the traversal and surfaces the error to the caller.
type VisitFunc func(n *Node) error

// Options configures a walk. Zero value is safe.
type Options struct {
	// MaxDepth, if > 0, caps the traversal at this depth. A chain that
	// exceeds this bound returns an Operational error with code
	// "succession_depth_exceeded". 0 ⇒ unbounded.
	MaxDepth int

	// VerifySignatures, if true, re-verifies each ancestor's signature
	// against Resolver at visit time. The CAS already verified signatures
	// at Put, so this is defense-in-depth for paranoid callers. Requires
	// Resolver to be non-nil.
	VerifySignatures bool

	// Resolver is required iff VerifySignatures is true.
	Resolver keys.Resolver
}

// Walk traverses the ancestry of root via s in pre-order DFS, calling
// visit at every node (including root). The walker validates each edge
// before descending: missing ancestors, cycles, non-monotonic
// generations, and unknown derivation methods are all surfaced as
// classified errors.
//
// visit is invoked AFTER per-node validation — a callback that returns
// nil can trust the node's self-consistency. Returning a non-nil error
// from visit stops the walk and propagates the error unchanged.
func Walk(root ids.GenomeID, s store.Store, opt Options, visit VisitFunc) error {
	if s == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"succession: nil store",
			nil,
		)
	}
	if visit == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"succession: nil visit function",
			nil,
		)
	}
	if root.IsZero() {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"succession: root GenomeID required",
			nil,
		)
	}
	if opt.VerifySignatures && opt.Resolver == nil {
		return shared_errors.Structural(
			shared_errors.CodeRequiredFieldMissing,
			"succession: VerifySignatures requires Resolver",
			nil,
		)
	}

	w := &walker{
		store:   s,
		opt:     opt,
		visit:   visit,
		onStack: make(map[ids.GenomeID]struct{}),
	}
	// Root has no descendant-imposed generation cap.
	return w.descend(root, ids.GenomeID(""), 0, 0, false)
}

// Verify runs Walk with a no-op visitor. Use this when the caller only
// cares whether the chain validates, not the individual descriptors.
func Verify(root ids.GenomeID, s store.Store) error {
	return Walk(root, s, Options{}, func(_ *Node) error { return nil })
}

// VerifyWithSignatures is Verify plus per-ancestor signature re-check.
// Use when the backing CAS is untrusted or when building an attested
// disclosure that must cite the chain under fresh crypto.
func VerifyWithSignatures(root ids.GenomeID, s store.Store, resolver keys.Resolver) error {
	return Walk(root, s, Options{
		VerifySignatures: true,
		Resolver:         resolver,
	}, func(_ *Node) error { return nil })
}

// ---- internals -------------------------------------------------------------

type walker struct {
	store   store.Store
	opt     Options
	visit   VisitFunc
	onStack map[ids.GenomeID]struct{}
}

// descend implements the recursive pre-order DFS. parentOf is the
// GenomeID of the descendant that reached this node (zero at root).
// depth is 0 at root, +1 per edge. mustBeBelow encodes the descendant-
// imposed generation cap: when enforceMax is true, this node's
// Generation MUST be strictly less than mustBeBelow.
func (w *walker) descend(
	id ids.GenomeID,
	parentOf ids.GenomeID,
	depth int,
	mustBeBelow uint64,
	enforceMax bool,
) error {
	// Depth cap check FIRST so we don't load a descriptor we won't use.
	if w.opt.MaxDepth > 0 && depth > w.opt.MaxDepth {
		return shared_errors.Operational(
			"succession_depth_exceeded",
			"succession: walk exceeded MaxDepth",
			nil,
		)
	}
	// Cycle check: if this node is currently on the DFS stack, we have
	// a back-edge. Under SHA-256 this should be impossible; mark Incident.
	if _, cycle := w.onStack[id]; cycle {
		return shared_errors.Incident(
			shared_errors.CodeTamperSignal,
			"succession: cycle detected in ancestry DAG at "+id.String(),
			nil,
		)
	}

	// Load the descriptor. store.Get already enforces R-14 self-
	// consistency; an unknown ID surfaces as Authority which we
	// re-classify to Operational "ancestor_missing" — the chain is
	// simply not walkable from here, not necessarily adversarial.
	desc, err := w.store.Get(id)
	if err != nil {
		if shared_errors.CategoryOf(err) == shared_errors.CategoryAuthority {
			if enforceMax {
				return shared_errors.Operational(
					"succession_ancestor_missing",
					"succession: ancestor "+id.String()+" not in store (parent of "+parentOf.String()+")",
					err,
				)
			}
			// Root itself is missing — that's a caller mistake, not a
			// chain gap. Keep Structural semantics by re-wrapping.
			return shared_errors.Structural(
				shared_errors.CodeRequiredFieldMissing,
				"succession: root "+id.String()+" not in store",
				err,
			)
		}
		return err
	}

	// Generation monotonicity: parent must be strictly earlier than
	// the descendant that reached us. This gate is doctrinal (chain
	// monotonicity) and a forged generation number is a structural
	// attack on the continuity story ⇒ Incident.
	if enforceMax && desc.Generation >= mustBeBelow {
		return shared_errors.Incident(
			shared_errors.CodeTamperSignal,
			"succession: generation monotonicity violated at "+id.String(),
			nil,
		)
	}

	// Optional: re-verify signature end-to-end.
	if w.opt.VerifySignatures {
		if err := desc.VerifySignature(w.opt.Resolver); err != nil {
			return err
		}
	}

	// Push on DFS stack for cycle detection during descent.
	w.onStack[id] = struct{}{}
	defer delete(w.onStack, id)

	// Pre-order visit.
	if err := w.visit(&Node{
		GenomeID:   id,
		Descriptor: desc,
		Depth:      depth,
		ParentOf:   parentOf,
	}); err != nil {
		return err
	}

	// Recurse into each parent. The child's Generation becomes the cap
	// for its parents.
	for _, edge := range desc.Provenance.DerivedFrom {
		if edge.ParentGenomeID.IsZero() {
			// Already rejected by Validate inside Get, but defense in depth.
			return shared_errors.Integrity(
				shared_errors.CodeFieldValueInvalid,
				"succession: zero parent_genome_id in "+id.String(),
				nil,
			)
		}
		if err := w.descend(edge.ParentGenomeID, id, depth+1, desc.Generation, true); err != nil {
			return err
		}
	}
	return nil
}

// ---- convenience -----------------------------------------------------------

// Ancestors returns the set of ancestor GenomeIDs reachable from root,
// NOT including root itself. Useful for disclosure builders that need
// to list every genome a reconstruction depends on. Order matches
// pre-order DFS of the descent but duplicates are deduplicated so a
// diamond-shaped DAG (two merge-parents sharing a grandparent) yields
// each ID exactly once.
func Ancestors(root ids.GenomeID, s store.Store) ([]ids.GenomeID, error) {
	seen := make(map[ids.GenomeID]struct{})
	var order []ids.GenomeID
	err := Walk(root, s, Options{}, func(n *Node) error {
		if n.GenomeID == root {
			return nil
		}
		if _, dup := seen[n.GenomeID]; dup {
			return nil
		}
		seen[n.GenomeID] = struct{}{}
		order = append(order, n.GenomeID)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return order, nil
}
