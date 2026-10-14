// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package reassembly_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/vault-genome/vaultgenome-core/internal/genome/componenttree"
	"github.com/vault-genome/vaultgenome-core/internal/reassembly"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
)

// Benchmarks for /internal/reassembly.AGDReassembler.
//
// Finalize is the hot path on the receive side: it opens every
// DisclosureMessage, compares plaintext hashes and sizes against the
// AGD's committed (Path, Kind, ByteSize, Hash) tuples, rebuilds the
// component Merkle tree, and verifies the rebuilt root against the
// signed ComponentTreeRoot. The vault's performance budget for a full
// bootstrap restore depends on how this scales with component count.
//
// The benchmark sweeps a small set of realistic component counts. Each
// iteration creates a fresh AGDReassembler against a pre-built harness
// (the per-iteration setup cost is dominated by the harness-level
// fixtures, which are created once via b.ResetTimer), admits all N
// messages, and calls Finalize.
//
// The benchmark is NOT a correctness test; it exists to surface
// regressions (e.g. O(N²) accidents in the Merkle rebuild or an
// un-batched crypto call in Admit). The test suite in
// agd_reassembler_test.go owns the correctness contract.

// benchSpec constructs N fixture components with moderate plaintext
// sizes. Size distribution approximates a real model drop:
//
//   - one "config" blob (~256 B)
//   - one "tokenizer" blob (~1 KB)
//   - N-2 "tensor" shards of ~1 KB each
//
// Each shard has a distinct byte prefix so plaintext hashes never
// collide — BuildTree rejects duplicate (path, hash) tuples at
// validation, so non-unique shards would fail harness setup before
// the benchmark body ever runs.
func benchSpec(n int) []compSpec {
	if n < 2 {
		n = 2
	}
	out := make([]compSpec, 0, n)

	out = append(out, compSpec{
		cid:       ids.ComponentID("c-cfg"),
		path:      "config/architecture",
		kind:      componenttree.KindConfig,
		plaintext: bytes.Repeat([]byte{0xC0}, 256),
	})
	out = append(out, compSpec{
		cid:       ids.ComponentID("c-tok"),
		path:      "tokenizer/vocab",
		kind:      componenttree.KindTokenizer,
		plaintext: bytes.Repeat([]byte{0xD1}, 1024),
	})

	for i := 0; i < n-2; i++ {
		payload := bytes.Repeat([]byte{byte(0xA0 + (i % 16))}, 1024)
		// First 8 bytes: shard index, so payloads stay unique across
		// the full N range regardless of the repeating byte pattern.
		for j := 0; j < 8; j++ {
			payload[j] = byte(i >> (j * 8))
		}
		out = append(out, compSpec{
			cid:       ids.ComponentID(fmt.Sprintf("c-shard-%04d", i)),
			path:      fmt.Sprintf("weights/shard-%04d", i),
			kind:      componenttree.KindTensor,
			plaintext: payload,
		})
	}
	return out
}

// benchSizes brackets the expected MVP model drop range:
//
//   - n=4:   a descriptor-only / tiny-head bundle.
//   - n=16:  small model with a few shards.
//   - n=64:  realistic multi-shard drop.
//   - n=256: stress size that exercises the Merkle tree's largest
//     branching level within the RFC 6962 promotion geometry.
var benchSizes = []int{4, 16, 64, 256}

// BenchmarkAGDReassembler_Finalize measures the New + Admit*N +
// Finalize pipeline as a whole. The bootstrap orchestrator pays for
// all three back-to-back, so this is the most operationally-meaningful
// number.
func BenchmarkAGDReassembler_Finalize(b *testing.B) {
	for _, n := range benchSizes {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			h := buildHarness(b, benchSpec(n))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
				if err != nil {
					b.Fatalf("NewAGDReassembler: %v", err)
				}
				for _, m := range h.messages {
					if err := r.Admit(m); err != nil {
						b.Fatalf("Admit: %v", err)
					}
				}
				res, err := r.Finalize()
				if err != nil {
					b.Fatalf("Finalize: %v", err)
				}
				// Use the result so the compiler can't DCE it.
				if len(res.Components) != n {
					b.Fatalf("unexpected component count: got=%d want=%d",
						len(res.Components), n)
				}
			}
		})
	}
}

// BenchmarkAGDReassembler_FinalizeOnly isolates Finalize from the
// admission path via StopTimer/StartTimer. The numbers here are purely
// the Finalize bookkeeping cost — tree rebuild, root comparison, and
// plaintext-map rewrite by Path — and are directly comparable across N
// without the AEAD-throughput noise that Admit introduces.
func BenchmarkAGDReassembler_FinalizeOnly(b *testing.B) {
	for _, n := range benchSizes {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			h := buildHarness(b, benchSpec(n))
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				r, err := reassembly.NewAGDReassembler(h.agd, h.compMap, h.store)
				if err != nil {
					b.Fatalf("NewAGDReassembler: %v", err)
				}
				for _, m := range h.messages {
					if err := r.Admit(m); err != nil {
						b.Fatalf("Admit: %v", err)
					}
				}
				b.StartTimer()

				if _, err := r.Finalize(); err != nil {
					b.Fatalf("Finalize: %v", err)
				}
			}
		})
	}
}
