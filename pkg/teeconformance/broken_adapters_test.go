// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package teeconformance_test

// The suite is only worth shipping if it catches the defects it names.
// A failing sub-test cannot be observed from inside the process that
// runs it, so each defective adapter is run in a child test process and
// the parent reads which sub-tests failed and which still passed.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"flag"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vault-genome/vaultgenome-core/pkg/teeconformance"
)

const brokenAdapterEnv = "TEECONFORMANCE_BROKEN_ADAPTER"

// ---- defective adapters --------------------------------------------------

var errAdapterDown = errors.New("broken adapter")

// brokenProducer either cannot quote at all or quotes for a nonce below
// the floor.
type brokenProducer struct {
	teeconformance.Producer
	quoteFails   bool
	acceptsShort bool
}

func (b brokenProducer) Quote(nonce teeconformance.Nonce) (teeconformance.Evidence, error) {
	if b.quoteFails {
		return nil, errAdapterDown
	}
	if b.acceptsShort && len(nonce) < teeconformance.NonceMinBytes {
		padded := append(append(teeconformance.Nonce(nil), nonce...), make([]byte, teeconformance.NonceMinBytes-len(nonce))...)
		return b.Producer.Quote(padded)
	}
	return b.Producer.Quote(nonce)
}

// brokenVerifier is a verifier with one defect: it errors on everything,
// accepts anything, or reports a measurement that is not the producer's.
type brokenVerifier struct {
	teeconformance.Verifier
	verifyFails bool
	rubberStamp teeconformance.Measurement // returned without any check when set
	reports     teeconformance.Measurement // returned in place of the real one when set
}

func (b brokenVerifier) Verify(ev teeconformance.Evidence, nonce teeconformance.Nonce) (teeconformance.Measurement, error) {
	if b.verifyFails {
		return nil, errAdapterDown
	}
	if b.rubberStamp != nil {
		return b.rubberStamp, nil
	}
	m, err := b.Verifier.Verify(ev, nonce)
	if err != nil {
		return nil, err
	}
	if b.reports != nil {
		return b.reports, nil
	}
	return m, nil
}

// brokenSealer is a sealer with one defect.
type brokenSealer struct {
	teeconformance.Sealer
	sealFails       bool
	secondSealFails bool
	unsealFails     bool
	wrongPlaintext  bool // unseals correctly, hands back other bytes
	permissive      bool // hands back the last plaintext whatever the blob or AAD
	deterministic   bool // the same blob for the same input

	mu    sync.Mutex
	seals int
	last  []byte
}

func (b *brokenSealer) Seal(pt, aad []byte) ([]byte, error) {
	b.mu.Lock()
	b.seals++
	n := b.seals
	b.last = append([]byte(nil), pt...)
	b.mu.Unlock()
	if b.sealFails || (b.secondSealFails && n == 2) {
		return nil, errAdapterDown
	}
	if b.deterministic {
		return fixedNonceAEAD().Seal(nil, make([]byte, 12), pt, aad), nil
	}
	return b.Sealer.Seal(pt, aad)
}

// fixedNonceAEAD is AES-GCM under a constant key: a sound cipher, used
// here with a constant nonce, which is the defect the suite must catch.
func fixedNonceAEAD() cipher.AEAD {
	block, err := aes.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

func (b *brokenSealer) Unseal(sealed, aad []byte) ([]byte, error) {
	if b.unsealFails {
		return nil, errAdapterDown
	}
	if b.permissive {
		b.mu.Lock()
		defer b.mu.Unlock()
		return append([]byte(nil), b.last...), nil
	}
	if b.deterministic {
		return fixedNonceAEAD().Open(nil, make([]byte, 12), sealed, aad)
	}
	pt, err := b.Sealer.Unseal(sealed, aad)
	if err != nil {
		return nil, err
	}
	if b.wrongPlaintext {
		return append([]byte("not-"), pt...), nil
	}
	return pt, nil
}

// ---- the variants and what the suite must say about each -----------------

type variant struct {
	producer func(p teeconformance.Producer) teeconformance.Producer
	verifier func(v teeconformance.Verifier) teeconformance.Verifier
	sealer   func(s teeconformance.Sealer) *brokenSealer
	failing  []string // sub-tests that must fail
	passing  []string // sub-tests that must still pass
	message  string   // a diagnostic the failing output must carry
}

var producerVerifierSubtests = []string{"RoundTrip", "NonceFloor_Producer", "NonceFloor_Verifier", "Replay", "Tamper", "MeasurementStability"}
var sealerSubtests = []string{"RoundTrip", "WrongAAD", "Tamper", "DistinctNoncePerSeal", "Truncation", "CrossInstance"}

// rest returns every sub-test of all that is not in failing.
func rest(all, failing []string) []string {
	var out []string
	for _, s := range all {
		skip := false
		for _, f := range failing {
			if s == f {
				skip = true
			}
		}
		if !skip {
			out = append(out, s)
		}
	}
	return out
}

func pvVariant(failing []string, message string, producer func(teeconformance.Producer) teeconformance.Producer, verifier func(teeconformance.Verifier) teeconformance.Verifier) variant {
	return variant{producer: producer, verifier: verifier, failing: failing, passing: rest(producerVerifierSubtests, failing), message: message}
}

func sealerVariant(failing []string, message string, sealer func(teeconformance.Sealer) *brokenSealer) variant {
	return variant{sealer: sealer, failing: failing, passing: rest(sealerSubtests, failing), message: message}
}

func identityProducer(p teeconformance.Producer) teeconformance.Producer { return p }
func identityVerifier(v teeconformance.Verifier) teeconformance.Verifier { return v }

var variants = map[string]variant{
	"producer cannot quote": pvVariant(
		[]string{"RoundTrip", "NonceFloor_Verifier", "Replay", "Tamper", "MeasurementStability"}, "Quote: broken adapter",
		func(p teeconformance.Producer) teeconformance.Producer {
			return brokenProducer{Producer: p, quoteFails: true}
		}, identityVerifier),
	"producer quotes for a short nonce": pvVariant(
		[]string{"NonceFloor_Producer"}, "expected producer to reject short nonce",
		func(p teeconformance.Producer) teeconformance.Producer {
			return brokenProducer{Producer: p, acceptsShort: true}
		}, identityVerifier),
	"verifier cannot verify": pvVariant(
		[]string{"RoundTrip", "MeasurementStability"}, "Verify: broken adapter",
		identityProducer, func(v teeconformance.Verifier) teeconformance.Verifier {
			return brokenVerifier{Verifier: v, verifyFails: true}
		}),
	"verifier accepts anything": pvVariant(
		[]string{"NonceFloor_Verifier", "Replay", "Tamper"}, "expected replay rejection",
		identityProducer, func(v teeconformance.Verifier) teeconformance.Verifier {
			return brokenVerifier{Verifier: v, rubberStamp: measure(32, []byte("ref-workload-child"))}
		}),
	"verifier reports another measurement": pvVariant(
		[]string{"RoundTrip", "MeasurementStability"}, "verifier returned",
		identityProducer, func(v teeconformance.Verifier) teeconformance.Verifier {
			return brokenVerifier{Verifier: v, reports: measure(32, []byte("someone else"))}
		}),
	"verifier truncates the measurement": pvVariant(
		[]string{"RoundTrip", "MeasurementStability"}, "31-byte measurement",
		identityProducer, func(v teeconformance.Verifier) teeconformance.Verifier {
			return brokenVerifier{Verifier: v, reports: measure(32, []byte("someone else"))[:31]}
		}),
	"verifier reports all zeros": pvVariant(
		[]string{"RoundTrip", "MeasurementStability"}, "all-zero measurement",
		identityProducer, func(v teeconformance.Verifier) teeconformance.Verifier {
			return brokenVerifier{Verifier: v, reports: make(teeconformance.Measurement, 32)}
		}),
	"sealer cannot seal": sealerVariant(
		sealerSubtests, "Seal: broken adapter",
		func(s teeconformance.Sealer) *brokenSealer { return &brokenSealer{Sealer: s, sealFails: true} }),
	"sealer fails on the second seal": sealerVariant(
		[]string{"DistinctNoncePerSeal"}, "Seal b: broken adapter",
		func(s teeconformance.Sealer) *brokenSealer { return &brokenSealer{Sealer: s, secondSealFails: true} }),
	"sealer cannot unseal": sealerVariant(
		[]string{"RoundTrip", "CrossInstance"}, "sealing key not stable across rebuild",
		func(s teeconformance.Sealer) *brokenSealer { return &brokenSealer{Sealer: s, unsealFails: true} }),
	"sealer returns other bytes": sealerVariant(
		[]string{"RoundTrip", "CrossInstance"}, "plaintext mismatch",
		func(s teeconformance.Sealer) *brokenSealer { return &brokenSealer{Sealer: s, wrongPlaintext: true} }),
	"sealer accepts any blob or AAD": sealerVariant(
		[]string{"WrongAAD", "Tamper", "Truncation"}, "expected unseal to reject",
		func(s teeconformance.Sealer) *brokenSealer { return &brokenSealer{Sealer: s, permissive: true} }),
	"sealer reuses its nonce": sealerVariant(
		[]string{"DistinctNoncePerSeal"}, "nonce reuse",
		func(s teeconformance.Sealer) *brokenSealer { return &brokenSealer{Sealer: s, deterministic: true} }),
}

// TestContract_CatchesEveryDefectItNames runs each defective adapter
// through the suite in a child process and checks that exactly the
// sub-tests guarding that defect fail, that the others still pass, and
// that the failure carries its diagnostic.
func TestContract_CatchesEveryDefectItNames(t *testing.T) {
	if os.Getenv(brokenAdapterEnv) != "" {
		return // we are the child; TestBrokenAdapterChild does the work
	}
	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			args := []string{"-test.run=^TestBrokenAdapterChild$", "-test.v"}
			if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
				args = append(args, "-test.gocoverdir="+f.Value.String())
			}
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), brokenAdapterEnv+"="+name)
			out, err := cmd.CombinedOutput()
			text := string(out)
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("the child must fail with a test failure, got err=%v\n%s", err, text)
			}
			for _, sub := range v.failing {
				if !strings.Contains(text, "--- FAIL: TestBrokenAdapterChild/"+sub+" ") {
					t.Errorf("sub-test %s did not fail for this defect\n%s", sub, text)
				}
			}
			for _, sub := range v.passing {
				if !strings.Contains(text, "--- PASS: TestBrokenAdapterChild/"+sub+" ") {
					t.Errorf("sub-test %s did not pass although the defect does not concern it\n%s", sub, text)
				}
			}
			if !strings.Contains(text, v.message) {
				t.Errorf("failure output lacks the diagnostic %q\n%s", v.message, text)
			}
		})
	}
}

// TestBrokenAdapterChild is the child side: it runs the suite against the
// defective adapter named in the environment. Outside a child process it
// has nothing to do.
func TestBrokenAdapterChild(t *testing.T) {
	name := os.Getenv(brokenAdapterEnv)
	if name == "" {
		return
	}
	v, ok := variants[name]
	if !ok {
		t.Fatalf("unknown adapter variant %q", name)
	}
	if v.sealer != nil {
		teeconformance.RunSealerContract(t, func(tt teeconformance.Tester) (teeconformance.Sealer, func(teeconformance.Tester) teeconformance.Sealer) {
			gt, ok := tt.(*testing.T)
			if !ok {
				tt.Fatal("expected *testing.T")
			}
			_, _, s, rebuild := newRefBackend(gt, "child", 32)
			broken := v.sealer(s)
			return broken, func(teeconformance.Tester) teeconformance.Sealer {
				again := v.sealer(rebuild())
				broken.mu.Lock()
				last := append([]byte(nil), broken.last...)
				broken.mu.Unlock()
				again.mu.Lock()
				again.last = last
				again.mu.Unlock()
				return again
			}
		})
		return
	}
	teeconformance.RunProducerVerifierContract(t, func(tt teeconformance.Tester) (teeconformance.Producer, teeconformance.Verifier) {
		gt, ok := tt.(*testing.T)
		if !ok {
			tt.Fatal("expected *testing.T")
		}
		p, verifier, _, _ := newRefBackend(gt, "child", 32)
		return v.producer(p), v.verifier(verifier)
	})
}

// A sanity check on the harness itself: the reference adapter run the
// same way passes every sub-test.
func TestBrokenAdapterHarness_ReferencePasses(t *testing.T) {
	if os.Getenv(brokenAdapterEnv) != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"-test.run=^TestConformance_ReferenceBackend_", "-test.v"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), brokenAdapterEnv+"=reference")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the reference adapter must pass: %v\n%s", err, out)
	}
	for _, sub := range sealerSubtests {
		if !strings.Contains(string(out), "--- PASS: TestConformance_ReferenceBackend_Sealer/"+sub+" ") {
			t.Errorf("reference sealer sub-test %s not reported as passing\n%s", sub, out)
		}
	}
}
