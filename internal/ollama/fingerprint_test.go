// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package ollama

import (
	"testing"
)

// The fingerprint follows the manifest: a model whose content changed has
// a new manifest, and so a new fingerprint.
func TestFingerprint_FollowsTheManifest(t *testing.T) {
	home, mf := fakeStore(t, "llama3.2:3b", config, weights, template)
	before, err := Fingerprint("llama3.2:3b", home)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Fingerprint("llama3.2:3b", home)
	if err != nil || again != before {
		t.Fatalf("fingerprint moved without a change: %s, %s (%v)", before, again, err)
	}
	mf.Layers = mf.Layers[:1]
	writeManifest(t, home, "llama3.2:3b", mf)
	after, err := Fingerprint("llama3.2:3b", home)
	if err != nil || after == before {
		t.Fatalf("a new manifest kept fingerprint %s (%v)", after, err)
	}
	if _, err := Fingerprint("absent:1", home); err == nil {
		t.Fatal("fingerprint of a model that is not there")
	}
	if _, err := Fingerprint("../escape", home); err == nil {
		t.Fatal("fingerprint of an invalid ref")
	}
}
