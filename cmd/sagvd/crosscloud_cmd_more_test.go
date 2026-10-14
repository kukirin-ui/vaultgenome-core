// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vault-genome/vaultgenome-core/internal/bootstrap/crosscloud"
	"github.com/vault-genome/vaultgenome-core/internal/compute/returnpath/server"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/genome/bundle"
	"github.com/vault-genome/vaultgenome-core/internal/genome/escrow"
	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	shared_errors "github.com/vault-genome/vaultgenome-core/internal/shared/errors"
	"github.com/vault-genome/vaultgenome-core/internal/shared/ids"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	shared_time "github.com/vault-genome/vaultgenome-core/internal/shared/time"
	"github.com/vault-genome/vaultgenome-core/internal/vault/keys"
	"github.com/vault-genome/vaultgenome-core/internal/vault/kms"
)

// A key release crosses the network only under TLS, or to this host.
func TestCheckDestinationEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		endpoint string
		want     string
	}{
		"https":          {"https://standby.example:8443", ""},
		"http loopback":  {"http://127.0.0.1:8443", ""},
		"http localhost": {"http://localhost:8443", ""},
		"http elsewhere": {"http://10.0.0.8:8443", "plain http is accepted only for a loopback destination"},
		"other scheme":   {"ftp://standby.example", "scheme must be https"},
		"no host":        {"standby.example:8443", "is not an absolute URL"},
		"empty":          {"", "is not an absolute URL"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkDestinationEndpoint(tc.endpoint)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestClassifyEnvelopeCategory(t *testing.T) {
	for want, err := range map[string]error{
		"structural":  shared_errors.Structural("c", "m", nil),
		"authority":   shared_errors.Authority("c", "m", nil),
		"integrity":   shared_errors.Integrity("c", "m", nil),
		"operational": shared_errors.Operational("c", "m", nil),
		"incident":    shared_errors.Incident("c", "m", nil),
		"unknown":     errors.New("plain"),
	} {
		require.Equal(t, want, classifyEnvelopeCategory(err), want)
	}
	require.Equal(t, "unknown", errCodeOrUnknown(errors.New("plain")))
	require.Equal(t, "c", errCodeOrUnknown(shared_errors.Operational("c", "m", nil)))
}

// What the coordinator found is printed field for field, with the
// destination's measurement and recipient key in hex and the dispatch time
// to the millisecond.
func TestBuildCoordinationOutput_CarriesEveryField(t *testing.T) {
	at := time.Date(2026, 10, 14, 12, 30, 45, 123_000_000, time.UTC)
	res := kms.CoordinationResult{
		HandshakeRequestID: "xcc-req-1", HandshakeAuditID: "xcc-evt-1", AttestationAuditID: "xcc-evt-2", KeyReleaseAuditID: "xcc-evt-3",
		DestinationMeasurement: bytes.Repeat([]byte{0xab}, 32), RecipientKeySHA256: bytes.Repeat([]byte{0xcd}, 32),
		PolicyVersion: "v1;revocation=1", TokenID: "xcc-dec-1", DispatchedAt: at,
	}
	out := buildCoordinationOutput(res, nil, 3)
	require.Equal(t, coordinationOutput{
		Status: "ok", HandshakeRequestID: "xcc-req-1", HandshakeAuditID: "xcc-evt-1", AttestationAuditID: "xcc-evt-2", KeyReleaseAuditID: "xcc-evt-3",
		DestinationMeasurement: hex.EncodeToString(res.DestinationMeasurement), RecipientKeySHA256: hex.EncodeToString(res.RecipientKeySHA256),
		PolicyVersion: "v1;revocation=1", TokenID: "xcc-dec-1", DispatchedAt: "2026-10-14T12:30:45.123Z", AuditChainLength: 3,
	}, out)
}

// A key file must be a file: a directory of the right mode is not a key.
func TestReadKeyFiles_DirectoryIsNotAKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keydir")
	require.NoError(t, os.Mkdir(dir, 0o700))
	_, err := readKeyFiles([]string{"vault-dek-1:" + dir})
	require.ErrorContains(t, err, "is a directory")
}

// destination is an in-process acp-bootstrap: the standby's simulated TEE
// behind the cross-cloud receiver, over a loopback HTTP server.
type destination struct {
	tee       *tee.Simulated
	srv       *httptest.Server
	mu        sync.Mutex
	delivered []crosscloud.Delivery
}

func (d *destination) deliveries() []crosscloud.Delivery {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]crosscloud.Delivery(nil), d.delivered...)
}

// newDestination starts the standby, trusting the authority key f holds.
func newDestination(t *testing.T, f *materialFixture) *destination {
	t.Helper()
	sim, err := tee.NewSimulated([]byte("standby-v1"), bytes.Repeat([]byte{0xD1}, 32))
	require.NoError(t, err)
	authPub, _, err := crypto.Ed25519FromSeed(f.authSeed)
	require.NoError(t, err)
	resolver := server.NewPublicKeyResolver(map[ids.KeyID]keys.VerifyingKey{
		ids.KeyID(f.cfg.Keys.AuthoritySigning.KeyID): {KeyID: ids.KeyID(f.cfg.Keys.AuthoritySigning.KeyID), Purpose: keys.PurposeSigningAuthority, PublicKey: authPub},
	})
	d := &destination{tee: sim}
	receiver, err := crosscloud.NewReceiver(crosscloud.Config{
		SourceAuthorityKeys: resolver, LocalTEE: sim, Kind: tee.ProviderSimulated, Registrar: keys.NewInMemoryStore(shared_time.NewSystemClock()),
		OnDelivery: func(del crosscloud.Delivery) { d.mu.Lock(); d.delivered = append(d.delivered, del); d.mu.Unlock() },
	})
	require.NoError(t, err)
	handler, err := crosscloud.NewHTTPHandler(crosscloud.HTTPHandlerConfig{Receiver: receiver, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	require.NoError(t, err)
	mux := http.NewServeMux()
	for path, h := range handler.Routes() {
		mux.HandleFunc(path, h)
	}
	d.srv = httptest.NewServer(mux)
	t.Cleanup(d.srv.Close)
	return d
}

// crossCloudFixture is a release authority configured to release to the
// destination: its keys, the standby pinned in the verifier registry and
// the allow list, the audit log and the operator's stop list.
type crossCloudFixture struct {
	*materialFixture
	dest    *destination
	cfgPath string
}

func newCrossCloudFixture(t *testing.T) *crossCloudFixture {
	t.Helper()
	f := newMaterialFixture(t)
	dest := newDestination(t, f)
	xdir := t.TempDir()
	meas := hex.EncodeToString(dest.tee.Measurement())
	pubPath := writeFile(t, xdir, "standby.pub", []byte(dest.tee.PublicKey()))
	f.cfg.CrossCloud = CrossCloudConfig{
		Enabled: true, PolicyVersion: "v1", InsecureSimulatedDestinations: true, RequestTimeoutSeconds: 5,
		VerifierRegistryPath: writeFile(t, xdir, "registry.json", []byte(`{"verifiers":[{"provider":"simulated","attestor_pubkey_path":"`+pubPath+`","expected_measurement_hex":"`+meas+`"}]}`)),
		PolicyAllowListPath:  writeFile(t, xdir, "allow.json", []byte(`{"version":"v1","allowed":{"simulated":["`+meas+`"]}}`)),
	}
	withAuditLog(t, xdir, &f.cfg)
	require.NoError(t, f.cfg.Validate())
	x := &crossCloudFixture{materialFixture: f, dest: dest}
	x.cfgPath = x.write(t, "sagvd.json", f.cfg)
	return x
}

func (x *crossCloudFixture) write(t *testing.T, name string, cfg Config) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	return writeFile(t, x.dir, name, raw)
}

func (x *crossCloudFixture) events(t *testing.T) []audit_event.Kind {
	t.Helper()
	xcc, err := LoadCrossCloudMaterials(x.cfg, shared_time.NewSystemClock())
	require.NoError(t, err)
	defer func() { _ = xcc.Close() }()
	var kinds []audit_event.Kind
	for _, e := range xcc.AuditChain.Events() {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

// crosscloud-restore refuses, after reading the config and before any
// handshake, a config it cannot run under, material it cannot load, and
// escrowed keys it cannot open or was given twice.
func TestCrossCloudRestoreCmd_RefusesAfterReadingTheConfig(t *testing.T) {
	x := newCrossCloudFixture(t)
	kid, keyPath, dek := sealedGenomeKey(t, x.dir)
	escrowPriv, err := escrow.GenerateKey()
	require.NoError(t, err)
	env, err := escrow.Seal(dek, kid, escrowPriv.PublicKey())
	require.NoError(t, err)
	envRaw, err := env.Marshal()
	require.NoError(t, err)
	envPath := writeFile(t, x.dir, kid+".escrow", envRaw)
	escrowKey := writeFile(t, x.dir, "escrow.key", escrowPriv.Bytes())
	require.NoError(t, os.Chmod(escrowKey, 0o600))

	invalid := x.cfg
	invalid.TEE.Provider = "vmware"
	disabled := x.cfg
	disabled.CrossCloud.Enabled = false
	noPeer := x.cfg
	noPeer.TEE.Peer.MeasurementPath = filepath.Join(x.dir, "absent")
	withEscrow := x.cfg
	withEscrow.CrossCloud.KeyEscrowPath = escrowKey
	noRegistry := x.cfg
	noRegistry.CrossCloud.VerifierRegistryPath = filepath.Join(x.dir, "absent.json")
	base := []string{"-decision-id", "dec-1", "-destination-kind", "simulated", "-destination-endpoint", x.dest.srv.URL}

	for name, tc := range map[string]struct {
		cfgPath string
		extra   []string
		want    string
	}{
		"invalid config":           {x.write(t, "invalid.json", invalid), []string{"-key-file", kid + ":" + keyPath}, "crosscloud-restore: config validation"},
		"crosscloud disabled":      {x.write(t, "disabled.json", disabled), []string{"-key-file", kid + ":" + keyPath}, "crosscloud.enabled=false"},
		"materials missing":        {x.write(t, "nopeer.json", noPeer), []string{"-key-file", kid + ":" + keyPath}, "tee.peer.measurement_path"},
		"escrow without a key":     {x.cfgPath, []string{"-key-escrow", envPath}, "needs crosscloud.key_escrow_path"},
		"escrowed key given twice": {x.write(t, "escrow.json", withEscrow), []string{"-key-file", kid + ":" + keyPath, "-key-escrow", envPath}, "given twice"},
		"registry missing":         {x.write(t, "noregistry.json", noRegistry), []string{"-key-file", kid + ":" + keyPath}, "verifier_registry_path"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"-config", tc.cfgPath}, base...)
			require.ErrorContains(t, runCrossCloudRestoreCmd(append(args, tc.extra...)), tc.want)
		})
	}
	require.Empty(t, x.dest.deliveries(), "nothing reached the destination")
}

// The release end to end: the authority handshakes with the attested
// standby, verifies its evidence against the pin, authorises under the
// allow list and the operator's stop list, wraps the key to the standby's
// handshake key and dispatches the token; the standby registers the key.
// Every step is on the audit log, and the printed result says so. A
// destination that cannot be reached fails after the handshake was
// recorded as initiated, with the failure classified.
func TestCrossCloudRestoreCmd_ReleasesToAnAttestedDestination(t *testing.T) {
	x := newCrossCloudFixture(t)
	kid, keyPath, _ := sealedGenomeKey(t, x.dir)
	args := []string{"-config", x.cfgPath, "-decision-id", "dec-e2e-1", "-destination-kind", "simulated", "-destination-endpoint", x.dest.srv.URL,
		"-key-file", kid + ":" + keyPath, "-session-id", "ses-e2e", "-manifest-id", "rjm-e2e"}
	var err error
	printed := captureStdout(t, func() { err = runCrossCloudRestoreCmd(args) })
	require.NoError(t, err)
	var out coordinationOutput
	require.NoError(t, json.Unmarshal([]byte(printed), &out), printed)
	require.Equal(t, "ok", out.Status)
	require.Nil(t, out.Error)
	require.NotEmpty(t, out.TokenID)
	require.NotEmpty(t, out.HandshakeRequestID)
	require.Equal(t, hex.EncodeToString(x.dest.tee.Measurement()), out.DestinationMeasurement)
	require.Equal(t, "v1;revocation=1", out.PolicyVersion)
	require.Equal(t, 3, out.AuditChainLength)
	require.Len(t, out.AuditTip, 64)
	require.Equal(t, uint64(1), out.StopSerial)
	require.NotEmpty(t, out.DispatchedAt)

	deliveries := x.dest.deliveries()
	require.Len(t, deliveries, 1)
	require.Equal(t, ids.DecisionID("dec-e2e-1"), deliveries[0].DecisionID)
	require.Equal(t, []ids.KeyID{ids.KeyID(kid)}, deliveries[0].KeyIDs)
	require.Equal(t, out.TokenID, deliveries[0].TokenID)
	require.Equal(t, []audit_event.Kind{audit_event.KindCrossCloudHandshakeInitiated, audit_event.KindCrossCloudAttestationVerified, audit_event.KindKeyReleaseAuthorized}, x.events(t))

	// An escrowed genome key is opened with the authority's escrow key and
	// released the same way; the binary's crosscloud-restore subcommand is
	// this function.
	escrowPriv, err := escrow.GenerateKey()
	require.NoError(t, err)
	escrowKey := writeFile(t, x.dir, "escrow.key", escrowPriv.Bytes())
	require.NoError(t, os.Chmod(escrowKey, 0o600))
	withEscrow := x.cfg
	withEscrow.CrossCloud.KeyEscrowPath = escrowKey
	kid2, _, dek2 := sealedGenomeKey(t, t.TempDir())
	env, err := escrow.Seal(dek2, kid2, escrowPriv.PublicKey())
	require.NoError(t, err)
	envRaw, err := env.Marshal()
	require.NoError(t, err)
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"sagvd", "crosscloud-restore", "-config", x.write(t, "escrow.json", withEscrow), "-decision-id", "dec-e2e-2", "-destination-kind", "simulated",
		"-destination-endpoint", x.dest.srv.URL, "-key-escrow", writeFile(t, x.dir, kid2+".escrow", envRaw)}
	var escrowed coordinationOutput
	require.NoError(t, json.Unmarshal([]byte(captureStdout(t, main)), &escrowed))
	require.Equal(t, "ok", escrowed.Status)
	require.Len(t, x.dest.deliveries(), 2)
	require.Equal(t, []ids.KeyID{ids.KeyID(kid2)}, x.dest.deliveries()[1].KeyIDs)

	// Nothing listens here: the handshake is on record as initiated, the
	// failure is classified and printed, and the command fails.
	args[7] = "http://127.0.0.1:1"
	var failed coordinationOutput
	printed = captureStdout(t, func() { err = runCrossCloudRestoreCmd(args) })
	require.Error(t, err)
	require.NoError(t, json.Unmarshal([]byte(printed), &failed), printed)
	require.Equal(t, "failed", failed.Status)
	require.NotNil(t, failed.Error)
	require.Equal(t, "operational", failed.Error.Category)
	require.Equal(t, 7, failed.AuditChainLength)
	require.Empty(t, failed.TokenID)
	require.Len(t, x.dest.deliveries(), 2, "nothing more reached the standby")
}

// crosscloud-confirm refuses, after reading the config, what the restore
// command refuses, and a decision the audit log does not record a release
// for; a release it does record is confirmed against the destination's
// receipt — which this destination does not serve — and an unreachable
// destination is asked again until -wait runs out.
func TestCrossCloudConfirmCmd_ConfirmsFromTheRecord(t *testing.T) {
	x := newCrossCloudFixture(t)
	kid, keyPath, _ := sealedGenomeKey(t, x.dir)
	var err error
	captureStdout(t, func() {
		err = runCrossCloudRestoreCmd([]string{"-config", x.cfgPath, "-decision-id", "dec-c-1", "-destination-kind", "simulated",
			"-destination-endpoint", x.dest.srv.URL, "-key-file", kid + ":" + keyPath})
	})
	require.NoError(t, err)

	invalid := x.cfg
	invalid.TEE.Provider = "vmware"
	disabled := x.cfg
	disabled.CrossCloud.Enabled = false
	noPeer := x.cfg
	noPeer.TEE.Peer.MeasurementPath = filepath.Join(x.dir, "absent")
	noRegistry := x.cfg
	noRegistry.CrossCloud.VerifierRegistryPath = filepath.Join(x.dir, "absent.json")
	for name, tc := range map[string]struct {
		cfgPath string
		want    string
	}{
		"invalid config":      {x.write(t, "invalid.json", invalid), "crosscloud-confirm: config validation"},
		"missing config":      {filepath.Join(x.dir, "absent.json"), "absent.json"},
		"crosscloud disabled": {x.write(t, "disabled.json", disabled), "crosscloud.enabled=false"},
		"materials missing":   {x.write(t, "nopeer.json", noPeer), "tee.peer.measurement_path"},
		"registry missing":    {x.write(t, "noregistry.json", noRegistry), "verifier_registry_path"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runCrossCloudConfirmCmd([]string{"-config", tc.cfgPath, "-decision-id", "dec-c-1", "-destination-endpoint", x.dest.srv.URL, "-key-id", kid})
			require.ErrorContains(t, err, tc.want)
		})
	}

	require.ErrorContains(t, runCrossCloudConfirmCmd([]string{"-nope"}), "flag provided but not defined")

	// The operator's bundle names the key and what the destination must
	// have restored; it is read before the config.
	digest := "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	blob, _, err := bundle.SealBytes(bundle.Header{ContentKind: bundle.ContentDir, ContentRef: "/adapters/2",
		ContentSnapshot: []byte(`{"components":[{"path":"adapter/model.bin","digest":"` + digest + `"}]}`)}, []byte("adapter"))
	require.NoError(t, err)
	bundlePath := writeFile(t, x.dir, "operator.genome", blob)
	bundleID, err := bundle.Identify(bundlePath)
	require.NoError(t, err)
	var out confirmOutput
	printed := captureStdout(t, func() {
		err = runCrossCloudConfirmCmd([]string{"-config", x.cfgPath, "-decision-id", "dec-c-1", "-destination-endpoint", x.dest.srv.URL, "-bundle", bundlePath})
	})
	require.Error(t, err, "the release was for another genome's key")
	require.NoError(t, json.Unmarshal([]byte(printed), &out), printed)
	require.Equal(t, bundleID.Header.KeyID, out.KeyID, "the key the bundle names")
	require.Equal(t, "failed", out.Status)

	printed = captureStdout(t, func() {
		err = runCrossCloudConfirmCmd([]string{"-config", x.cfgPath, "-decision-id", "dec-unknown", "-destination-endpoint", x.dest.srv.URL, "-key-id", kid})
	})
	require.ErrorContains(t, err, "records no authorized release")
	require.NoError(t, json.Unmarshal([]byte(printed), &out), printed)
	require.Equal(t, "failed", out.Status)
	require.Equal(t, "authority", out.Error.Category)
	require.Equal(t, "dec-unknown", out.DecisionID)
	require.Equal(t, 3, out.AuditChainLength)

	printed = captureStdout(t, func() {
		err = runCrossCloudConfirmCmd([]string{"-config", x.cfgPath, "-decision-id", "dec-c-1", "-destination-endpoint", x.dest.srv.URL, "-key-id", kid})
	})
	require.Error(t, err, "this destination serves no receipt")
	require.NoError(t, json.Unmarshal([]byte(printed), &out), printed)
	require.Equal(t, "failed", out.Status)
	require.Equal(t, kid, out.KeyID)
	require.False(t, out.MatchedOperatorBundle)
	require.Len(t, out.AuditTip, 64)

	// A destination that cannot be reached is asked again while -wait
	// allows, then the failure is reported.
	before := confirmPoll
	confirmPoll = 20 * time.Millisecond
	t.Cleanup(func() { confirmPoll = before })
	start := time.Now()
	printed = captureStdout(t, func() {
		err = runCrossCloudConfirmCmd([]string{"-config", x.cfgPath, "-decision-id", "dec-c-1", "-destination-endpoint", "http://127.0.0.1:1", "-key-id", kid, "-wait", "150ms"})
	})
	require.Error(t, err)
	require.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond, "it kept asking")
	require.NoError(t, json.Unmarshal([]byte(printed), &out), printed)
	require.Equal(t, "operational", out.Error.Category)
}
