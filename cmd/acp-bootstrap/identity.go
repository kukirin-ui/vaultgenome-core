// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/vault-genome/vaultgenome-core/internal/shared/crypto"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
)

// destinationIdentity is what a source operator needs in order to trust
// this destination: its TEE family and measurement (for the allow-list
// and the verifier registry) and, for the simulated backend, the key its
// Evidence is signed with. Hardware Evidence is signed by the vendor's
// certificate chain instead, so no attestor key is printed for it.
type destinationIdentity struct {
	TEEProvider          string `json:"tee_provider"`
	MeasurementHex       string `json:"measurement_hex"`
	AttestorPublicKeyPEM string `json:"attestor_public_key_pem,omitempty"`
	// InsecureSimulation is true for a destination with no hardware
	// isolation, so a source operator pinning it sees that it is one.
	InsecureSimulation bool `json:"insecure_simulation,omitempty"`
	// TDX is what a gcp-tdx measurement is made of.
	TDX *tdxIdentity `json:"tdx,omitempty"`
	// VTPM is what an azure-cgpu guest's vTPM measured of its boot.
	VTPM *vtpmIdentity `json:"vtpm,omitempty"`
}

// runIdentity implements `acp-bootstrap identity -config <path>`: it
// builds the configured TEE producer and prints the destination's
// identity as JSON, without opening any listener.
func runIdentity(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("acp-bootstrap identity", flag.ContinueOnError)
	var configPath string
	fs.StringVar(&configPath, "config", "", "path to JSON config file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configPath == "" {
		return errors.New("acp-bootstrap identity: -config is required")
	}
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("acp-bootstrap identity: config validation: %w", err)
	}
	producer, err := buildTEEProducer(cfg.TEE)
	if err != nil {
		return err
	}
	id := destinationIdentity{
		TEEProvider:    cfg.TEE.Provider,
		MeasurementHex: hex.EncodeToString(producer.Measurement()),
	}
	if sim, ok := producer.(*tee.Simulated); ok {
		pemBytes, err := crypto.PublicKeyPEM(sim.PublicKey())
		if err != nil {
			return err
		}
		id.AttestorPublicKeyPEM = string(pemBytes)
		id.InsecureSimulation = true
	}
	id.TDX = tdxIdentityOf(producer)
	id.VTPM = vtpmIdentityOf(producer)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(id)
}

// tdxIdentity is what a TDX guest's measurement is made of: MRTD and the
// four RTMRs, hashed together (SHA-384) into the measurement above.
type tdxIdentity struct {
	MRTDHex string   `json:"mrtd_hex"`
	RTMRHex []string `json:"rtmr_hex"`
}

func tdxIdentityOf(p tee.Producer) *tdxIdentity {
	t, ok := p.(*tee.GCPTDXProducer)
	if !ok {
		return nil
	}
	mrtd := t.MRTD()
	rtmr := t.RTMRs()
	out := &tdxIdentity{MRTDHex: hex.EncodeToString(mrtd[:])}
	for i := range rtmr {
		out.RTMRHex = append(out.RTMRHex, hex.EncodeToString(rtmr[i][:]))
	}
	return out
}

// vtpmIdentity is what an azure-cgpu guest's vTPM measured of its boot:
// the PCRs quoted and their digest, which a peer may pin (pcr_digests).
type vtpmIdentity struct {
	PCRs         []string `json:"pcrs"`
	PCRDigestHex string   `json:"pcr_digest_hex"`
}

func vtpmIdentityOf(p tee.Producer) *vtpmIdentity {
	a, ok := p.(*tee.AzureCGPUProducer)
	if !ok {
		return nil
	}
	sel, digest := a.VTPMBoot()
	out := &vtpmIdentity{PCRDigestHex: hex.EncodeToString(digest)}
	for _, s := range sel {
		out.PCRs = append(out.PCRs, s.String())
	}
	return out
}
