// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// vsock-attest — runs inside an AWS Nitro Enclave in production-mode.
//
// Production-mode enclaves do not expose console output to the parent
// (--debug-mode is off), so they cannot dump base64 attestation to a
// captured console buffer. Instead, this binary:
//
//   1. Reads /etc/vault-genome/report-data.bin (64 bytes, baked into the
//      .eif at build time) — this is SHA-512 of the workload manifest.
//   2. Opens an NSM session against /dev/nsm and requests an attestation
//      with that report-data set as the user_data field.
//   3. Opens a vsock connection back to the parent EC2 (CID 3, port
//      VSOCK_PORT — default 5005).
//   4. Sends: 4-byte big-endian length + raw COSE_Sign1 attestation bytes.
//   5. Closes cleanly and exits.
//
// The parent runs the companion Python listener (vsock-receive.py) which
// accepts the connection, reads length + payload, and saves the
// attestation document to disk as a binary file.
//
// PCR0/PCR1/PCR2 in the resulting attestation will be NON-ZERO (because
// this enclave was launched without --debug-mode), and PCR0 must equal
// the value reported by `nitro-cli describe-eif --eif-path <eif>` —
// proving the running enclave content matches the built .eif image.
//
// Build:
//   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
//     go build -trimpath -ldflags="-s -w" -o vsock-attest .
//
// Embed the resulting binary into the .eif via Docker COPY in the
// production-mode Dockerfile.enclave.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/hf/nsm"
	nsmreq "github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
)

const (
	parentCID            uint32 = 3                                   // vsock CID for the parent EC2 host
	defaultPort          uint32 = 5005                                // arbitrary application port
	reportDataPath       string = "/etc/vault-genome/report-data.bin" // baked into .eif at build time
	connectRetryInterval        = 1 * time.Second
	connectMaxAttempts          = 30
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("[vsock-attest] ")

	// VSOCK_PORT can override the default at runtime if needed (kept for
	// future flexibility; production launchers will leave it at default).
	port := defaultPort
	if v := os.Getenv("VSOCK_PORT"); v != "" {
		if p, err := strconv.ParseUint(v, 10, 32); err == nil {
			port = uint32(p)
		}
	}

	log.Printf("starting; reading %s", reportDataPath)
	reportData, err := os.ReadFile(reportDataPath)
	if err != nil {
		log.Fatalf("read report-data: %v", err)
	}
	if len(reportData) != 64 {
		log.Fatalf("report-data must be exactly 64 bytes (got %d)", len(reportData))
	}
	log.Printf("report-data: %d bytes (sha-512 of workload manifest)", len(reportData))

	log.Println("opening NSM session against /dev/nsm")
	s, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Fatalf("nsm.OpenDefaultSession: %v", err)
	}
	defer s.Close()

	log.Println("requesting attestation")
	res, err := s.Send(&nsmreq.Attestation{UserData: reportData})
	if err != nil {
		log.Fatalf("attestation request: %v", err)
	}
	if res.Error != "" {
		log.Fatalf("attestation error: %s", res.Error)
	}
	if res.Attestation == nil || len(res.Attestation.Document) == 0 {
		log.Fatalf("attestation: empty response")
	}
	doc := res.Attestation.Document
	log.Printf("attestation document: %d bytes", len(doc))

	log.Printf("connecting to parent at CID=%d port=%d", parentCID, port)
	conn, err := dialWithRetry(parentCID, port, connectMaxAttempts, connectRetryInterval)
	if err != nil {
		log.Fatalf("vsock.Dial: %v", err)
	}
	defer conn.Close()

	// Length-prefix framing: 4-byte big-endian length, then payload.
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(doc)))
	if _, err := conn.Write(lenbuf[:]); err != nil {
		log.Fatalf("write length: %v", err)
	}
	if _, err := conn.Write(doc); err != nil {
		log.Fatalf("write document: %v", err)
	}
	log.Printf("attestation sent (%d bytes); closing connection", len(doc)+4)
	if err := conn.Close(); err != nil {
		log.Printf("close (non-fatal): %v", err)
	}

	// Tiny grace period so the parent can drain its buffer before the
	// enclave terminates, in case TCP-style FIN flushing is finicky.
	time.Sleep(500 * time.Millisecond)
	log.Println("done")
}

// dialWithRetry tries to open a vsock connection multiple times before giving up.
// In production the parent listener is started before the enclave launches, so
// the very first dial usually succeeds. The retry loop is defensive in case
// nitro-cli scheduling causes the enclave to come up a moment too soon.
func dialWithRetry(cid, port uint32, attempts int, interval time.Duration) (*vsock.Conn, error) {
	var lastErr error
	for i := 1; i <= attempts; i++ {
		conn, err := vsock.Dial(cid, port, nil)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		log.Printf("vsock.Dial attempt %d/%d failed: %v", i, attempts, err)
		time.Sleep(interval)
	}
	return nil, fmt.Errorf("vsock.Dial: gave up after %d attempts: %w", attempts, errors.Join(lastErr))
}
