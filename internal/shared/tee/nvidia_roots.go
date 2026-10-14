// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// NVIDIA's roots, pinned: the trust anchors of a GPU's attestation
// certificate chain and of the reference integrity manifests NVIDIA signs.
// Both are the certificates NVIDIA ships in its open-source verifier
// (github.com/NVIDIA/nvtrust, local_gpu_verifier/src/verifier/certs):
// the NVIDIA Device Identity CA (SHA-256 fingerprint 102bf659…167b48) and
// the NVIDIA CoRIM signing Root CA (12977b51…1df5d1). An operator may
// pin others through the verifier's configuration.

// NVIDIADeviceRootPEM is the NVIDIA Device Identity CA.
const NVIDIADeviceRootPEM = `-----BEGIN CERTIFICATE-----
MIICCzCCAZCgAwIBAgIQLTZwscoQBBHB/sDoKgZbVDAKBggqhkjOPQQDAzA1MSIw
IAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklE
SUEwIBcNMjExMTA1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDUxIjAgBgNVBAMM
GU5WSURJQSBEZXZpY2UgSWRlbnRpdHkgQ0ExDzANBgNVBAoMBk5WSURJQTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABA5MFKM7+KViZljbQSlgfky/RRnEQScW9NDZF8SX
gAW96r6u/Ve8ZggtcYpPi2BS4VFu6KfEIrhN6FcHG7WP05W+oM+hxj7nyA1r1jkB
2Ry70YfThX3Ba1zOryOP+MJ9vaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwHQYDVR0OBBYEFFeF/4PyY8xlfWi3Olv0jUrL+0lfMB8GA1UdIwQY
MBaAFFeF/4PyY8xlfWi3Olv0jUrL+0lfMAoGCCqGSM49BAMDA2kAMGYCMQCPeFM3
TASsKQVaT+8S0sO9u97PVGCpE9d/I42IT7k3UUOLSR/qvJynVOD1vQKVXf0CMQC+
EY55WYoDBvs2wPAH1Gw4LbcwUN8QCff8bFmV4ZxjCRr4WXTLFHBKjbfneGSBWwA=
-----END CERTIFICATE-----
`

// NVIDIARIMRootPEM is the NVIDIA CoRIM signing Root CA.
const NVIDIARIMRootPEM = `-----BEGIN CERTIFICATE-----
MIICKTCCAbCgAwIBAgIQRdrjoA5QN73fh1N17LXicDAKBggqhkjOPQQDAzBFMQsw
CQYDVQQGEwJVUzEPMA0GA1UECgwGTlZJRElBMSUwIwYDVQQDDBxOVklESUEgQ29S
SU0gc2lnbmluZyBSb290IENBMCAXDTIzMDMxNjE1MzczNFoYDzIwNTMwMzA4MTUz
NzM0WjBFMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGTlZJRElBMSUwIwYDVQQDDBxO
VklESUEgQ29SSU0gc2lnbmluZyBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEuECyi9vNM+Iw2lfUzyBldHAwaC1HF7TCgp12QcEyUTm3Tagxwr48d55+K2VI
lWYIDk7NlAIQdcV/Ff7euGLI+Qauj93HsSI4WX298PpW54RTgz9tC+Q684caR/BX
WEeZo2MwYTAdBgNVHQ4EFgQUpaXrOPK4ZDAk08DBskn594zeZjAwHwYDVR0jBBgw
FoAUpaXrOPK4ZDAk08DBskn594zeZjAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwCgYIKoZIzj0EAwMDZwAwZAIwHGDyscDP6ihHqRvZlI3eqZ4YkvjE
1duaN84tAHRVgxVMvNrp5Tnom3idHYGW/dskAjATvjIx6VzHm/4e2GiZAyZEIUBD
OKPzp5ei/A0iUZpdvngenDwV8Qa/wGdiTmJ7Bp4=
-----END CERTIFICATE-----
`

// parseNVIDIARoot parses one PEM certificate: the configured root, or the
// pinned one when none is configured.
func parseNVIDIARoot(configured []byte, pinned string) (*x509.Certificate, error) {
	raw := configured
	if len(raw) == 0 {
		raw = []byte(pinned)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
