// SPDX-License-Identifier: AGPL-3.0-or-later

package tee

import (
	"encoding/pem"
	"errors"
)

// AWS's root, pinned: the trust anchor of every Nitro Enclaves attestation
// document in the commercial partitions. AWS publishes it at
// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// (SHA-256 of the zip 8cf60e2b…faff7c) and prints the certificate's SHA-256
// fingerprint in the attestation documentation:
//
//	64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
//
// Subject CN=aws.nitro-enclaves, O=Amazon, OU=AWS, C=US; ECDSA P-384;
// valid 2019-10-28 to 2049-10-28. TestAWSNitroRootG1_Fingerprint holds the
// embedded certificate to that fingerprint. An operator may pin another
// root through AWSNitroVerifierConfig.PinnedRoots (a GovCloud partition,
// or a rotation AWS announces).

// AWSNitroRootG1PEM is the AWS Nitro Enclaves Root CA G1.
const AWSNitroRootG1PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`

// awsNitroPinnedRoots returns the DER of the pinned root, the one the
// verifier trusts when its configuration names none.
func awsNitroPinnedRoots() [][]byte {
	der, err := awsNitroRootG1DER()
	if err != nil {
		// The constant above is checked by a test; a parse failure here
		// would be a build defect, not a runtime condition.
		return nil
	}
	return [][]byte{der}
}

func awsNitroRootG1DER() ([]byte, error) {
	block, _ := pem.Decode([]byte(AWSNitroRootG1PEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("aws-nitro: the pinned root is not a PEM certificate")
	}
	return block.Bytes, nil
}
