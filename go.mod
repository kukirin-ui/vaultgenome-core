module github.com/vault-genome/vaultgenome-core

go 1.27.2

// Dependency additions require:
//   1. A justification file at docs/dependencies/<name>.md.
//   2. Inclusion in the allowlist at 00_CI_Security_Policy.md §5.
//   3. PR review acknowledging both of the above.
//
// Current approved direct dependencies:
//   - github.com/stretchr/testify   — test assertions (docs/dependencies/testify.md)
//   - go.etcd.io/bbolt              — append-only audit store (docs/dependencies/bbolt.md)

require (
	github.com/beevik/etree v1.8.1
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/stretchr/testify v1.12.1
	go.etcd.io/bbolt v1.5.0
	golang.org/x/crypto v0.58.0
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
