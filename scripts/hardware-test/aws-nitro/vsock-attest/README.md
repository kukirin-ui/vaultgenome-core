# vsock-attest — production-mode AWS Nitro attestation client

A small Go binary that runs **inside** an AWS Nitro Enclave in
production mode (without `--debug-mode`). Captures a real Nitro
attestation document and ships it back to the parent EC2 host
over vsock.

## Why this exists

In `--debug-mode`, the Nitro Enclave exposes a console that the
parent can read with `nitro-cli console --enclave-id <id>`. We can
print the attestation document to stdout there and parse it back on
the parent. **But debug-mode forces PCR0/PCR1/PCR2 to all-zeros by
AWS design** — debug enclaves are explicitly not trustworthy in
production. For an auditor-grade attestation, the enclave must be
launched *without* `--debug-mode`, which removes console access.

The vsock channel is the production-mode replacement for the console.
The enclave program inside the .eif opens a vsock connection back to
the parent (CID 3, port 5005), sends the attestation document length-
prefixed, and exits cleanly. The parent runs `vsock-receive.py`
companion listener which writes the bytes to disk.

## Build

```bash
# From this directory. go.mod names Go 1.27.2 and go.sum is committed, so
# the build reads only the versions recorded there:
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -mod=readonly -trimpath -ldflags="-s -w" -o vsock-attest .
```

The resulting binary is fully static, ~2 MB, suitable for direct COPY
into a minimal Alpine or Amazon Linux 2023 enclave image.

## Container Dockerfile (production-mode .eif build)

```dockerfile
FROM amazonlinux:2023
RUN mkdir -p /etc/vault-genome /usr/local/bin
COPY vsock-attest /usr/local/bin/vsock-attest
COPY 02-report-data.bin /etc/vault-genome/report-data.bin
RUN chmod +x /usr/local/bin/vsock-attest
CMD ["/usr/local/bin/vsock-attest"]
```

Then:

```bash
docker build -f Dockerfile.enclave -t vault-genome-attest-prod:latest .
nitro-cli build-enclave \
  --docker-uri vault-genome-attest-prod:latest \
  --output-file vault-genome-attest-prod.eif \
  > eif-build-prod.json

# Capture the EXPECTED PCR0 — the verifier will compare this against
# the PCR0 the chip embeds in the attestation document.
nitro-cli describe-eif --eif-path vault-genome-attest-prod.eif \
  > eif-describe-prod.json
```

## Run (production mode)

```bash
# 1. Start parent listener BEFORE launching the enclave.
python3 scripts/vsock-receive.py 04-attestation-document.bin &
LISTENER_PID=$!

# 2. Launch the enclave WITHOUT --debug-mode.
sudo nitro-cli run-enclave \
  --eif-path vault-genome-attest-prod.eif \
  --memory 4096 --cpu-count 2 --enclave-cid 16

# 3. Wait for the listener to receive + write the document.
wait $LISTENER_PID

# 4. Terminate the enclave.
sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID' \
  | xargs sudo nitro-cli terminate-enclave --enclave-id

# 5. Confirm PCR0 in the attestation matches the EXPECTED PCR0.
EXPECTED=$(jq -r '.Measurements.PCR0' eif-describe-prod.json)
GOT=$(python3 - <<'EOF'
import cbor2
with open("04-attestation-document.bin", "rb") as f:
    raw = f.read()
_, _, payload, _ = cbor2.loads(raw)
doc = cbor2.loads(payload)
print(doc["pcrs"][0].hex())
EOF
)
[ "$EXPECTED" = "$GOT" ] && echo "✓ PCR0 matches" || echo "✗ MISMATCH"
```

## Dependencies

- `github.com/hf/nsm` — Nitro Security Module Go bindings (NSM ioctl)
- `github.com/mdlayher/vsock` — clean Go vsock library (uses AF_VSOCK syscalls)
- Standard library: `encoding/binary`, `log`, `os`, `time`

No CGO. Single static binary.

## License

AGPL-3.0-or-later (matches the rest of the kit).
