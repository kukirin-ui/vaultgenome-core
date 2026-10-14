# AWS Nitro Enclaves — the run of 2026-10-14 (production mode)

One m5.xlarge in us-east-2a, driven by `examples/full-test-run.sh` on the
tree of this commit. Sanitized excerpts, the same set as the May 2026
cohort's plus the records the October scripts add; the raw material is
listed at the end. The kit README's section "The run of 2026-10-14" reads
these files.

```
2026-10-14/
├── README.md
├── CROSS-VM-MATRIX.md                   rendered by 07-cross-vm-matrix.sh (cohort of one)
├── 01-VM1-us-east-2a/
│   ├── 00-vm-identity.txt               derived on the laptop by 08 from the two files below (last line says so)
│   ├── vm-identity-pack.txt             written on the instance by 06-pack-evidence.sh
│   ├── 02d-expected-pcrs.json           EXPECTED PCR0/1/2 from describe-eif of the built image
│   ├── 03-enclaves-state.json           the enclave running, PCRs included (captured before the wait)
│   ├── 03-enclave-terminate.json        terminate-enclave's answer: the enclave had already exited
│   ├── 03-enclaves-state-post.json      no enclave left
│   ├── vsock-receive.log                the parent listener: 4526 bytes received from CID 16
│   ├── 05-attestation-parsed.json       module_id, PCR0/1/2, user_data, cabundle_count
│   ├── 06-pcr-binding-check.json        captured vs expected, every PCR
│   ├── 06-chain-validation.json         chain, anchor, COSE, user_data, PCR0: production_grade true (08 on the laptop)
│   ├── 06-root-ca-check.json            archive sha256 and certificate fingerprint, both checked (02c)
│   └── terraform-outputs.json           instance, AZ, AMI, public IP of the run
└── workload/01-VM1-us-east-2a/          Demo 1, Demo 2 and the inference comparison, as printed
```

Not here, by the kit's convention (founders' Desktop pack,
`AWS-Nitro-Real-Hardware-Test/run-20261014T165832Z/`): the attestation
document (`04-attestation-document.bin`/`.b64`), the enclave launch
record, the build manifest and `02-report-data.*`, the root certificate
and its archive, the runner's log, the enclave images.
