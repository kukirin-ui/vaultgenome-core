# The negatives drill: the authority says no, seven times, on one record

The failover drill ([gcp-failover](../gcp-failover)) asked one question of
the release authority — *will you move the model?* — and got one yes.
This drill asks eight, against the same attack on the same two machines,
and expects seven refusals, each for a different reason, each decided
where the code decides it: on the audit record for a trigger that reaches
the policy engine, at the door for a policy that cannot be admitted at
all. The one move it allows goes to the newest state whose bytes match
the sentinel's signed word, with the corrupted newer bundle set aside on
the record.

```bash
bash scripts/hardware-test/failover-negatives/run.sh <gcp-project> [zone]
```

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, and boots two AMD SEV-SNP Confidential
VMs in one project:

- The **primary** ([`../gcp-failover/primary.sh`](../gcp-failover/primary.sh),
  unchanged) — `n2d-standard-8`: fine-tunes Qwen2.5-0.5B, the sentinel
  seals generation 0 and generation 1 with the chip's report on every
  record (ADR 0017), the tripwire is touched and the adapter overwritten,
  the sentinel reports the compromise and exits 3.
- The **standby** ([`standby-negatives.sh`](standby-negatives.sh)) —
  `n2d-standard-4`: the release authority (`sagvd failover`, its escrow key
  sealed to this chip, ADR 0016) and the destination (`acp-bootstrap`) on
  loopback TLS, as in the failover drill. It pulls the primary's outbox
  replica and runs the eight policies below, in order, against the one
  compromise report.

| # | The operator's policy (serial) | What the authority must do | Where |
| - | - | - | - |
| 1 | stands 45 s; armed before the attack, expired when the report comes (1) | decline: *expired* | on the record |
| 2 | allows at most 1 s of lost state (2) | decline: *the policy allows at most 1s* | on the record |
| 3 | quarantines a day (3) | decline: *no genome in the verified chain … checks out* | on the record |
| 4 | a good policy (4), under an operator stop list (serial 2, everything) | decide, hand-shake, verify the chip — and deny the release: *operator stop in force* | on the record |
| 5 | pins another machine as the standby (5): the primary's measurement | decide, hand-shake, verify the chip — and deny: *releases only to its standby* | on the record |
| 6 | a good policy (6), the newest bundle corrupted in the replica | set generation 1 aside (*hashes to …, the record says …*), restore generation 0, gate it, confirm the receipt | on the record |
| 7 | policy 6 again | refuse: *already carried out a failover* | at the door |
| 8 | signed by a stranger (7) | refuse: the signature is not the operator's | at the door |

Runs 1–6 are events on one audit log; run 4 and run 5 are refused *after*
the standby's chip has verified, by the policy alone. Runs 7 and 8 never
reach the log — a policy that is spent or unsigned is refused before the
authority does anything on its behalf, which is why the stop list, the
policy and the audit log share one operator key.

**Design:** [ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md),
[ADR 0016](../../../docs/adr/0016-escrow-key-sealed-to-the-release-host.md),
[ADR 0017](../../../docs/adr/0017-limits-on-the-primarys-word.md), operator
runbook [07](../../../docs/operator/07_failover.md). The refusals are the
executor's unit tests (`internal/vault/failover/executor_test.go`) run on
the shipping binaries on real chips.

## Results — run `20260916T191033Z`

Two live SEV-SNP machines, one attack, eight policies, seven refusals,
one move. Primary `n2d-standard-8` and standby `n2d-standard-4`,
europe-west4-a, AMD EPYC 7B13 (Milan), `Memory Encryption Features active:
AMD SEV SEV-ES SEV-SNP`, `/dev/sev-guest` (`*/metadata.txt`,
`*/system.txt`, `*/tsm.txt`). Primary measurement `69da361d…c790`
(`primary/sentinel-identity.json`), standby `21199b36…9546`
(`standby/destination-identity.json`, the same VM is the authority:
`standby/authority-identity.json`).

**The authority's key, sealed** (`standby/escrow-provision.json`): key
`c9245db7bdb5fd86`, `tee: gcp-sev-snp`, wrapped to recovery key `0b9fa2d1edf3539f`;
`key_escrow_storage: sealed:gcp-sev-snp`. **The primary's word**
(`primary/sentinel.json`, `finetune-*.json`, `attack-at.txt`): two
generations sealed (120 steps in 49.1 s, 160 steps in 71.6 s, loss
5.33 → 0.0009), generation 0 at 19:17:18.80Z, generation 1 at 19:21:36.80Z,
each record carrying the chip's report; attacked at 19:21:46.57Z, the sentinel
reported `outcome: compromised` at 19:21:48.79Z with generation 1 as its
last word and exited 3.

**The eight runs** (`standby/steps.txt`, `report-N.json`,
`failover-N.log`, `policy-N.json` with `-issue.txt` and `-verify.txt`,
`stop-N.json`):

| # | Policy | `sagvd failover` | What the authority said |
| - | - | - | - |
| 1 | serial 1, stood 2026-09-16T19:13:45Z–2026-09-16T19:14:30Z; armed at 19:13:45Z, the report came at 19:21:48.79Z and was observed at 19:21:57.81Z | exit 3 | **declined** — *failover: policy serial 1 expired at 2026-09-16T19:14:30Z* |
| 2 | serial 2, `--max-rpo 1s` | exit 3 | **declined** — *the newest trustworthy genome, generation 1, was sealed 11.996s before the trigger; the policy allows at most 1s* |
| 3 | serial 3, `--quarantine 24h` | exit 3 | **declined** — *no genome in the verified chain was sealed by 2026-09-15T19:21:48.792219003Z and checks out*; both generations set aside, "sealed at …, after the cutoff 2026-09-15T19:21:48Z" |
| 4 | serial 4, a good policy, under stop list serial 2 (`--all`, "incident review") | exit 1 | decided *failover* → hand-shake → the standby's chip **verified** → **denied** — *operator stop in force (revocation serial 2): incident review* |
| 5 | serial 5, standby pinned to the primary's measurement `69da361d…c790`; stop list serial 3 (nothing stopped) | exit 1 | decided *failover* → hand-shake → the chip **verified** → **denied** — *failover policy serial 5 releases only to its standby (gcp-sev-snp, measurement [69da361d…c790]); gcp-sev-snp 21199b36…9546 is not it* |
| 6 | serial 6, a good policy; `gen-000001.genome` in the replica with one byte flipped (`addaaf0c…be7d` → `640046c8…5671`, `tamper.txt`) | exit 0 | generation 1 **set aside** — *sentinel: gen-000001.genome hashes to 640046c8…5671 (2216819 bytes), the record says addaaf0c…be7d (2216819 bytes), the record says addaaf0c…be7d* — and **generation 0 restored** (key `genome-1a5e4e6f76e3-g0-958f666bdfd6`, 2,215,614 bytes, sealed 19:17:18.80Z): 5 files, 2,209,723 bytes in **12.7 ms**, gate **EXACT** (16 fixtures, `max_abs_err: 0`), receipt confirmed; RPO **270.0 s** (the attack less generation 0's seal), release 0.04 s, gate 11.80 s, failover 12.06 s, RTO 34.37 s (the report waited in the replica through runs 2–5) |
| 7 | serial 6 again | exit 1 | refused at the door — *failover: policy serial 6 already carried out a failover (audit event xcc-evt-…000c); moving again needs a new policy*; no event |
| 8 | serial 7, signed with a stranger's key under the operator's key id | exit 1 | refused at the door — *failover: signature does not verify under the operator key* (`acpctl failover verify` says the same, exit 4); no event |

**One record** (`standby/audit-events.jsonl`, `audit-verify.json`): 16
events, `ok: true`, tip `05a015c1…7161` —

| Event | At | Kind | Run |
| - | - | - | - |
| 1 | 19:21:57.818Z | `FAILOVER_DECIDED` | 1 |
| 2 | 19:21:59.961Z | `FAILOVER_DECIDED` | 2 |
| 3 | 19:22:00.043Z | `FAILOVER_DECIDED` | 3 |
| 4 | 19:22:00.137Z | `FAILOVER_DECIDED` (decision *failover*, generation 1) | 4 |
| 5 | 19:22:00.138Z | `CROSS_CLOUD_HANDSHAKE_INITIATED` | 4 |
| 6 | 19:22:00.648Z | `CROSS_CLOUD_ATTESTATION_VERIFIED` | 4 |
| 7 | 19:22:00.651Z | `KEY_RELEASE_DENIED` (stage policy, `failover-policy-v1;failover=4;revocation=2`) | 4 |
| 8 | 19:22:00.741Z | `FAILOVER_DECIDED` | 5 |
| 9 | 19:22:00.742Z | `CROSS_CLOUD_HANDSHAKE_INITIATED` | 5 |
| 10 | 19:22:00.763Z | `CROSS_CLOUD_ATTESTATION_VERIFIED` | 5 |
| 11 | 19:22:00.765Z | `KEY_RELEASE_DENIED` (stage policy, `failover-policy-v1;failover=5;revocation=3`) | 5 |
| 12 | 19:22:11.121Z | `FAILOVER_DECIDED` (decision *failover*, generation 0) | 6 |
| 13 | 19:22:11.123Z | `CROSS_CLOUD_HANDSHAKE_INITIATED` | 6 |
| 14 | 19:22:11.144Z | `CROSS_CLOUD_ATTESTATION_VERIFIED` | 6 |
| 15 | 19:22:11.146Z | `KEY_RELEASE_AUTHORIZED` (`failover-policy-v1;failover=6;revocation=3`) | 6 |
| 16 | 19:22:23.163Z | `CROSS_CLOUD_RESTORE_COMPLETED` | 6 |

Runs 4 and 5 are the point of the drill: the standby's chip verified
(`CROSS_CLOUD_ATTESTATION_VERIFIED`, a real SEV-SNP report under the
authority's nonce) and the key still did not move, because the operator's
stop list said stop, and because the policy named another machine. The
refusal is the operator's, on the record, after the hardware said yes.
Runs 7 and 8 never reach the record: a spent or unsigned policy is refused
before the authority does anything on its behalf. Run 6 shows what the
chooser does with a replica an intruder reached: the newest bundle's bytes
do not match the sentinel's signed record, so it is set aside on the
record and the move goes to the generation before — EXACT on the same
runtime, 270.0 s of state given up rather than one corrupted byte
restored.

**Cost.** About 13 minutes on two machines, a few cents.

## The raised runtime — run `20261014T035731Z` (evidence/20261014T035731Z)

The same eight runs on the raised Python runtime (torch 2.14.1+cpu,
transformers 5.19.0, numpy 2.5.4; `*/pip-freeze.txt`), the same two
machines in europe-west4-a. Two generations sealed (120 steps in 47.2 s,
160 in 68.7 s, loss 5.33 → 0.0009), the attack, `outcome: compromised`
with generation 1 as the last word. The same seven refusals for the same
seven reasons, and the same one move (`standby/steps.txt`, `report-N.json`,
`failover-N.log`):

| # | Policy | `sagvd failover` | What the authority said |
| - | - | - | - |
| 1 | serial 1, expired at 2026-10-14T04:02:12Z | exit 3 | **declined** — *policy serial 1 expired* |
| 2 | serial 2, `--max-rpo 1s` | exit 3 | **declined** — *generation 1 was sealed 8.996s before the trigger; the policy allows at most 1s* |
| 3 | serial 3, `--quarantine 24h` | exit 3 | **declined** — *no genome in the verified chain was sealed by the cutoff and checks out*; both generations set aside |
| 4 | serial 4, under stop list serial 2 | exit 1 | decided *failover* → handshake → the standby's chip **verified** → **denied** — *operator stop in force* |
| 5 | serial 5, standby pinned to the primary's measurement | exit 1 | decided *failover* → handshake → the chip **verified** → **denied** — *releases only to its standby* |
| 6 | serial 6, `gen-000001.genome` with one byte flipped (`8b5f8661…ebe2` → `087b3516…72dc`) | exit 0 | generation 1 **set aside**, **generation 0 restored**, gate **EXACT** (16 fixtures), RPO 267.0 s, restore 11.3 ms, gate 11.40 s, the move itself 12.08 s (trigger observed → confirmed; September 12.06 s), RTO 90.56 s — the sixth policy was issued 79 s after the attack this time, 25 s in September, the five answers before it having taken longer to come round |
| 7 | serial 6 again | exit 1 | refused at the door — *already carried out a failover*; no event |
| 8 | serial 7, a stranger's signature | exit 1 | refused at the door — *signature does not verify under the operator key*; no event |

One record: 16 events, `audit-verify.json` `ok: true`, tip `094b5ec2…90af`,
the same sequence as in September. The authority's key files were sealed
on the standby before any of it, the cross-cloud transport's client key
among them (`seal-keys (failover config) exit=0
sealed=crosscloud.transport_tls.client_key already=5`).

## Evidence files

- `primary/` — as in the failover drill: `finetune-0.json`,
  `finetune-1.json` (+ `.log`), `sentinel-identity.json`,
  `sentinel-keygen.txt`, `sentinel.json`, `sentinel.log`, `attack-at.txt`,
  `metadata.txt`, `system.txt`, `tsm.txt`, `pip-freeze.txt`, `steps.txt`,
  `console.log`.
- `standby/` — `escrow-provision.json`, `recovery-keygen.txt`,
  `authority-identity.json`, `destination-identity.json`,
  `primary-identity.json`, `verifiers.json`, `allow.json`; `stop-1.json`,
  `stop-2.json`, `stop-3.json` (the operator's stop lists as applied);
  `policy-1.json` … `policy-7.json` with `policy-N-issue.txt` and
  `policy-N-verify.txt` (policy 7's verify is the refusal); `report-1.json`
  … `report-6.json` (the executor's reports; runs 7 and 8 wrote none) and
  `failover-1.log` … `failover-8.log`; `tamper.txt`, `replica-ls.txt`,
  `replica-sha256.txt` (the replica after the primary's last word, before
  the tamper); `restored-ls.txt`, `restored-adapter-head.txt` (generation
  0's bytes); `audit-events.jsonl`, `audit-verify.json`; `cache-vcek-*.der`
  (the VCEKs fetched from AMD for both chips); `acp-bootstrap.log`,
  `metadata.txt`, `system.txt`, `tsm.txt`, `pip-freeze.txt`, `steps.txt`,
  `console.log`.

The evidence holds no key, seed, token or config: the sealed escrow key's
bytes are not in it, the operator's and the stranger's seeds stayed on the
VM and were deleted with it, the bearer token crossed only through the
run's private bucket, and the bucket was deleted with the VMs.

## Scope

One run, the 0.5B model of the failover drill, two machines of one TEE
family in one project. The refusals are the executor's unit tests
(`internal/vault/failover/executor_test.go`, `policy_test.go`) run on the
shipping binaries on real chips; the ninth, a rogue sentinel with the
stolen seed attesting from the wrong chip, is the failover drill's own
negative leg ([gcp-failover](../gcp-failover), declined on the record on
`20260916T021933Z`). Not exercised here: a lost-heartbeat trigger (Drill
II's negative leg and the local tests), a forged chip report (SEV-SNP
signatures are verified to AMD's root, C7), and an operator stop that
lands *during* a hand-shake rather than before it (the unit test
`TestOperatorStopHaltsAFailover`).
