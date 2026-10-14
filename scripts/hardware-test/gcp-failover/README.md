# Continuity Drill, failover leg: a model moves itself off a compromised machine

This is the whole promise of the platform in one run, on real hardware: a
model is fine-tuned on one machine; that machine is attacked; and the model
comes back on another — as it was just before the attack, nowhere the
operator did not choose, with attestation on both ends.

```bash
bash scripts/hardware-test/gcp-failover/run.sh <gcp-project> [zone]
```

`run.sh` builds `sagvd`, `acp-bootstrap`, `acpctl` and `keygen` for
linux/amd64, packs `workers/genome`, and boots two AMD SEV-SNP Confidential
VMs in the same project:

- The **standby** ([`standby.sh`](standby.sh)) hosts the **release authority**
  (`sagvd failover`, attesting with its chip) and the **destination**
  (`acp-bootstrap`), on loopback TLS. The authority makes its escrow key in its
  own process and writes it only sealed to its chip, wrapped to the operator's
  recovery key (ADR 0016), hands the public half to the primary, and — under
  an operator-signed failover policy that pins the primary's chip (ADR 0017) —
  waits, watching a replica of the primary's outbox and holding a warm copy of
  every sealed genome.
- The **primary** ([`primary.sh`](primary.sh)) runs the workload and, beside
  it, the **sentinel** (`acpctl sentinel watch --tee gcp-sev-snp`). It
  fine-tunes a real model, the sentinel seals each state as the next
  generation of a genome chain — each key encapsulated only to the authority's
  escrow key, every record carrying the chip's report — and the outbox is
  replicated to a bucket. Then the machine is attacked.

Reports come back to `evidence/<stamp>/`; both VMs and the bucket are deleted
on every exit. The genome key never crosses in the clear: it lives on the
primary only as an escrow envelope, which the authority opens and re-wraps to
the standby's attested per-handshake key (ADR 0009, 0011, 0012).

**Design:** [ADR 0012](../../../docs/adr/0012-sentinel-and-policy-driven-failover.md),
operator runbook [07](../../../docs/operator/07_failover.md).

## The scenario

1. The standby provisions the authority and publishes its escrow public key.
2. The primary fine-tunes generation 0 (Qwen2.5-0.5B-Instruct, LoRA r8, 120
   steps); the sentinel seals it and replicates the outbox. Before it
   starts, the sentinel's seed is sealed in place to the primary's chip
   (`acpctl sentinel seal-key`, ADR 0023): the sentinel runs from the
   sealed file, and the operator pins the same key.
3. The operator signs a failover policy pinning the primary's sentinel key and
   the standby's SEV-SNP measurement, requiring an EQUIVALENT gate. The
   authority arms `sagvd failover`.
4. The primary keeps training: generation 1 (160 steps). The sentinel seals it.
5. **The attack.** A tripwire file is touched and the adapter is overwritten
   with garbage. The sentinel checks its wires before it would seal, so it
   never seals the tampered state: it writes a signed compromise report naming
   generation 1 as the last good one, and exits 3.
6. The authority sees the compromise in the replica — with the primary chip's
   report on it — chooses generation 1, records `FAILOVER_DECIDED`, releases
   its escrowed key to the standby — which attests with its own chip, restores
   the genome, recomputes the sealed fixtures to prove the model works, and
   signs a receipt — and confirms it.
7. **The negative leg.** The sentinel seed is stolen and used off the
   primary's chip: a rogue sentinel on the standby seals a generation of its
   own, every record attested by the wrong chip. A second policy watches its
   outbox: the rogue's records are ignored, the silence after the primary's
   last genuine word is the trigger, nothing past that word is trusted, and
   the decision is declined on the record. A second negative takes the
   *sealed* seed file to the standby's chip: a real SEV-SNP chip, the wrong
   one — `acpctl sentinel identity --key` refuses it (exit 2). The thief
   who takes the file the sentinel runs from takes nothing.

## Results — run `20260916T021933Z`

The same drill, with the escrow key sealed to the authority's chip
([ADR 0016](../../../docs/adr/0016-escrow-key-sealed-to-the-release-host.md)),
the primary attesting every record with its chip and the policy pinning it
([ADR 0017](../../../docs/adr/0017-limits-on-the-primarys-word.md)), and a
negative leg: a rogue sentinel with the stolen seed on the wrong chip.

**Machines**, both AMD SEV-SNP Confidential VMs (`Memory Encryption
Features active: AMD SEV SEV-ES SEV-SNP`, `/dev/sev-guest` present, in each
`tsm.txt`):

- Primary: GCP `n2d-standard-8`, us-central1-c — trains and runs the sentinel.
  Launch measurement `10f5ac22…4519` (48 bytes; `primary/sentinel-identity.json`).
- Standby: GCP `n2d-standard-4`, us-central1-c — the authority and the
  destination. Launch measurement `7dc7c12e…5acc`.

**The escrow key, sealed** (`standby/escrow-provision.json`, `escrow-sealed-shape.txt`,
`escrow-reprovision.json`, `authority-identity.json`)

| | |
| - | - |
| `sagvd escrow-provision` | exit 0: key `d2aac7b965c6ab76`, `tee: gcp-sev-snp`, sealed at the standby's measurement, `source: generated`; wrapped to recovery key `93b4bd0871bfacf6` |
| On disk | `vault-genome/sealed-escrow-key/v1` — the `sealed` field is 80 base64 characters (a 12-byte nonce, the 32-byte key, a 16-byte tag); no key file |
| The derived key | `SNP_GET_DERIVED_KEY` on `/dev/sev-guest` answered on GCP: the seal round-tripped before the file was written, and every envelope below was opened with the key unsealed at start |
| The recovery ceremony | `acpctl escrow recover` piped into `sagvd escrow-provision -stdin`: exit 0, the same key `d2aac7b965c6ab76`, `source: stdin`, re-sealed on this chip |
| `sagvd identity` | `key_escrow_storage: sealed:gcp-sev-snp` |

**The primary's word** (`primary/sentinel.json`, `standby/failover-verify.txt`)

The sentinel ran with `--tee gcp-sev-snp` and put the chip's report on every
record: the compromise report in `sentinel.json` carries
`attestation.kind: gcp-sev-snp` with a 1184-byte report bound to the
record. The policy (serial 1) pins `primary TEE: gcp-sev-snp,
measurements 10f5ac22…4519 (every record must carry its report)`, and
`stopped and not back within 60s` is a trigger beside the compromise report
and the 120 s heartbeat timeout.

The primary sealed two generations (120 then 160 steps of LoRA fine-tuning,
51.8 s and 72.9 s), then was attacked at 02:26:44.92Z. The sentinel's
report: `outcome: compromised`, `generations_sealed: 2`, last generation 1;
it exited 3.

**The failover** (`standby/report.json`)

| | |
| - | - |
| Trigger | compromise report; tripwire `/root/canary`; `primary_measurement_hex` = the primary's chip |
| Genome restored | **generation 1** — the last sealed before the attack (key `genome-134ad7e32883-g1-d9318608d0c0`, 2,208,627 bytes), **not** the tampered state |
| Gate on the standby | **EXACT** — door "pinned replay", 16 fixtures, max abs err 0 (required: EQUIVALENT) |
| Restore | 5 files, 2,202,926 bytes, in **14.1 ms** |
| Detect | **7.69 s** (the sentinel's detection → the authority acting, across the bucket replication) |
| RPO | **9.00 s** (attack − generation-1 seal time) |
| RTO | **23.98 s** (failure → a confirmed, gated restore on the standby), of which the gate ran the model for 14.4 s |
| Audit | 5 events — `FAILOVER_DECIDED` (naming the primary's measurement) → handshake → attestation → `KEY_RELEASE_AUTHORIZED` → `CROSS_CLOUD_RESTORE_COMPLETED`; `audit-verify.json`: `ok: true`, tip `b20fc6d7…55b4` |

`release.policy_version` is `failover-policy-v1;failover=1;revocation=1`. The
restored adapter (`restored-adapter-head.txt`) is the generation-1
safetensors — binary weights, not the ASCII bytes the intruder planted.

**The negative leg: a stolen seed off the pinned chip** (`standby/rogue-report.json`,
`rogue-sentinel.json`, `rogue-failover.log`, `failover-2-verify.txt`)

The thief — here, the standby itself — copied the outbox, dropped the
compromise report, and ran a sentinel with the stolen seed and `--tee
gcp-sev-snp`: its own chip, so every record it wrote carried a genuine
SEV-SNP report, from the wrong machine. It sealed a generation 2 of its own
(the restored model with one file changed) and heartbeated. A second policy
(serial 2) pinned the primary as before, acted on lost heartbeats only (30 s)
and quarantined a day.

| | |
| - | - |
| The rogue's records | **ignored**: `heartbeat.json: … gcp-sev-snp attestation does not verify: … MEASUREMENT 7dc7c12e…5acc not in acceptable set` — the standby's chip is not the primary |
| The trigger | **heartbeat-timeout** at the primary's last genuine heartbeat (02:26:47.34Z, attested by `10f5ac22…4519`), 30.06 s after the executor armed — the rogue's heartbeats moved nothing |
| The chain | `gen-000002.seal.json` set aside: *after generation 1, the last the sentinel's heartbeat-timeout names*; generations 1 and 0 set aside by the quarantine |
| Decision | **declined**, on the record (`FAILOVER_DECIDED`, audit chain length 6): *no genome in the verified chain was sealed by the cutoff and checks out*. `sagvd failover` exited 3. No key moved |

**Attestation on both ends, and on every record.** The release handshake
verified the standby's live SEV-SNP quote before any key left the authority,
as before; now the authority also verified the primary's report on the
compromise report it acted on, and refused a real report from another chip.

**RTO/RPO in context.** RPO is bounded by the sentinel's seal cadence and the
outbox replication lag. Detection here took 7.7 s (2.5 s in the earlier run):
the compromise report reached the replica through a tar snapshot pushed every
3 s and pulled every 3 s. RTO is dominated by the gate: the standby spent
14.4 s proving the model works before it signed for it. The key release and
the restore themselves took under 0.3 s together.

The earlier run of this kit, `20260915T021334Z` (plaintext escrow key, the
authority simulated, no primary pin), is kept beside this one: RTO 16.81 s,
RPO 9.0 s, gate EXACT.

## The key files sealed to the chip — run `20260916T212752Z` (evidence/20260916T212752Z)

The same drill, run once more with ADR 0023 in the kit: right after the
authority's config is written, `sagvd seal-keys -config sagvd-base.json`
seals its key files in place — `keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path` — to this chip's derived key
(`standby/seal-keys.json`: `tee: gcp-sev-snp`, measurement `21199b36…9546`),
and every `sagvd` from then on reads them sealed: `sagvd identity` and
`sagvd escrow-provision` (key `4f2ac49d2919c37e`, exit 0), the recovery
ceremony, `sagvd failover` (exit 0), the audit log's verify. The failover
itself: generation 1 restored and gated **EXACT**, RTO **22.10 s**,
RPO 9.00 s, 5 audit events verified (tip `bb9fa06c…fa62`); the negative
leg as before — `rogue: sagvd failover exit=3 (want 3: declined) status=declined`.

No plaintext seed is on the standby's disk after the seal step, and none
is in the evidence: `seal-keys.json` names the files, `steps.txt` says
`seal-keys exit=0`.

## The sentinel's seed sealed to the chip — run `20260916T231442Z` (evidence/20260916T231442Z)

The same drill with the sentinel's seed sealed (ADR 0023, amended): right
after the operator pinned the key, `acpctl sentinel seal-key --key
/root/sentinel.seed --tee gcp-sev-snp` sealed the seed in place to the
primary's chip (`primary/sentinel-seal-key.json`: `tee: gcp-sev-snp`,
measurement `10f5ac22…4519`, `sealed: true`), `acpctl sentinel identity --key`
read the same key `sentinel-aa5c0c595b883fe0` from the sealed file
(`primary/sentinel-identity-sealed.json`), and the sentinel ran from it:
two generations sealed, the attack, the compromise report, exit 3. The
authority failed over on that word — generation 1 restored and gated
**EXACT**, RTO **18.53 s**, RPO 9.00 s, 5 audit events
verified (tip `17876233…1c5f`) — and the two negatives on the standby's chip:
the bare seed stolen there declined as before (`rogue: sagvd failover exit=3 (want 3: declined) status=declined`), and the sealed
file taken there refused to open (`stolen sealed seed: acpctl sentinel identity exit=2 (want 2: does not open off the primary's chip): acpctl sentinel identity: --key: /root/stolen.sealed: integrity[signature_invalid]: sealed secret "sentinel.seed": this host does not open it (sealed at 10f5ac22cef1db0a… on gcp-sev-snp): integrity[signature_invalid]: `).

On the standby every secret file was sealed too (ADR 0023, amended
twice): `sagvd seal-keys` sealed the authority's 5 files —
`keys.authority_signing.seed_path`, `keys.session_sealing.material_path`, `keys.audit_signing.seed_path`, `vault.tls.server_key`, `http_api.bearer_token_file` — and `acp-bootstrap seal-keys` the destination's own copies
on the same host — `http.tls.server_key`, `http.bearer_token_file` (`standby/dest-seal-keys.json`); the
whole drill ran from them. The one file the authority still read bare
in this run is the cross-cloud transport's client key: the kit sealed
the base config's files before the failover config that names it was
written; the kits now seal again after writing it (`seal-keys` skips
what is sealed); the cross-cloud drill's run `20260916T233717Z`
(`../failover-cgpu/evidence/20260916T233717Z/authority/steps.txt`) carries the
proof: `seal-keys (failover config) exit=0 sealed=crosscloud.transport_tls.client_key already=5`.

No plaintext seed is on the primary's disk after the seal step; the bare
copy the standby's negative used lived in the run's private bucket,
deleted with the run. None is in the evidence.

## The raised runtime — run `20261014T034337Z` (evidence/20261014T034337Z)

The same drill — the escrow key and every key file sealed on the standby,
the sentinel's seed sealed on the primary, the primary pinned to its chip,
both negatives — on the raised Python runtime (torch 2.14.1+cpu,
transformers 5.19.0, numpy 2.5.4 on both machines; `*/pip-freeze.txt`),
us-central1-c, the same launch measurements (primary `10f5ac22…4519`,
standby `7dc7c12e…5acc`). Two generations sealed (120 steps in 53.6 s,
160 in 76.5 s, loss 5.33 → 0.0009), the attack, the compromise report
with the chip's report on it, exit 3. The authority failed over on that
word: generation 1 restored (key `genome-86d10d8e1ca5-g1-57d211810465`,
2,216,819 bytes; 5 files, 2,210,904 bytes, in 12.2 ms) and gated
**EXACT** (pinned replay, 16 fixtures, 12.3 s); detect 4.42 s, RPO
9.00 s, release 0.25 s, RTO **18.69 s** (September: 18.53 s); 5 audit
events verified (tip `d6e0a658…2c4d`). The negatives as before: the bare
seed stolen to the standby's chip declined (`rogue: sagvd failover exit=3
(want 3: declined) status=declined`, heartbeat-timeout, the rogue's
generation 2 set aside), the sealed file taken there refused to open
(`exit=2`). One thing closed since the run above: the cross-cloud
transport's client key is sealed in this kit too — `seal-keys (failover
config) exit=0 sealed=crosscloud.transport_tls.client_key already=5`
(`standby/steps.txt`) — so every file the authority read in this run was
sealed.

## Evidence files

- `primary/` — `finetune-0.json`, `finetune-1.json` (the two fine-tunes),
  `sentinel-identity.json` (the chip's measurement and the sentinel key id),
  `sentinel.json` (the sentinel's final report: outcome, the generation it
  last sealed, the wires that fired, the attested compromise report),
  `attack-at.txt`, `system.txt` and `tsm.txt` (SEV-SNP boot lines,
  configfs-tsm, `/dev/sev-guest`), `steps.txt`, `console.log`.
- `standby/` — `escrow-provision.json`, `escrow-sealed-shape.txt`,
  `escrow-reprovision.json`, `recovery-keygen.txt` (the sealed key and the
  ceremony), `authority-identity.json` and `destination-identity.json`,
  `primary-identity.json` (what the operator pinned), `failover-verify.txt`
  and `failover-2-verify.txt` (the signed policies), `report.json` (the
  failover report), `audit-verify.json` (the log checked offline after the
  failover), `restored-adapter-head.txt`, `rogue-report.json`,
  `rogue-sentinel.json`, `rogue-outbox.txt`, `rogue-failover.log` (the
  negative leg), `tsm.txt`, `steps.txt`, `console.log`, `acp-bootstrap.log`,
  `failover.log`.

The evidence holds no key, seed, token or config. The sealed escrow key's
bytes are not in it (only their length); the recovered key went through a
pipe. The sentinel seed crossed to the standby only through the run's private
bucket, for the negative leg, and the bucket was deleted with the VMs.

## Scope

This proves the failover mechanism and attestation on real hardware. Both
machines are CPU confidential VMs. An attested GPU standby needs confidential
GPUs (H100 CC), a TDX producer and verifier — not tested yet. CPU→GPU fidelity
is measured separately in [`gcp-drill`](../gcp-drill).
