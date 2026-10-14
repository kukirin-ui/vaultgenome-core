# Compliance crosswalk

This directory maps Vault Genome's technical controls to the
regulatory and audit frameworks enterprise customers ask about during
procurement. The single canonical document is
[`crosswalk.md`](crosswalk.md). Per-framework deep dives can be added
later under `soc2.md`, `iso27001.md`, etc., as customer demand
materialises.

The one assurance mark the project pursues directly is the OpenSSF Best
Practices badge; [`openssf-best-practices.md`](openssf-best-practices.md)
maps every criterion to where it is met in the tree.

Vault Genome is not yet certified under any of these frameworks —
certification requires a paid audit engagement (SOC 2 Type II ≈
$25k–60k, ISO 27001 ≈ $30k–80k, FedRAMP Moderate ≈ $250k–1M+) plus
12–18 months of operational evidence. The crosswalk is the
*technical* readiness story we present to buyers; the audit is the
*procedural* readiness story their compliance team verifies.

## What customers actually ask

In order of frequency in Q1–Q2 2026 customer conversations:

1. **SOC 2 Type II** (US enterprise default) — "do you have one?"
   then "when?" then "are the controls already in place even if the
   audit hasn't run?"
2. **ISO 27001** (international + EU enterprise) — same pattern.
3. **HIPAA** (US healthcare AI customers) — covered entities
   require a signed BAA and concrete safeguards.
4. **PCI DSS 4.0** (financial services) — typically deferred to the
   bank's own audit, but they want our controls table.
5. **FedRAMP** (US government / defence) — comes up only in
   enterprise sovereign deployments; FedRAMP Moderate is the realistic
   target.
6. **NIS2 / DORA** (EU regulated industries, post-Jan 2025) — newer,
   less prescriptive, gaining urgency in EU banking conversations.
7. **GDPR** (EU customers, every conversation) — Article 25
   "data protection by design" is what TEE-backed processing
   directly addresses.

## How to use this directory

- Sales conversation: pull the relevant section of
  [`crosswalk.md`](crosswalk.md) and walk through it with the
  customer's CISO / GRC lead.
- Customer security questionnaire: `crosswalk.md` answers ~70% of
  questions on a typical CAIQ / SIG / Lite-CAIQ form. The remaining
  30% are operational (incident response timelines, employee
  background checks) and answered from
  `business/27_security_program.md` (private repo).
- Audit prep: when the time comes to engage an auditor, the
  crosswalk is the starting evidence map. Each framework's section
  cites:
  - The Vault Genome control (file + ADR + test)
  - The framework's control identifier
  - The status (`✅ implemented`, `🟡 partial`,
    `⏳ planned-for-Q…`, `❌ out-of-scope`)
