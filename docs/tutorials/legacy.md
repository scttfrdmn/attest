# Tutorial: Legacy Ingest — 30 Minutes to Audit-Ready SSP

This tutorial follows **Dr. Marcus Rodriguez's biomedical genomics lab** at Meridian
Research University. The lab has 4 years of existing compliance documentation —
an Information Security Policy, an Incident Response Plan, training records,
and a prior SSP draft. They need to get from scattered documents to an
audit-ready posture in one session.

See also: [`demo/legacy/`](../../demo/legacy/) for full scenario context.

---

## Prerequisites

- Existing compliance documents (PDF, Word, or markdown)
- AWS management account access with a signed BAA (for HIPAA)
- `attest` installed and `attest init` already run

---

## Step 1 — Initialize with existing org

```bash
AWS_PROFILE=sre attest init --region us-east-1
```

Because you have a signed BAA with AWS, HIPAA is auto-detected:

```
SRE initialized. Written to .attest/sre.yaml
  Org: o-genomics123 (2 environments)
  Found: HIPAA BAA (signed 2024-03-15) — activating hipaa framework
  Active frameworks: hipaa
```

Add NIST 800-171 if you handle CUI:

```bash
attest frameworks add nist-800-171-r2
```

---

## Step 2 — First scan (shows the gap)

```bash
attest scan
```

```
Posture summary:
  Total controls:  158 (110 NIST + 48 HIPAA)
  Enforced:          0   (no SCPs deployed yet)
  Partial:           0
  Gaps:            158

Score: 0 / 790 (0%) — Needs work
```

This 0% score doesn't mean you have nothing — it means attest hasn't seen
your existing documents yet. That's what the next step fixes.

---

## Step 3 — Ingest existing documentation

```bash
attest ai ingest ./policies/information-security-policy.pdf
```

```
Analyzing: information-security-policy.pdf (42 pages)
Mapping to: NIST SP 800-171 R2, HIPAA Security Rule

Results:
─────────────────────────────────────────────────────────────────
Control    Status      Finding
─────────────────────────────────────────────────────────────────
3.11.1[a]  ✓ Covered   "Section 4.2: Annual risk assessment required"
3.11.1[b]  ✓ Covered   "Section 4.3: Risk management measures defined"
3.11.2[a]  ✗ Missing   No vulnerability scanning schedule found
3.12.4[a]  ~ Partial   SSP referenced but not included in this document
3.6.1[a]   ✓ Covered   "Appendix C: Incident Response Procedures"
3.6.1[b]   ✓ Covered   "Section 7.1: Incident documentation requirements"
3.6.3[a]   ✗ Missing   No IR testing/exercise schedule mentioned

164.308(a)(1) ✓ Covered  "Section 2.1: Security Management Process"
164.308(a)(6) ✓ Covered  "Appendix C: Incident Response"
─────────────────────────────────────────────────────────────────

8 controls covered | 2 partially covered | 6 gaps identified

Create attestation records for covered controls? [y/n] y
Created 8 draft attestation records in .attest/drafts/
```

Ingest your other documents:

```bash
attest ai ingest ./policies/incident-response-plan.pdf
attest ai ingest ./training/citi-completion-records.csv
attest ai ingest ./policies/risk-assessment-2025.docx
```

---

## Step 4 — Review and confirm draft attestations

```bash
ls .attest/drafts/
# att-3.11.1-from-infosec-policy.yaml
# att-3.6.1-from-infosec-policy.yaml
# att-164.308-from-infosec-policy.yaml
# ...

cat .attest/drafts/att-3.11.1-from-infosec-policy.yaml
```

```yaml
id: ATT-DRAFT-001
control_id: "3.11.1"
objective_id: "3.11.1[a]"
title: "Annual risk assessment — covered by Information Security Policy §4.2"
evidence_ref: "information-security-policy.pdf, Section 4.2, page 18"
evidence_type: policy_doc
affirmed_by: ""       # fill in
expires_at: ""        # fill in
status: draft
```

Confirm each draft:

```bash
attest attest confirm ATT-DRAFT-001 \
  --affirmed-by "CISO Dr. Lee" \
  --expires 2027-04-01
```

Or confirm all at once:

```bash
for f in .attest/drafts/*.yaml; do
  attest attest confirm $(basename $f .yaml) \
    --affirmed-by "CISO Dr. Lee" \
    --expires 2027-04-01
done
```

---

## Step 5 — Rescan (after document ingest)

```bash
attest scan
```

```
Posture summary:
  Total controls:  158
  Enforced:          0   (SCPs not yet deployed)
  Partial:          63   (attested administrative controls)
  AWS Covered:      31   (AWS-managed via BAA)
  Gaps:             64

Score: 354 / 790 (44.8%) — Partial coverage, no SCPs yet
```

51% improvement from document ingest alone — before touching any AWS infrastructure.

---

## Step 6 — Deploy SCPs for technical controls

```bash
attest compile --scp-strategy merged
AWS_PROFILE=sre attest preflight --region us-east-1
AWS_PROFILE=sre attest apply --approve --region us-east-1
```

```
  Snapshot: applied-20260416-151200
  Creating SCP: attest-scp-01
  Deployed 1 SCP(s) to r-xxxx.
```

---

## Step 7 — Final scan

```bash
attest scan
```

```
Posture summary:
  Total controls:  158
  Enforced:         25   (SCPs + attested admin controls)
  Partial:          63   (partially covered)
  AWS Covered:      31
  Gaps:             39

Score: 564 / 790 (71.4%) — Approaching assessment readiness
```

39 gaps remain — these are controls needing active work:
- Training program documentation
- Vulnerability scanning schedule
- IR testing exercise records

---

## Step 8 — Generate audit-ready SSP

```bash
attest generate ssp --framework nist-800-171-r2
attest generate ssp --framework hipaa
attest generate poam
```

The SSP automatically includes:
- Evidence citations from ingested documents (with page references)
- AWS-side evidence from BAA and Artifact reports
- Crosswalk noting where one SCP satisfies both NIST and HIPAA controls
- Attestation records with approver, date, and expiry

```
Written to .attest/documents/ssp-nist-800-171-r2.md
Written to .attest/documents/ssp-hipaa.md
Written to .attest/documents/poam.md
```

---

## Step 9 — Close remaining gaps with AI assistance

```bash
AWS_PROFILE=sre attest ai onboard --mode checkpoint --region us-east-1
```

The AI identifies the 39 remaining gaps, sorted by impact, and guides you through
closing them — drafting missing procedures, scheduling IR exercises, setting up
vulnerability scanning.

---

## What changed in 30 minutes

| Before | After |
|---|---|
| 0 / 790 score (0%) | 564 / 790 (71.4%) |
| 0 controls documented | 88 controls documented |
| Scattered PDFs | Structured attestation records |
| No audit trail | Git-backed evidence chain |
| No SSP | Two framework SSPs + POA&M |

---

## Next steps

- [Greenfield tutorial](greenfield.md) — building from scratch
- [Rollback guide](../operations/rollback.md) — undoing a deployment
- Add more frameworks: `attest frameworks add iso27001-2022`
