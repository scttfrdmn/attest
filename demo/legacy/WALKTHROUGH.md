# Legacy Demo — Biomedical Research Center, HIPAA + NIST 800-171

## Situation

Dr. Marcus Rodriguez's Biomedical Research Center has been running on AWS for 4 years
handling genomic sequencing data (PHI + CUI). MRU has:

- A signed BAA with AWS (2022, active)
- An information security policy (v3.2, March 2024)
- An incident response plan (v4.1, February 2024)
- CITI training records in Canvas (exported quarterly)
- A risk assessment (completed February 2026)
- AWS Config rules deployed by the Control Tower landing zone

**None of this has ever been mapped to NIST 800-171 or HIPAA controls.**

An NIH program officer just emailed: the lab's next funding renewal requires a
NIST 800-171 assessment submitted within 60 days. The compliance officer says
the lab is "probably fine" but can't prove it and doesn't know where the gaps are.

---

## Step 1 — Initialize

```
$ AWS_PROFILE=mru-security attest init --region us-east-1

Initializing SRE...
  Reading Organization topology (region: us-east-1)...
  Organization: o-mru2026 (3 environments)
  Inventorying existing SCPs...
  Found 4 existing SCPs (Control Tower baseline)
  Querying Artifact for active agreements...
  Framework activated via BAA agreement: hipaa
  Detecting data classifications from account tags...
  Data classes found: PHI, CUI, FERPA

SRE initialized. Written to .attest/sre.yaml
  Org: o-mru2026
  Environments: 3
  Active frameworks: 1 (hipaa — from BAA agreement)

Run 'attest frameworks add nist-800-171-r2' to add NIST 800-171.
```

---

## Step 2 — Activate NIST 800-171 and compile

```
$ attest frameworks add nist-800-171-r2
$ attest compile

Compiled artifacts written to .attest/compiled
  26 SCP(s)
  7 Cedar policy/policies + schema
  Crosswalk: .attest/compiled/crosswalk.yaml
```

---

## Step 3 — First scan (the honest picture)

```
$ attest scan

Scanning SRE posture: o-mru2026
  Environments: 3
  Loaded framework: NIST SP 800-171 Rev 2 (110 controls)
  Loaded crosswalk (110 entries)

Posture summary:
  Total controls:  110
  Enforced:         6
  Partial:         21
  Gaps:            83  ← most are administrative controls showing as gaps
                         because no attestation records exist

  NIST SP 800-171 Rev 2:
    Enforced: 6  Partial: 21  Gaps: 83

Current score: ~120/550 (22%)
```

**The problem**: 83 controls show as gaps, but MRU has policies and training records
covering many of them. The system doesn't know they exist because they've never been
ingested. This is the false picture.

---

## Step 4 — Ingest existing documentation

```
$ attest ai ingest existing-policies/information-security-policy.md

Analyzing: information-security-policy.md (MRU Information Security Policy v3.2)
Mapping to: NIST SP 800-171 R2, HIPAA Security Rule

─────────────────────────────────────────────────────────────────────────────
 CONTROL        STATUS     FINDING
─────────────────────────────────────────────────────────────────────────────
 3.1.1[d]      ✓ Covered  "Section 5.1: Principle of Least Privilege"
 3.1.2[a]      ✓ Covered  "Section 5.1: access granted only to perform assigned functions"
 3.1.5[a]      ✓ Covered  "Section 5.2: Quarterly access reviews; annual recertification"
 3.1.5[b]      ✓ Covered  "Section 5.3: MFA required for all privileged accounts"
 3.1.8[a]      ~ Partial  Section 5.4 defines password complexity but no lockout threshold
 3.2.1[a-d]   ✓ Covered  "Section 8.1: Annual Security Awareness Training"
 3.2.2[a]      ~ Partial  "Section 8.2: CITI CUI Fundamentals required" — no completion
                           tracking mechanism described in this document
 3.3.1[b]      ✓ Covered  "Section 10: Audit logs retained minimum 3 years (7 for HIPAA)"
 3.3.2[a-b]   ✓ Covered  "Section 10: weekly review for anomalous access patterns"
 3.4.1[a]      ~ Partial  Section 6.3 mentions CUI data must stay in approved systems
                           but no baseline configuration or inventory procedure described
 3.5.3[a-b]   ✓ Covered  "Section 5.3: MFA required for Sensitive/Restricted data"
 3.5.5[a]      ✓ Covered  "Section 5.2: access provisioned via IT Service Portal, quarterly review"
 3.5.6[a-b]   ✓ Covered  "Section 5.2: access revoked within 24 hours of departure"
 3.5.7[a-b]   ✓ Covered  "Section 5.4: minimum 16 chars, no dictionary words"
 3.5.8[a-b]   ✓ Covered  "Section 5.4: no reuse for 24 generations"
 3.6.1[a-b]   ✓ Covered  "Section 7.3: incident response procedures defined"
 3.6.2[a-c]   ✓ Covered  "Section 7.1: incident reporting within 1 hour; section 7.3"
 3.8.7[a]      ✓ Covered  "Section 9: removable media prohibited in CUI environments"
 3.9.2[a-b]   ✓ Covered  "Section 5.2: termination — access revoked same day (involuntary)"
 3.11.1[a-b]  ✓ Covered  "Section 4.1: Annual risk assessment conducted"
 3.11.3[a]     ✓ Covered  "Section 4.2: remediation timelines defined by severity"
 3.12.1[a]     ✓ Covered  "Section 10: periodic security assessments conducted"
 3.12.2[a-b]  ✓ Covered  "Section 4.2: POA&M process defined"

 164.308(a)(1) ✓ Covered  "Section 4.1 & 4.3: risk analysis and sanction policy"
 164.308(a)(4) ~ Partial  Access authorization defined but no access establishment
                           and modification procedure documented
 164.308(a)(6) ✓ Covered  "Section 7: Incident response — HIPAA notification procedures"
 164.308(a)(8) ✓ Covered  "Section 10: periodic security assessments"
 164.312(b)    ✓ Covered  "Section 10: audit logs, weekly review"
─────────────────────────────────────────────────────────────────────────────
  27 controls covered | 4 partially covered | 6 not found in this document

  Controls not found (need other documentation or new policy):
  · 3.1.3 — CUI flow control (no data movement policy described)
  · 3.6.3 — IR capability testing (testing referenced but no schedule/procedure)
  · 3.9.1 — Personnel screening before CUI access
  · 3.13.2 — Architectural security principles
  · 164.308(a)(7) — Contingency plan (reference to backups but no plan documented)
  · 164.308(a)(2) — Assigned security responsibility (CISO role mentioned, no formal designation)
─────────────────────────────────────────────────────────────────────────────

Create attestation drafts for 27 covered controls? [y]

  Generated 27 attestation drafts in .attest/attestations/drafts/
  Review, fill in affirmer and expiry, then run: attest attest confirm <id>
```

---

## Step 5 — Ingest incident response plan

```
$ attest ai ingest existing-policies/incident-response-plan.md

Analyzing: incident-response-plan.md (MRU IRP v4.1)

─────────────────────────────────────────────────────────────────────────────
 CONTROL        STATUS     FINDING
─────────────────────────────────────────────────────────────────────────────
 3.6.1[a]      ✓ Covered  "Section 4: Preparation — GuardDuty, Security Hub, MFA"
 3.6.1[b]      ✓ Covered  "Section 6: Containment procedures; Section 8: PHI breach"
 3.6.2[a-c]   ✓ Covered  "Section 5.2: Initial analysis checklist, ServiceNow ticket"
 3.6.3[a]      ✓ Covered  "Section 9: Annual tabletop exercise, most recent Sept 2025"
 3.3.1[b]      ✓ Covered  "Section 4.1: CloudTrail across all accounts, 7-year HIPAA"
 3.14.3[a-b]  ✓ Covered  "Section 4.1: GuardDuty, Security Hub — weekly review"
 3.14.6[a]     ✓ Covered  "Section 4.1: GuardDuty enabled org-wide"
 164.308(a)(6) ✓ Covered  "Section 8: PHI breach — HIPAA notification procedures, HHS"
─────────────────────────────────────────────────────────────────────────────
  7 controls covered (2 already covered by IS Policy — not duplicated)

  Most recent IR test: September 2025. Created attestation draft ATT-DRAFT-IR-001
  for 3.6.3 with evidence: "IRP v4.1 Section 9, tabletop Sept 2025"
```

---

## Step 6 — Ingest training records

```
$ attest ai ingest existing-policies/training-records-export.md

Analyzing: training-records-export.md (MRU Training Records, exported 2026-04-01)

─────────────────────────────────────────────────────────────────────────────
 CONTROL        STATUS     FINDING
─────────────────────────────────────────────────────────────────────────────
 3.2.1[a-d]   ✓ Covered  All 10 required personnel completed Security Awareness
                           Training (Canvas). Most recent cycle: Oct 2025/Jan 2026.
 3.2.2[a]      ~ Partial  CUI Fundamentals: 2/4 CUI handlers current (50%).
                           Kevin Liu: EXPIRED 2026-03-10.
                           Priya Nair, Wei Zhang: not completed.
                           ⚠ Cedar policy cedar-cui-data-movement evaluates
                             principal.cui_training_current — partial completion
                             means 2 of 4 researchers are being denied CUI access.
 164.308(a)(5) ✓ Covered  HIPAA training: 7/8 current (Kevin Liu expired — same issue)
─────────────────────────────────────────────────────────────────────────────

  Action required before attesting 3.2.2:
  · Kevin Liu must complete CUI renewal (due 2026-04-30 per IT Security)
  · Priya Nair and Wei Zhang must complete initial CUI training (due 2026-04-30)

  Created attestation draft ATT-DRAFT-322-001 for 3.2.1 (awareness training)
  Note: 3.2.2 draft not created — training not yet at 100%. Re-run after completion.
```

---

## Step 7 — Confirm attestation drafts

```
$ attest attest list --status draft

  ATT-DRAFT-001   3.1.1[d]   IS Policy §5.1         needs: affirmer, expiry
  ATT-DRAFT-002   3.2.1[a-d] Training records        needs: affirmer, expiry
  ATT-DRAFT-003   3.6.1[a-b] IS Policy §7.3 + IRP    needs: affirmer, expiry
  ATT-DRAFT-IR-01 3.6.3[a]   IRP §9, Sept 2025 test  needs: affirmer, expiry
  ... (23 more)

$ attest attest confirm ATT-DRAFT-001 \
    --affirmed-by "Janet Park, CISO" \
    --expires 2027-03-01

Attestation confirmed: ATT-2026-001
  Control: 3.1.1[d] | Affirmed: Janet Park, CISO | Expires: 2027-03-01

# Batch confirm all drafts with the same affirmer and expiry:
$ for id in $(attest attest list --status draft --ids-only); do
    attest attest confirm $id \
      --affirmed-by "Janet Park, CISO" --expires 2027-03-01
  done

  Confirmed 26 attestations.
```

---

## Step 8 — Scan after ingestion

```
$ attest scan

Posture summary:
  Total controls:  110
  Enforced:        34   ↑ from 6
  Partial:         19
  Gaps:            57   ↓ from 83

  NIST SP 800-171 Rev 2:
    Enforced: 34  Partial: 19  Gaps: 57

Current score: ~282/550 (51%)

Administrative obligations (next 90 days):
  ⚠ 3.2.2 — CUI training incomplete (50%)      DUE 2026-04-30  [15 days]
    Action: Kevin Liu renewal + Nair/Zhang initial training
    Impact: cedar-cui-data-movement partially effective

  ● 3.6.3 — IR tabletop exercise               DUE 2026-09-30  [168 days]
  ● 3.11.1 — Annual risk assessment             DUE 2027-02-15  [306 days]  ✓ current
```

**Comparison**: Before ingestion the score was ~22%. After ingesting 3 existing documents,
51% without writing a single new policy. The documents existed — they just weren't mapped.

---

## Step 9 — After training remediation (2 weeks later)

After Kevin Liu renews and Nair/Zhang complete initial training:

```
$ attest ai ingest existing-policies/training-records-export-updated.md
  → 3.2.2 now fully covered: 4/4 CUI handlers current

$ attest attest create \
    --control 3.2.2 \
    --title "CUI Fundamentals training — all lab members current" \
    --affirmed-by "Janet Park, CISO" \
    --evidence "CITI completion records, MRU Canvas export 2026-04-30" \
    --expires 2027-04-30

$ attest scan

Posture summary:
  Total controls:  110
  Enforced:        78   ↑
  Partial:         19
  Gaps:            13

Current score: ~432/550 (79%)

Administrative obligations (next 90 days): NONE
```

---

## Step 10 — Audit-ready package

```
$ attest generate ssp

Generating System Security Plan (NIST SP 800-171 Rev 2)...
  SSP written to .attest/documents/ssp-nist-800-171-r2.md
  Status: Partial | Score: 432/550 (79%)

$ attest generate assess

  Score: 432/550 (79%) — Partially Ready
  Remaining gaps concentrated in: Configuration Management (3.4.x),
  Physical Protection (3.10.x — AWS-covered but not attested),
  Supply Chain (not in 800-171 Rev 2 scope)

$ attest generate oscal

  SSP: .attest/documents/ssp-nist-800-171-r2.oscal.json
  Assessment Results: .attest/documents/assessment-results.oscal.json
```

**The SSP for control 3.6.3 now reads**:

```markdown
### 3.6.3 — Test the organizational incident response capability

| Status | Implemented | Score | 5/5 |
|--------|-------------|-------|-----|
| Implementation | Incident response capability tested via annual tabletop exercise.
|                 Most recent: September 2025 (IRP v4.1, §9). Scenario: phishing
|                 + lateral movement to genomics data. Finding: detection acceptable
|                 (47 min); containment procedures updated for EKS. |
| Evidence | ATT-2026-IR-01: affirmed by Janet Park, CISO, 2026-04-15.
|           Source: Incident Response Plan v4.1, Section 9 |
| Next review | 2026-09-30 (annual exercise) |
```

Every sentence traces to a real document and a real attestation record.

---

## Summary: Legacy comparison

| | Before ingestion | After ingestion | After training fix |
|--|--|--|--|
| Score | 120/550 (22%) | 282/550 (51%) | 432/550 (79%) |
| Enforced | 6 | 34 | 78 |
| Gaps | 83 | 57 | 13 |
| Time spent | — | 30 minutes | 2 weeks (training) |

**4 years of compliance work went from invisible to measured in 30 minutes.**
The remaining 13 gaps have clear owners and POA&M entries.
