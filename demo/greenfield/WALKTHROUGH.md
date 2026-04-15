# Greenfield Demo — Quantum Computing Lab, CMMC 2.0 Level 2

## Situation

Dr. Sarah Chen's Quantum Computing Lab at Meridian Research University received a DoD
subcontract (DARPA QuBIC program, Contract W911NF-26-1-0203) requiring CMMC 2.0 Level 2
certification within 90 days. The lab handles research data tagged as Controlled
Unclassified Information (CUI // DoD // DIST D).

**Starting state**: One AWS account, no SCPs beyond AWS defaults, no compliance program,
no policies, no training records.

---

## Step 1 — Initialize

```
$ AWS_PROFILE=mru-security attest init --region us-east-1

Initializing SRE...
  Reading Organization topology (region: us-east-1)...
  Organization: o-mru2026 (1 environment)
  Inventorying existing SCPs...
  Found 1 existing SCP (FullAWSAccess — AWS default)
  Querying Artifact for active agreements...
  Detecting data classifications from account tags...

SRE initialized. Written to .attest/sre.yaml
  Org: o-mru2026
  Environments: 1
  Active frameworks: 0

No frameworks activated. Run 'attest frameworks add <framework-id>' to activate one.
```

**What attest found**: A single account with no data class tags, no compliance SCPs, no
frameworks. The `attest:data-class` tag is missing — attest can't infer CUI from the
current account configuration.

Fix the account tags first:

```
$ aws organizations tag-resource \
    --resource-id 100000000002 \
    --tags Key=attest:data-class,Value=CUI \
           Key=attest:owner,Value="Dr. Sarah Chen" \
           Key=attest:purpose,Value="DARPA QuBIC quantum computing research"
```

---

## Step 2 — Activate NIST 800-171

```
$ attest frameworks add nist-800-171-r2

Activating framework: nist-800-171-r2
  Loading framework definition... (110 controls, 14 families)
  Validating Artifact agreement requirements...
  Computing control overlap with existing frameworks...
  Framework nist-800-171-r2 activated. Run 'attest compile' to generate policies.
```

---

## Step 3 — First scan (the brutal truth)

```
$ attest scan

Scanning SRE posture: o-mru2026
  Environments: 1
  Loaded framework: NIST SP 800-171 Rev 2 (110 controls)

Posture summary:
  Total controls:  110
  Enforced:         0   ← no compiled artifacts yet
  Partial:          0
  Gaps:           110

  NIST SP 800-171 Rev 2:
    Enforced: 0  Partial: 0  Gaps: 110

Tip: run 'attest compile' first for crosswalk-based posture.
```

---

## Step 4 — Compile (generates the technical artifacts)

```
$ attest compile

Compiling policies for 1 framework(s)...
  Resolving cross-framework control overlap...
  Generating SCPs (structural enforcement)...
  Generating Cedar policies (operational enforcement)...
  Building crosswalk manifest...
  Writing artifacts...

Compiled artifacts written to .attest/compiled
  26 SCP(s)
  7 Cedar policy/policies + schema
  Crosswalk: .attest/compiled/crosswalk.yaml

Run 'attest apply' to deploy to the organization.
```

---

## Step 5 — Scan after compile (technical picture)

```
$ attest scan

Scanning SRE posture: o-mru2026
  Environments: 1
  Loaded framework: NIST SP 800-171 Rev 2 (110 controls)
  Loaded crosswalk (110 entries)

Posture summary:
  Total controls:  110
  Enforced:         6   ← fully specified controls
  Partial:         21   ← SCP or Cedar but not both
  Gaps:            83   ← no technical enforcement defined
                         (many are administrative controls)

  NIST SP 800-171 Rev 2:
    Enforced: 6  Partial: 21  Gaps: 83
```

**Score so far: ~120/550 (22%)**. Technical controls are defined. Administrative controls
are all gaps. This is the real starting state for most greenfield organizations.

---

## Step 6 — AI onboarding session

```
$ attest ai onboard --mode greenfield

Attest AI: I've analyzed your SRE (o-mru2026) and NIST 800-171 R2 framework.

           Technical status: 6 enforced, 21 partial, 83 gaps.

           Of those 83 gaps, 34 are administrative controls requiring human
           processes. Here's what you need to build, in order of priority:

           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           CRITICAL — blocks Cedar attribute resolution:
           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

           3.2.2 — Role-based CUI handling training
           ┌─────────────────────────────────────────────────────────────┐
           │ 3 Cedar policies evaluate principal.cui_training_current.    │
           │ Until this attribute is set to true via your principal        │
           │ resolver, those policies will deny all operations for all     │
           │ users. Your CUI data movement control is enforced but        │
           │ effectively denying everyone.                                │
           └─────────────────────────────────────────────────────────────┘
           Do you have an existing CUI training program? [y/n/skip] n

           → I'll generate a draft CUI training policy for your review.
             Generating: .attest/drafts/policy-3.2.2-cui-training.md

           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           HIGH — required for CMMC Assessment Ready status:
           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

           3.11.1 — Annual risk assessment
           3.12.4 — System Security Plan (attest generate ssp handles this)
           3.6.1  — Incident response capability
           3.2.1  — Security awareness training program

           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           MODERATE — required for full CMMC compliance:
           ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

           3.6.3  — IR capability testing (annual exercise)
           3.7.1  — Maintenance procedures
           3.9.1  — Personnel screening before CUI access
           ... (12 more)

           Work through 3.2.2 now? [y/n] y
```

---

## Step 7 — Generated policy (draft for review)

Attest generates `.attest/drafts/policy-3.2.2-cui-training.md`:

```markdown
# CUI Handling and Security Awareness Training Policy
**Control**: NIST SP 800-171 Rev 2 — 3.2.2
**Organization**: Meridian Research University — Quantum Computing Lab
**Prepared**: 2026-04-15 (attest ai generate-policy)
**Status**: DRAFT — requires review and adoption before attesting

---

## Purpose

This policy establishes the training requirements for all personnel with
access to Controlled Unclassified Information (CUI) in the MRU Quantum
Computing Lab AWS environment (Account: quantum-cui-lab, o-mru2026).

## Technical dependency

This policy directly enables enforcement of the following Cedar policies:
- `attest-scp-require-mfa-cedar-authorized-principals` (3.1.1): evaluates
  `principal.authorization_current` and `principal.training_complete`
- `attest-scp-cui-region-restrict-cedar-cui-data-movement` (3.1.3): evaluates
  `principal.cui_training_current` and `principal.lab_authorization`

Until this training is implemented and tracked in the principal resolver, the
above Cedar policies will deny all operations for all principals.

## Scope

All researchers, students, and staff with access to the `quantum-cui-lab`
AWS account or any CUI-classified data repositories.

## Requirements

### Initial training (before CUI access is granted)
1. Complete CITI Program: "Controlled Unclassified Information Fundamentals" module
2. Review MRU Information Security Policy (Section 6: CUI Handling)
3. Sign CUI Handling Acknowledgment form
4. Notify IT Security (itsecurity@mru.edu) to enable CUI access in IAM

### Annual renewal
- Training must be renewed before the 12-month expiration date
- Expiry date is tracked in the MRU LMS (Canvas) and the IAM role tag
  `attest:cui-expiry` on each researcher's assumed role
- IT Security sends reminder 30 days before expiration
- Access is suspended automatically if training is not renewed (enforced by Cedar)

### Training content (minimum)
- What CUI is and what it is not (NIST SP 800-171 Appendix A)
- Marking and handling requirements for CUI // DoD // DIST D
- Approved data storage locations (only within o-mru2026 CUI enclave)
- Prohibited actions: email, personal cloud storage, unencrypted devices
- Incident reporting: how and when to report a potential CUI spill

## Records

Training completion is tracked in:
1. MRU LMS (Canvas) — course completion certificates
2. IAM role tags: `attest:cui-training = true`, `attest:cui-expiry = YYYY-MM-DD`
3. `.attest/attestations/` — annual attestation records

## Review schedule

This policy is reviewed annually or upon significant changes to CUI handling
requirements. Next review: 2027-04-15.

---
*Prepared by attest AI. Review and customize before adoption.*
*After adoption: attest attest create --control 3.2.2 --evidence this-file.md*
```

---

## Step 8 — Record attestations as controls are implemented

After implementing the training program and completing the first training cycle:

```
$ attest attest create \
    --control 3.2.2 \
    --title "CUI handling training — initial cycle complete" \
    --affirmed-by "Dr. Sarah Chen (PI)" \
    --evidence "CITI completions for 4 lab members, LMS export 2026-05-01" \
    --evidence-type training_record \
    --expires 2027-05-01

Attestation created: ATT-2026-001
  Control: 3.2.2 | Status: active | Expires: 2027-05-01

$ attest attest create \
    --control 3.11.1 \
    --title "Initial risk assessment — quantum-cui-lab" \
    --affirmed-by "MRU CISO Janet Park" \
    --evidence ".attest/drafts/risk-assessment-2026.md" \
    --evidence-type policy_doc \
    --expires 2027-04-15

Attestation created: ATT-2026-002
```

---

## Step 9 — Scan after 6 weeks of work

After implementing training, risk assessment, IR plan, and personnel screening:

```
$ attest scan

Posture summary:
  Total controls:  110
  Enforced:        94
  Partial:         12
  Gaps:             4

  NIST SP 800-171 Rev 2:
    Enforced: 94  Partial: 12  Gaps: 4

Administrative obligations (next 90 days):
  ◐ 3.6.3 — IR capability test        due 2026-07-15  [71 days]
  ● 3.7.1 — Maintenance procedures     due 2026-08-01  [88 days]
```

---

## Step 10 — Assessment-ready SSP

```
$ attest generate ssp

Generating System Security Plan (NIST SP 800-171 Rev 2)...
  SSP written to .attest/documents/ssp-nist-800-171-r2.md
  Status: Partial | Score: 487/550 (88.5%)

$ attest generate assess

Generating self-assessment (NIST SP 800-171 Rev 2)...
  Assessment written to .attest/documents/assessment.md
  Score: 487/550 (88.5%) — Assessment Ready
```

**In 6 weeks from a blank slate**, the lab went from 0/550 to 487/550 — Assessment Ready
for CMMC 2.0 Level 2. The remaining 12 partial controls have a clear remediation path
in the POA&M.

---

## Summary: Greenfield timeline

| Week | Work | Score |
|------|------|-------|
| 0 | attest init, compile | 22% (technical only) |
| 1 | CUI training implemented, ATT-2026-001 | 35% |
| 2 | Risk assessment, IR plan drafted | 48% |
| 3 | Personnel screening, ATT-2026-002/003 | 62% |
| 4 | attest apply (SCPs deployed to org) | 74% |
| 5 | Remaining attestations, policy reviews | 82% |
| 6 | Final scan, SSP generated | 88.5% |
